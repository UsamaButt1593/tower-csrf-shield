//! Token generation and verification primitives shared across patterns.
//!
//! Two token shapes are used throughout this crate:
//!
//! - **Opaque**: `base64url(random_bytes)`. Used wherever a value is only
//!   ever compared against a server-held copy (synchronizer pattern; naive
//!   double-submit; hybrid+session with no HMAC pre-check). Carries no
//!   embedded expiry, since its lifetime is governed by whatever it's stored
//!   in (the session, or simply "until the cookie is replaced").
//! - **Signed**: `nonce.timestamp_millis.signature`, where `signature =
//!   base64url(HMAC-SHA256(secret, "nonce.timestamp_millis"))`. Used
//!   wherever a token must be verifiable without any server-side storage
//!   (HMAC double-submit; hybrid HMAC-only stage 2; hybrid+session's
//!   optional pre-check). Carries its own expiry via the embedded timestamp,
//!   because nothing else would ever invalidate it otherwise.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::error::CsrfError;

type HmacSha256 = Hmac<Sha256>;

/// Number of random bytes in an opaque token, before base64url encoding.
const OPAQUE_TOKEN_BYTES: usize = 32;
/// Number of random bytes in a signed token's nonce, before base64url encoding.
const NONCE_BYTES: usize = 16;

/// Generates `base64url(random_bytes)` with no server-side structure at all.
pub(crate) fn generate_opaque_token() -> String {
    random_b64(OPAQUE_TOKEN_BYTES)
}

fn random_b64(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Compares two token strings in constant time (with respect to content;
/// the length check itself short-circuits, which leaks only the token
/// length and is the conventional, accepted tradeoff for fixed-format
/// tokens — see `MessageDigest.isEqual`-style comparisons elsewhere).
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

/// An HMAC-SHA256 signing key plus a validity window.
///
/// Required by the HMAC sub-approach of the double-submit pattern, by the
/// HMAC-only stage 2 of the hybrid pattern, and optionally by the
/// pre-check step of the hybrid pattern's session-backed stage 2.
///
/// `Debug` is implemented by hand to avoid ever printing key material.
pub struct HmacConfig {
    mac: HmacSha256,
    pub(crate) ttl: Duration,
}

impl HmacConfig {
    /// `secret` should be a high-entropy value; 32 bytes/256 bits or more is
    /// a reasonable minimum. `ttl` bounds how long an issued token remains
    /// acceptable — since a signed token carries no server-side record that
    /// could otherwise be used to invalidate it, the embedded timestamp is
    /// the *only* thing that ever expires it.
    pub fn new(secret: impl AsRef<[u8]>, ttl: Duration) -> Self {
        let mac = HmacSha256::new_from_slice(secret.as_ref())
            .expect("HMAC-SHA256 accepts a key of any length");
        Self { mac, ttl }
    }

    /// Convenience constructor using a 24-hour TTL.
    pub fn with_default_ttl(secret: impl AsRef<[u8]>) -> Self {
        Self::new(secret, Duration::from_secs(24 * 60 * 60))
    }

    /// Generates a fresh signed token: `nonce.timestamp.signature`.
    pub(crate) fn generate(&self) -> String {
        let nonce = random_b64(NONCE_BYTES);
        let timestamp = now_millis();
        let sig = self.sign(&nonce, timestamp);
        format!("{nonce}.{timestamp}.{sig}")
    }

    fn sign(&self, nonce_b64: &str, timestamp_millis: u128) -> String {
        let payload = format!("{nonce_b64}.{timestamp_millis}");
        let mut mac = self.mac.clone();
        mac.update(payload.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// Verifies a signed token's structure, signature, and TTL, in that
    /// order (structure and signature are checked with no side effects, so
    /// this is always safe to call before touching any server-side state).
    pub(crate) fn verify(&self, token: &str) -> Result<(), CsrfError> {
        let mut parts = token.split('.');
        let nonce = parts.next().ok_or(CsrfError::MalformedToken)?;
        let ts_str = parts.next().ok_or(CsrfError::MalformedToken)?;
        let sig = parts.next().ok_or(CsrfError::MalformedToken)?;
        if parts.next().is_some() {
            return Err(CsrfError::MalformedToken);
        }
        let timestamp: u128 = ts_str.parse().map_err(|_| CsrfError::MalformedToken)?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig)
            .map_err(|_| CsrfError::MalformedToken)?;

        let payload = format!("{nonce}.{ts_str}");
        let mut mac = self.mac.clone();
        mac.update(payload.as_bytes());
        mac.verify_slice(&sig_bytes)
            .map_err(|_| CsrfError::InvalidSignature)?;

        let now = now_millis();
        if timestamp > now {
            // Issued in the future relative to this server's clock: reject
            // rather than special-case clock skew, since issuance and
            // verification always happen on the same process.
            return Err(CsrfError::TokenExpired);
        }
        let age = Duration::from_millis(u64::try_from(now - timestamp).unwrap_or(u64::MAX));
        if age > self.ttl {
            return Err(CsrfError::TokenExpired);
        }
        Ok(())
    }
}

impl fmt::Debug for HmacConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacConfig")
            .field("mac", &"<redacted>")
            .field("ttl", &self.ttl)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_round_trip() {
        let hmac = HmacConfig::with_default_ttl(b"test-secret-at-least-32-bytes-ok");
        let token = hmac.generate();
        assert!(hmac.verify(&token).is_ok());
    }

    #[test]
    fn signed_rejects_tampered_signature() {
        let hmac = HmacConfig::with_default_ttl(b"test-secret-at-least-32-bytes-ok");
        let token = hmac.generate();
        let mut parts: Vec<&str> = token.split('.').collect();
        let tampered_sig = if parts[2].starts_with('A') { "B" } else { "A" };
        let owned = format!("{}{}", tampered_sig, &parts[2][1..]);
        parts[2] = &owned;
        let tampered = parts.join(".");
        assert!(matches!(
            hmac.verify(&tampered),
            Err(CsrfError::InvalidSignature)
        ));
    }

    #[test]
    fn signed_rejects_wrong_key() {
        let a = HmacConfig::with_default_ttl(b"key-a-at-least-32-bytes-long-ok");
        let b = HmacConfig::with_default_ttl(b"key-b-at-least-32-bytes-long-ok");
        let token = a.generate();
        assert!(matches!(b.verify(&token), Err(CsrfError::InvalidSignature)));
    }

    #[test]
    fn signed_rejects_expired() {
        let hmac = HmacConfig::new(b"test-secret-at-least-32-bytes-ok", Duration::from_millis(0));
        let token = hmac.generate();
        std::thread::sleep(Duration::from_millis(5));
        assert!(matches!(hmac.verify(&token), Err(CsrfError::TokenExpired)));
    }

    #[test]
    fn signed_rejects_malformed() {
        let hmac = HmacConfig::with_default_ttl(b"test-secret-at-least-32-bytes-ok");
        assert!(matches!(
            hmac.verify("not-a-valid-token"),
            Err(CsrfError::MalformedToken)
        ));
    }

    #[test]
    fn opaque_tokens_are_unique_and_urlsafe() {
        let a = generate_opaque_token();
        let b = generate_opaque_token();
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn constant_time_eq_behaves_like_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }
}
