//! Cookie transport settings shared by the double-submit and hybrid
//! patterns.
//!
//! Two things are deliberately *not* configurable here, by omission rather
//! than validation:
//!
//! - **`HttpOnly`** is never a setting on [`CookieConfig`] at all. Whether
//!   the cookie ends up `HttpOnly` is a property of which pattern uses it
//!   (double-submit: always `false`; hybrid: always `true`), applied when
//!   the pattern module renders the `Set-Cookie` header — see
//!   [`CookieSettings::set_cookie_header`].
//! - **`Path`** is always `/`. A CSRF cookie scoped to a narrower path has
//!   no legitimate use case here and isn't worth the surface area.
//!
//! What *is* enforced at compile time is the interaction between the
//! `__Host-` cookie prefix and `Secure`: per the prefix's own requirements
//! (`Secure`, `Path=/`, no `Domain`), [`CookieConfig::host_prefixed`] simply
//! has no `secure` setter to call — it is hardcoded `true` — so there is no
//! way to construct a `__Host-`-prefixed, non-`Secure` configuration.

use std::marker::PhantomData;

use cookie::{Cookie, SameSite};
use http::header::COOKIE;
use http::{HeaderMap, HeaderValue};

mod sealed {
    pub trait Sealed {}
}

/// Type-state marker for [`CookieConfig`]: no `__Host-` prefix, `Secure` is
/// caller-chosen.
#[derive(Debug, Clone, Copy)]
pub struct NotHostPrefixed;

/// Type-state marker for [`CookieConfig`]: `__Host-` prefix applied,
/// `Secure` hardcoded `true`.
#[derive(Debug, Clone, Copy)]
pub struct HostPrefixed;

impl sealed::Sealed for NotHostPrefixed {}
impl sealed::Sealed for HostPrefixed {}

/// Sealed trait implemented only by [`NotHostPrefixed`] and [`HostPrefixed`].
pub trait PrefixState: sealed::Sealed + Send + Sync + 'static {
    #[doc(hidden)]
    fn effective_name(name: &str) -> String;
    #[doc(hidden)]
    const IS_HOST_PREFIXED: bool;
}

impl PrefixState for NotHostPrefixed {
    fn effective_name(name: &str) -> String {
        name.to_owned()
    }
    const IS_HOST_PREFIXED: bool = false;
}

impl PrefixState for HostPrefixed {
    fn effective_name(name: &str) -> String {
        format!("__Host-{name}")
    }
    const IS_HOST_PREFIXED: bool = true;
}

/// Builder for a CSRF cookie's transport-level settings: name, `SameSite`,
/// `Secure`, and whether to apply the `__Host-` prefix.
///
/// Construct via [`CookieConfig::standard`] or [`CookieConfig::host_prefixed`];
/// call [`CookieConfig::resolve`] (invoked automatically by the pattern
/// builders) to obtain the plain, immutable [`CookieSettings`] stored in a
/// built layer.
pub struct CookieConfig<S: PrefixState = NotHostPrefixed> {
    name: String,
    same_site: SameSite,
    secure: bool,
    _marker: PhantomData<S>,
}

impl CookieConfig<NotHostPrefixed> {
    /// A cookie without the `__Host-` prefix; `secure` is your choice (but
    /// should be `true` for anything served over HTTPS, which is to say:
    /// almost always).
    pub fn standard(name: impl Into<String>, same_site: SameSite, secure: bool) -> Self {
        Self {
            name: name.into(),
            same_site,
            secure,
            _marker: PhantomData,
        }
    }
}

impl CookieConfig<HostPrefixed> {
    /// A cookie with the `__Host-` prefix. `Secure` is hardcoded `true` and
    /// `Path=/` is always used (see module docs), matching what the prefix
    /// requires.
    pub fn host_prefixed(name: impl Into<String>, same_site: SameSite) -> Self {
        Self {
            name: name.into(),
            same_site,
            secure: true,
            _marker: PhantomData,
        }
    }
}

impl<S: PrefixState> CookieConfig<S> {
    pub(crate) fn resolve(self) -> CookieSettings {
        CookieSettings {
            name: S::effective_name(&self.name),
            same_site: self.same_site,
            secure: self.secure,
            host_prefixed: S::IS_HOST_PREFIXED,
        }
    }
}

/// The plain, resolved form of a [`CookieConfig`], stored inside a built
/// layer. Not generic: the `__Host-` prefix state only matters during
/// construction (it decides `name` and `secure`), not afterwards.
#[derive(Clone, Debug)]
pub struct CookieSettings {
    pub(crate) name: String,
    same_site: SameSite,
    secure: bool,
    #[allow(dead_code)] // surfaced via Debug for diagnostics; not read otherwise
    host_prefixed: bool,
}

impl CookieSettings {
    /// Builds a `Set-Cookie` header value carrying `value`.
    ///
    /// `http_only` is supplied by the caller rather than stored on this
    /// type: whether the cookie is `HttpOnly` is dictated entirely by which
    /// pattern is using it, never by user choice (see module docs).
    pub(crate) fn set_cookie_header(&self, value: &str, http_only: bool) -> HeaderValue {
        let built = Cookie::build((self.name.clone(), value.to_owned()))
            .path("/")
            .secure(self.secure)
            .http_only(http_only)
            .same_site(self.same_site)
            .build();
        HeaderValue::from_str(&built.to_string())
            .expect("name/value/attributes always produce a valid header value")
    }
}

/// Finds a cookie named `name` in the request's `Cookie` header(s), if
/// present. A request may repeat the `Cookie` header or fold multiple
/// cookies into one value; both are handled. Free-standing (rather than a
/// `CookieSettings` method) because [`crate::service`] needs to look up a
/// cookie by name generically, before it knows which pattern — and
/// therefore which `CookieSettings` — is in play.
pub(crate) fn find_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for header_value in headers.get_all(COOKIE) {
        let Ok(s) = header_value.to_str() else {
            continue;
        };
        for parsed in Cookie::split_parse(s) {
            let Ok(c) = parsed else { continue };
            if c.name() == name {
                return Some(c.value().to_owned());
            }
        }
    }
    None
}

/// Re-export so consumers don't need a direct `cookie` crate dependency just
/// to write `SameSite::Lax`.
pub use cookie::SameSite as CookieSameSite;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_prefixed_applies_prefix_and_forces_secure() {
        let s = CookieConfig::host_prefixed("csrf", SameSite::Lax).resolve();
        assert_eq!(s.name, "__Host-csrf");
        let header = s.set_cookie_header("tok", false);
        let text = header.to_str().unwrap();
        assert!(text.contains("__Host-csrf=tok"));
        assert!(text.contains("Secure"));
        assert!(text.contains("Path=/"));
        assert!(!text.contains("Domain"));
    }

    #[test]
    fn standard_cookie_respects_secure_flag_and_has_no_prefix() {
        let s = CookieConfig::standard("csrf", SameSite::Strict, false).resolve();
        assert_eq!(s.name, "csrf");
        let text = s.set_cookie_header("tok", false).to_str().unwrap().to_owned();
        assert!(!text.contains("Secure"));
        assert!(text.contains("SameSite=Strict"));
    }

    #[test]
    fn http_only_is_controlled_by_caller_not_config() {
        let s = CookieConfig::standard("csrf", SameSite::Lax, true).resolve();
        let off = s.set_cookie_header("tok", false).to_str().unwrap().to_owned();
        let on = s.set_cookie_header("tok", true).to_str().unwrap().to_owned();
        assert!(!off.contains("HttpOnly"));
        assert!(on.contains("HttpOnly"));
    }

    #[test]
    fn find_cookie_handles_multiple_cookies_and_repeated_headers() {
        let mut h = HeaderMap::new();
        h.append(COOKIE, "a=1; csrf=abc; b=2".parse().unwrap());
        h.append(COOKIE, "other=zzz".parse().unwrap());
        assert_eq!(find_cookie(&h, "csrf").as_deref(), Some("abc"));
        assert_eq!(find_cookie(&h, "other").as_deref(), Some("zzz"));
        assert_eq!(find_cookie(&h, "missing"), None);
    }
}
