//! Optional `Origin` allow-list check, applied to unsafe-method requests
//! alongside (not instead of) the chosen CSRF pattern's own verification.
//!
//! This layer checks only the `Origin` header — never `Referer` — and,
//! when enabled, **fails closed**: an unsafe-method request with no
//! `Origin` header at all is rejected rather than let through. This is a
//! deliberate choice, not an oversight; if your clients legitimately never
//! send `Origin` on state-changing requests, leave this check on
//! [`OriginPolicy::Skip`] and rely on the token pattern alone.
//!
//! Enabling CORS with credentials for an origin effectively extends your
//! trust boundary to that origin regardless of what's configured here —
//! this check only constrains *which origins may complete a state-changing
//! request against this layer*, it has no bearing on which origins your
//! `CORSLayer` (or equivalent) permits to read responses. Configuring CORS
//! remains entirely the caller's responsibility.

use std::sync::Arc;

use http::header::ORIGIN;
use http::HeaderMap;

/// Whether to enforce an `Origin` allow-list on unsafe-method requests.
#[derive(Clone, Debug)]
pub enum OriginPolicy {
    /// Skip the `Origin` check entirely (rely on the token pattern, and
    /// whatever `SameSite`/CORS configuration exists elsewhere).
    Skip,
    /// Reject unsafe-method requests whose `Origin` header is missing or
    /// absent from this list. Entries are compared exactly against the
    /// header's string value, e.g. `"https://example.com"` (no trailing
    /// slash, matching how browsers send it).
    Enforce(Arc<[String]>),
}

impl OriginPolicy {
    /// Builds an [`OriginPolicy::Enforce`] from any collection of origin
    /// strings.
    pub fn enforce(allowed: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self::Enforce(allowed.into_iter().map(Into::into).collect())
    }

    /// Returns `true` if the request should be allowed to proceed.
    pub(crate) fn check(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::Skip => true,
            Self::Enforce(allowed) => match headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
                Some(origin) => allowed.iter().any(|a| a == origin),
                None => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_origin(origin: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(o) = origin {
            h.insert(ORIGIN, o.parse().unwrap());
        }
        h
    }

    #[test]
    fn skip_always_allows() {
        let policy = OriginPolicy::Skip;
        assert!(policy.check(&headers_with_origin(None)));
        assert!(policy.check(&headers_with_origin(Some("https://evil.example"))));
    }

    #[test]
    fn enforce_allows_listed_origin() {
        let policy = OriginPolicy::enforce(["https://example.com"]);
        assert!(policy.check(&headers_with_origin(Some("https://example.com"))));
    }

    #[test]
    fn enforce_rejects_unlisted_origin() {
        let policy = OriginPolicy::enforce(["https://example.com"]);
        assert!(!policy.check(&headers_with_origin(Some("https://evil.example"))));
    }

    #[test]
    fn enforce_fails_closed_on_missing_origin() {
        let policy = OriginPolicy::enforce(["https://example.com"]);
        assert!(!policy.check(&headers_with_origin(None)));
    }
}
