use std::fmt;

/// Reasons a request can be rejected by the CSRF layer, or a session lookup
/// can fail while ensuring/verifying a token.
///
/// This type is intentionally not exposed in any HTTP response body (to avoid
/// handing an attacker a fine-grained oracle on *why* their forged request
/// failed); it is surfaced only via [`tracing`] events. Consumers who need
/// the reason for their own logging/metrics can match on it in a `tracing`
/// subscriber.
#[derive(Debug)]
#[non_exhaustive]
pub enum CsrfError {
    /// The incoming request's method/content-type did not carry a token
    /// where the configured pattern expected one (missing cookie, missing
    /// form field, missing header).
    MissingToken,
    /// A token was present via two channels (e.g. cookie and form field) but
    /// they did not match.
    TokenMismatch,
    /// A structurally malformed token (wrong number of parts, invalid
    /// base64, etc).
    MalformedToken,
    /// An HMAC-signed token's signature did not verify.
    InvalidSignature,
    /// An HMAC-signed token's embedded timestamp is outside the configured
    /// TTL (or is in the future).
    TokenExpired,
    /// The synchronizer/hybrid-session pattern requires a
    /// `tower_sessions::Session` to be present in the request extensions
    /// (i.e. `tower_sessions::SessionManagerLayer` must run *before* this
    /// layer), but none was found.
    ///
    /// The most common real-world cause isn't a missing `SessionManagerLayer`
    /// at all — it's two different versions of `tower-sessions` linked into
    /// the same binary (e.g. via `axum-login` or a session-store crate
    /// requiring a different version than this crate does), producing two
    /// distinct `Session` types under the same name. See the `tower-sessions`
    /// dependency comment in `Cargo.toml` before assuming your layer order is
    /// wrong.
    MissingSessionExtension,
    /// The session has no token stored at the configured key, or the token
    /// it holds does not match the request's submitted token.
    SessionTokenMismatch,
    /// The underlying `tower_sessions` store returned an error (e.g. a
    /// failed database round-trip).
    SessionStore(tower_sessions::session::Error),
    /// The request body could not be buffered/read (I/O error surfaced by
    /// the inner body implementation).
    BodyRead(Box<dyn std::error::Error + Send + Sync>),
    /// A form-field transport was configured, but the request's
    /// `Content-Type` was not `application/x-www-form-urlencoded`.
    UnsupportedContentType,
    /// The request's `Origin` header was missing or not in the configured
    /// allow-list.
    OriginNotAllowed,
}

impl fmt::Display for CsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingToken => write!(f, "CSRF token absent from the expected channel(s)"),
            Self::TokenMismatch => write!(f, "CSRF token channels did not match"),
            Self::MalformedToken => write!(f, "CSRF token is structurally malformed"),
            Self::InvalidSignature => write!(f, "CSRF token signature is invalid"),
            Self::TokenExpired => write!(f, "CSRF token has expired"),
            Self::MissingSessionExtension => write!(
                f,
                "no tower_sessions::Session in request extensions; is SessionManagerLayer installed above this layer?"
            ),
            Self::SessionTokenMismatch => write!(f, "submitted token does not match the session-stored token"),
            Self::SessionStore(e) => write!(f, "session store error: {e}"),
            Self::BodyRead(e) => write!(f, "failed to read request body: {e}"),
            Self::UnsupportedContentType => write!(f, "expected application/x-www-form-urlencoded body"),
            Self::OriginNotAllowed => write!(f, "Origin header missing or not allowed"),
        }
    }
}

impl std::error::Error for CsrfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionStore(e) => Some(e),
            Self::BodyRead(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<tower_sessions::session::Error> for CsrfError {
    fn from(e: tower_sessions::session::Error) -> Self {
        Self::SessionStore(e)
    }
}

impl CsrfError {
    /// `true` for errors that mean *this deployment is misconfigured*
    /// (missing session middleware, a failing session store) rather than
    /// *this particular request looks forged*. The service layer maps
    /// these to `500` (and logs at `error!`) instead of the `403` used for
    /// ordinary verification failures, since presenting either as "your
    /// CSRF token was invalid" would hide a bug the operator needs to see.
    pub(crate) fn is_server_fault(&self) -> bool {
        matches!(self, Self::MissingSessionExtension | Self::SessionStore(_))
    }
}
