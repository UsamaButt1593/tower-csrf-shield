//! The trait machinery that makes each CSRF pattern a distinct type.
//!
//! This is split into two traits on purpose:
//!
//! - [`CsrfPattern`] is the small, public trait that appears in
//!   [`crate::CsrfLayer`]'s generic parameter. It is *sealed* (see
//!   [`sealed::Sealed`]): only the marker types this crate defines —
//!   [`crate::synchronizer::Synchronizer`],
//!   [`crate::double_submit::DoubleSubmit`], and [`crate::hybrid::Hybrid`] —
//!   can implement it, so a `CsrfLayer<P>` is always backed by one of the
//!   three patterns this crate actually knows how to run. There is no way
//!   to construct a fourth, half-implemented pattern from outside the
//!   crate.
//! - [`CsrfPatternDispatch`] is crate-private and does the actual work
//!   (reading tokens, verifying them, issuing new ones). Keeping it private
//!   means its plumbing types ([`RequiredInput`], [`ExtractedTokens`],
//!   [`IssuedToken`]) never need to be part of the public API.
//!
//! Every pattern-specific `verify`/`ensure_token` implementation is
//! deliberately free of any request-body generic parameter: reading a form
//! field (the only operation that needs the body) happens once, generically,
//! in [`crate::service`], before dispatch. By the time a pattern's `verify`
//! runs, "the token the client submitted" is already a plain `Option<String>`
//! — see [`ExtractedTokens`].

use async_trait::async_trait;
use http::{Extensions, HeaderName, HeaderValue};

use crate::error::CsrfError;

pub mod double_submit;
pub mod hybrid;
pub mod synchronizer;

pub(crate) mod sealed {
    /// Implemented only by this crate's own pattern marker types.
    pub trait Sealed {}
}

/// Marker trait selecting a CSRF verification pattern
/// (synchronizer/double-submit/hybrid) at the type level.
///
/// This trait is sealed and cannot be implemented outside this crate.
pub trait CsrfPattern: sealed::Sealed + Send + Sync + 'static {
    /// The fully-resolved, immutable configuration this pattern needs at
    /// request time.
    type Config: Send + Sync + 'static;
}

/// What a pattern needs pulled out of an unsafe-method request before its
/// `verify` can run — described declaratively so [`crate::service`] can do
/// the (body-type-generic) extraction once, uniformly, for any pattern.
#[doc(hidden)]
pub(crate) struct RequiredInput {
    /// `Some(name)` if this pattern reads a cookie (double-submit, hybrid);
    /// `None` for the synchronizer pattern, which has no cookie at all.
    pub(crate) cookie_name: Option<String>,
    /// `Some(field)` if the client is expected to submit the token as a
    /// body field.
    pub(crate) body_field: Option<String>,
    /// `Some(name)` if the client is expected to submit the token as a
    /// header (double-submit only).
    pub(crate) header: Option<HeaderName>,
}

/// The token(s) extracted from a request, in already-owned, body-type-free
/// form, ready to hand to a pattern's `verify`.
#[doc(hidden)]
pub(crate) struct ExtractedTokens {
    pub(crate) cookie: Option<String>,
    pub(crate) submitted: Option<String>,
}

/// A token to expose to the handler (via request extensions, see
/// [`crate::CsrfToken`]) for this request/response cycle, plus, if a new
/// value was issued, the `Set-Cookie` header to attach to the response.
#[doc(hidden)]
pub(crate) struct IssuedToken {
    pub(crate) value: String,
    pub(crate) set_cookie: Option<HeaderValue>,
}

/// Crate-private counterpart to [`CsrfPattern`] that does the actual work.
/// Every [`CsrfPattern`] implementation in this crate also implements this.
#[async_trait]
pub(crate) trait CsrfPatternDispatch: CsrfPattern {
    /// Declares what needs to be read off an unsafe-method request.
    fn required_input(config: &Self::Config) -> RequiredInput;

    /// Verifies an already-extracted token. `extensions` provides access to
    /// the request's `tower_sessions::Session`, if any, without requiring
    /// this trait to know the request's body type.
    async fn verify(
        config: &Self::Config,
        extracted: ExtractedTokens,
        extensions: &Extensions,
    ) -> Result<(), CsrfError>;

    /// Ensures a valid token exists for this request/response cycle:
    /// reuses `existing_cookie_value` if it is still usable and `force_new`
    /// is `false`, otherwise issues (and, for session-backed patterns,
    /// persists) a fresh one. `existing_cookie_value` is `None` for the
    /// synchronizer pattern (it has no cookie; it looks at the session
    /// directly).
    async fn ensure_token(
        config: &Self::Config,
        extensions: &Extensions,
        existing_cookie_value: Option<&str>,
        force_new: bool,
    ) -> Result<IssuedToken, CsrfError>;
}
