//! The double-submit cookie pattern: a token is set in a (non-`HttpOnly`)
//! cookie and must be echoed back by the client via a form field or header;
//! the layer compares the two.
//!
//! Two sub-approaches, selected by the marker types [`Naive`] and [`Hmac`]:
//!
//! - [`Naive`]: the cookie/submitted match *is* the entire check. No
//!   additional configuration, no server-side state.
//! - [`Hmac`]: the token is additionally an HMAC-signed, self-expiring
//!   value (see [`crate::crypto::HmacConfig`]), so a value that merely
//!   matches its own cookie isn't enough — it must also carry a valid
//!   signature from this server's secret. Still no server-side storage.
//!
//! The cookie this pattern sets is always **not** `HttpOnly` (a requirement
//! of the pattern in its classic form: not applicable here since the
//! client's copy comes back via a form field or header rather than being
//! read from the cookie by JS, but kept non-`HttpOnly` for compatibility
//! with double-submit tooling that does expect to read it) — this isn't a
//! setting you can change; [`crate::CookieConfig`] never exposes an
//! `HttpOnly` toggle at all, and this module hardcodes `false` when it
//! renders the `Set-Cookie` header.

use std::marker::PhantomData;

use async_trait::async_trait;
use http::{Extensions, HeaderName};

use crate::builder::SharedSettingsBuilder;
use crate::cookie_config::{CookieConfig, CookieSettings, PrefixState};
use crate::crypto::{self, HmacConfig};
use crate::error::CsrfError;
use crate::patterns::{
    sealed, CsrfPattern, CsrfPatternDispatch, ExtractedTokens, IssuedToken, RequiredInput,
};
use crate::transport::TokenTransport;
use crate::typestate::{Missing, Present};

/// Sub-approach marker: no signing. The cookie/submitted-value match is the
/// entire verification.
#[derive(Debug, Clone, Copy)]
pub struct Naive;

/// Sub-approach marker: the token is HMAC-signed and self-expiring.
#[derive(Debug, Clone, Copy)]
pub struct Hmac;

impl sealed::Sealed for Naive {}
impl sealed::Sealed for Hmac {}

/// Sealed trait implemented only by [`Naive`] and [`Hmac`]; it carries the
/// behavior that differs between them. Its items are implementation
/// details.
pub trait DoubleSubmitMode: sealed::Sealed + Send + Sync + 'static {
    /// What this sub-approach needs configured beyond the shared cookie and
    /// transport: nothing (`()`) for [`Naive`], an [`HmacConfig`] for [`Hmac`].
    type Extra: Send + Sync + 'static;

    /// Cheap, no-I/O check of whether `existing` (the current cookie value,
    /// if any) is still usable as-is.
    #[doc(hidden)]
    fn has_existing_valid(extra: &Self::Extra, existing: Option<&str>) -> bool;

    /// Generates a fresh token value.
    #[doc(hidden)]
    fn generate_token(extra: &Self::Extra) -> String;

    /// Verifies `token` beyond the cookie/submitted match that already
    /// happened (a no-op for [`Naive`]; signature+TTL check for [`Hmac`]).
    #[doc(hidden)]
    fn verify(extra: &Self::Extra, token: &str) -> Result<(), CsrfError>;
}

impl DoubleSubmitMode for Naive {
    type Extra = ();

    fn has_existing_valid(_extra: &(), existing: Option<&str>) -> bool {
        existing.is_some_and(|s| !s.is_empty())
    }

    fn generate_token(_extra: &()) -> String {
        crypto::generate_opaque_token()
    }

    fn verify(_extra: &(), _token: &str) -> Result<(), CsrfError> {
        Ok(())
    }
}

impl DoubleSubmitMode for Hmac {
    type Extra = HmacConfig;

    fn has_existing_valid(extra: &HmacConfig, existing: Option<&str>) -> bool {
        existing.is_some_and(|s| extra.verify(s).is_ok())
    }

    fn generate_token(extra: &HmacConfig) -> String {
        extra.generate()
    }

    fn verify(extra: &HmacConfig, token: &str) -> Result<(), CsrfError> {
        extra.verify(token)
    }
}

/// Marker type selecting the double-submit pattern, parameterized by its
/// sub-approach ([`Naive`] or [`Hmac`]). See the module docs.
pub struct DoubleSubmit<M: DoubleSubmitMode>(PhantomData<M>);

impl<M: DoubleSubmitMode> sealed::Sealed for DoubleSubmit<M> {}
impl<M: DoubleSubmitMode> CsrfPattern for DoubleSubmit<M> {
    type Config = DoubleSubmitConfig<M>;
}

/// Immutable configuration for the double-submit pattern, parameterized by
/// its sub-approach.
///
/// Construct one with [`DoubleSubmitConfig::<Naive>::new`] or
/// [`DoubleSubmitConfig::<Hmac>::new`] (or let [`DoubleSubmitBuilder`] do
/// it). The two constructors take different arguments: only the `Hmac`
/// one accepts — and requires — an [`HmacConfig`], so it is impossible to
/// attach HMAC settings to a naive configuration, or to select HMAC without
/// providing them.
pub struct DoubleSubmitConfig<M: DoubleSubmitMode> {
    pub(crate) cookie: CookieSettings,
    pub(crate) transport: TokenTransport,
    pub(crate) extra: M::Extra,
}

impl DoubleSubmitConfig<Naive> {
    /// The cookie/submitted-value match is the entire check; nothing else
    /// to configure. The cookie's `HttpOnly` attribute is always `false`.
    pub fn new<S: PrefixState>(cookie: CookieConfig<S>, transport: TokenTransport) -> Self {
        Self {
            cookie: cookie.resolve(),
            transport,
            extra: (),
        }
    }
}

impl DoubleSubmitConfig<Hmac> {
    /// Tokens are HMAC-signed and self-expiring per `hmac`. The cookie's
    /// `HttpOnly` attribute is always `false`.
    pub fn new<S: PrefixState>(
        cookie: CookieConfig<S>,
        transport: TokenTransport,
        hmac: HmacConfig,
    ) -> Self {
        Self {
            cookie: cookie.resolve(),
            transport,
            extra: hmac,
        }
    }
}

#[async_trait]
impl<M: DoubleSubmitMode> CsrfPatternDispatch for DoubleSubmit<M> {
    fn required_input(config: &Self::Config) -> RequiredInput {
        let (body_field, header) = match &config.transport {
            TokenTransport::Form(field) => (Some(field.clone()), None),
            TokenTransport::Header(name) => (None, Some(name.clone())),
        };
        RequiredInput {
            cookie_name: Some(config.cookie.name.clone()),
            body_field,
            header,
        }
    }

    async fn verify(
        config: &Self::Config,
        extracted: ExtractedTokens,
        _extensions: &Extensions,
    ) -> Result<(), CsrfError> {
        let cookie_val = extracted.cookie.ok_or(CsrfError::MissingToken)?;
        let submitted = extracted.submitted.ok_or(CsrfError::MissingToken)?;
        if !crypto::constant_time_eq(&cookie_val, &submitted) {
            return Err(CsrfError::TokenMismatch);
        }
        M::verify(&config.extra, &cookie_val)
    }

    async fn ensure_token(
        config: &Self::Config,
        _extensions: &Extensions,
        existing_cookie_value: Option<&str>,
        force_new: bool,
    ) -> Result<IssuedToken, CsrfError> {
        if force_new || !M::has_existing_valid(&config.extra, existing_cookie_value) {
            let token = M::generate_token(&config.extra);
            let set_cookie = config.cookie.set_cookie_header(&token, false);
            Ok(IssuedToken {
                value: token,
                set_cookie: Some(set_cookie),
            })
        } else {
            Ok(IssuedToken {
                value: existing_cookie_value
                    .expect("has_existing_valid confirmed a value is present")
                    .to_owned(),
                set_cookie: None,
            })
        }
    }
}

/// Type-state builder for [`DoubleSubmitConfig`]. `.cookie(..)` and one of
/// `.submit_via_form_field(..)`/`.submit_via_header(..)` are required, in
/// either order; the sub-approach is chosen last, via `.naive()` or
/// `.hmac(..)`, which also finishes double-submit-specific configuration.
pub struct DoubleSubmitBuilder<C = Missing, T = Missing> {
    cookie: Option<CookieSettings>,
    transport: Option<TokenTransport>,
    _marker: PhantomData<(C, T)>,
}

impl DoubleSubmitBuilder<Missing, Missing> {
    pub(crate) fn new() -> Self {
        Self {
            cookie: None,
            transport: None,
            _marker: PhantomData,
        }
    }
}

impl<T> DoubleSubmitBuilder<Missing, T> {
    /// The cookie this pattern sets and reads. Its `HttpOnly` attribute is
    /// always `false`, per the pattern's requirements — see the module
    /// docs; [`CookieConfig`] does not expose a setting for it.
    pub fn cookie<S: PrefixState>(self, cookie: CookieConfig<S>) -> DoubleSubmitBuilder<Present, T> {
        DoubleSubmitBuilder {
            cookie: Some(cookie.resolve()),
            transport: self.transport,
            _marker: PhantomData,
        }
    }
}

impl<C> DoubleSubmitBuilder<C, Missing> {
    /// The client submits the token back as this body field, in addition to
    /// the cookie.
    pub fn submit_via_form_field(self, field: impl Into<String>) -> DoubleSubmitBuilder<C, Present> {
        DoubleSubmitBuilder {
            cookie: self.cookie,
            transport: Some(TokenTransport::Form(field.into())),
            _marker: PhantomData,
        }
    }

    /// The client submits the token back as this header, in addition to the
    /// cookie.
    pub fn submit_via_header(self, header: HeaderName) -> DoubleSubmitBuilder<C, Present> {
        DoubleSubmitBuilder {
            cookie: self.cookie,
            transport: Some(TokenTransport::Header(header)),
            _marker: PhantomData,
        }
    }
}

impl DoubleSubmitBuilder<Present, Present> {
    /// Selects the naive sub-approach: the cookie/submitted match is the
    /// entire check, with no additional configuration.
    pub fn naive(self) -> SharedSettingsBuilder<DoubleSubmit<Naive>> {
        SharedSettingsBuilder::new(DoubleSubmitConfig {
            cookie: self.cookie.expect("Present guarantees this is set"),
            transport: self.transport.expect("Present guarantees this is set"),
            extra: (),
        })
    }

    /// Selects the HMAC sub-approach: the token must additionally carry a
    /// valid signature and be within `hmac`'s TTL.
    pub fn hmac(self, hmac: HmacConfig) -> SharedSettingsBuilder<DoubleSubmit<Hmac>> {
        SharedSettingsBuilder::new(DoubleSubmitConfig {
            cookie: self.cookie.expect("Present guarantees this is set"),
            transport: self.transport.expect("Present guarantees this is set"),
            extra: hmac,
        })
    }
}
