//! The hybrid pattern: stage 1 is always a cookie/form double-check, using
//! an `HttpOnly` cookie the server sets into both channels itself (not a
//! classical double-submit, where client JS reads and echoes a
//! JS-readable cookie — see the crate-level docs for the distinction).
//! Stage 2 is either HMAC-only (fully stateless) or session-backed, chosen
//! by the marker types [`HmacOnlyStage`] and [`SessionStage`].
//!
//! **The one thing to read carefully if you're modifying this file:**
//! [`HybridStage2::verify`] for [`SessionStage`] runs its optional HMAC
//! pre-check *before* it ever calls `extensions.get::<Session>()`, and
//! returns on failure via `?` before reaching that line. This ordering is
//! the entire point of the pre-check — it lets an illegitimate request be
//! rejected on signature verification alone, with no database round trip —
//! so if you touch this function, preserve the order: pre-check first,
//! session resolution second, never the reverse.

use std::marker::PhantomData;

use async_trait::async_trait;
use http::Extensions;

use crate::builder::SharedSettingsBuilder;
use crate::cookie_config::{CookieConfig, CookieSettings, PrefixState};
use crate::crypto::{self, HmacConfig};
use crate::error::CsrfError;
use crate::patterns::{
    sealed, CsrfPattern, CsrfPatternDispatch, ExtractedTokens, IssuedToken, RequiredInput,
};
use crate::typestate::{Missing, Present};

/// Stage-2 marker: fully stateless. The token is HMAC-signed and
/// self-expiring; there is no session and nothing is ever persisted.
#[derive(Debug, Clone, Copy)]
pub struct HmacOnlyStage;

/// Stage-2 marker: the token is compared against a value stored in a
/// `tower_sessions::Session`, optionally behind an HMAC pre-check.
#[derive(Debug, Clone, Copy)]
pub struct SessionStage;

impl sealed::Sealed for HmacOnlyStage {}
impl sealed::Sealed for SessionStage {}

/// Sealed trait implemented only by [`HmacOnlyStage`] and [`SessionStage`];
/// it carries the behavior that differs between them. Its items are
/// implementation details.
#[async_trait]
pub trait HybridStage2: sealed::Sealed + Send + Sync + 'static {
    /// What this stage needs configured beyond the shared cookie and form
    /// field: an [`HmacConfig`] for [`HmacOnlyStage`], a
    /// [`HybridSessionConfig`] for [`SessionStage`].
    type Extra: Send + Sync + 'static;

    /// Cheap, no-I/O check of whether `existing` is still usable as-is.
    #[doc(hidden)]
    fn has_existing_valid(extra: &Self::Extra, existing: Option<&str>) -> bool;

    /// Generates a fresh token value. Does not persist it — see `on_issue`.
    #[doc(hidden)]
    fn generate_token(extra: &Self::Extra) -> String;

    /// Persists a freshly generated token wherever this stage's authority
    /// lives (the session, for [`SessionStage`]; nowhere, for
    /// [`HmacOnlyStage`]).
    #[doc(hidden)]
    async fn on_issue(extra: &Self::Extra, extensions: &Extensions, token: &str) -> Result<(), CsrfError>;

    /// Verifies `token` against this stage's authority.
    #[doc(hidden)]
    async fn verify(extra: &Self::Extra, token: &str, extensions: &Extensions) -> Result<(), CsrfError>;
}

#[async_trait]
impl HybridStage2 for HmacOnlyStage {
    type Extra = HmacConfig;

    fn has_existing_valid(extra: &HmacConfig, existing: Option<&str>) -> bool {
        existing.is_some_and(|s| extra.verify(s).is_ok())
    }

    fn generate_token(extra: &HmacConfig) -> String {
        extra.generate()
    }

    async fn on_issue(_extra: &HmacConfig, _extensions: &Extensions, _token: &str) -> Result<(), CsrfError> {
        // Nothing to persist: the signature itself is the sole authority.
        Ok(())
    }

    async fn verify(extra: &HmacConfig, token: &str, _extensions: &Extensions) -> Result<(), CsrfError> {
        extra.verify(token)
    }
}

/// Configuration for [`SessionStage`]. Both fields must be stated; there is
/// no `Default`.
pub struct HybridSessionConfig {
    /// The key under which the token is stored in the
    /// `tower_sessions::Session`.
    pub session_key: String,
    /// `Some(..)`: verify the token's HMAC signature and TTL *before* the
    /// session is resolved on every unsafe-method request, so a forged
    /// request is rejected without a session-store round trip. Tokens are
    /// then HMAC-signed. `None`: the session-stored comparison is the sole
    /// authority and tokens are plain random values.
    pub hmac_precheck: Option<HmacConfig>,
}

#[async_trait]
impl HybridStage2 for SessionStage {
    type Extra = HybridSessionConfig;

    fn has_existing_valid(extra: &HybridSessionConfig, existing: Option<&str>) -> bool {
        match &extra.hmac_precheck {
            Some(precheck) => existing.is_some_and(|s| precheck.verify(s).is_ok()),
            None => existing.is_some_and(|s| !s.is_empty()),
        }
    }

    fn generate_token(extra: &HybridSessionConfig) -> String {
        match &extra.hmac_precheck {
            Some(precheck) => precheck.generate(),
            None => crypto::generate_opaque_token(),
        }
    }

    async fn on_issue(extra: &HybridSessionConfig, extensions: &Extensions, token: &str) -> Result<(), CsrfError> {
        let session = extensions
            .get::<tower_sessions::Session>()
            .ok_or(CsrfError::MissingSessionExtension)?;
        session.insert(&extra.session_key, token).await?;
        Ok(())
    }

    async fn verify(extra: &HybridSessionConfig, token: &str, extensions: &Extensions) -> Result<(), CsrfError> {
        // CRITICAL ORDERING — see this module's top-level docs. The
        // pre-check, when configured, runs and must pass before anything
        // below touches the session. `?` returns early on failure, so a
        // request that fails the pre-check never reaches session
        // resolution: no `extensions.get::<Session>()`, no store call.
        if let Some(precheck) = &extra.hmac_precheck {
            precheck.verify(token)?;
        }

        // Only reached once the pre-check has passed (or wasn't configured
        // at all): now, and only now, do we resolve the session.
        let session = extensions
            .get::<tower_sessions::Session>()
            .ok_or(CsrfError::MissingSessionExtension)?;
        let stored: Option<String> = session.get(&extra.session_key).await?;
        match stored {
            Some(expected) if crypto::constant_time_eq(&expected, token) => Ok(()),
            _ => Err(CsrfError::SessionTokenMismatch),
        }
    }
}

/// Marker type selecting the hybrid pattern, parameterized by its stage-2
/// sub-approach ([`HmacOnlyStage`] or [`SessionStage`]). See the module
/// docs.
pub struct Hybrid<S2: HybridStage2>(PhantomData<S2>);

impl<S2: HybridStage2> sealed::Sealed for Hybrid<S2> {}
impl<S2: HybridStage2> CsrfPattern for Hybrid<S2> {
    type Config = HybridConfig<S2>;
}

/// Immutable configuration for the hybrid pattern, parameterized by its
/// stage-2 sub-approach.
///
/// Construct one with [`HybridConfig::<HmacOnlyStage>::new`] or
/// [`HybridConfig::<SessionStage>::new`] (or let [`HybridBuilder`] do it).
/// The two constructors take different stage-2 arguments, so a session
/// configuration cannot be attached to an HMAC-only one or vice versa.
pub struct HybridConfig<S2: HybridStage2> {
    pub(crate) cookie: CookieSettings,
    pub(crate) form_field: String,
    pub(crate) stage2: S2::Extra,
}

impl HybridConfig<HmacOnlyStage> {
    /// Fully stateless: stage 2 is the token's HMAC signature and TTL. The
    /// cookie's `HttpOnly` attribute is always `true`.
    pub fn new<S: PrefixState>(
        cookie: CookieConfig<S>,
        form_field: impl Into<String>,
        hmac: HmacConfig,
    ) -> Self {
        Self {
            cookie: cookie.resolve(),
            form_field: form_field.into(),
            stage2: hmac,
        }
    }
}

impl HybridConfig<SessionStage> {
    /// Session-backed: stage 2 compares the token against the session, with
    /// an optional HMAC pre-check (see [`HybridSessionConfig`]). The
    /// cookie's `HttpOnly` attribute is always `true`.
    pub fn new<S: PrefixState>(
        cookie: CookieConfig<S>,
        form_field: impl Into<String>,
        session: HybridSessionConfig,
    ) -> Self {
        Self {
            cookie: cookie.resolve(),
            form_field: form_field.into(),
            stage2: session,
        }
    }
}

#[async_trait]
impl<S2: HybridStage2> CsrfPatternDispatch for Hybrid<S2> {
    fn required_input(config: &Self::Config) -> RequiredInput {
        RequiredInput {
            cookie_name: Some(config.cookie.name.clone()),
            body_field: Some(config.form_field.clone()),
            header: None,
        }
    }

    async fn verify(
        config: &Self::Config,
        extracted: ExtractedTokens,
        extensions: &Extensions,
    ) -> Result<(), CsrfError> {
        // Stage 1: cookie/form double-check.
        let cookie_val = extracted.cookie.ok_or(CsrfError::MissingToken)?;
        let submitted = extracted.submitted.ok_or(CsrfError::MissingToken)?;
        if !crypto::constant_time_eq(&cookie_val, &submitted) {
            return Err(CsrfError::TokenMismatch);
        }
        // Stage 2: HMAC-only or session-backed, per `S2`.
        S2::verify(&config.stage2, &cookie_val, extensions).await
    }

    async fn ensure_token(
        config: &Self::Config,
        extensions: &Extensions,
        existing_cookie_value: Option<&str>,
        force_new: bool,
    ) -> Result<IssuedToken, CsrfError> {
        if force_new || !S2::has_existing_valid(&config.stage2, existing_cookie_value) {
            let token = S2::generate_token(&config.stage2);
            S2::on_issue(&config.stage2, extensions, &token).await?;
            let set_cookie = config.cookie.set_cookie_header(&token, true); // always HttpOnly
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

/// Type-state builder for [`HybridConfig`]. `.cookie(..)` and
/// `.form_field(..)` are required, in either order; the stage-2
/// sub-approach is chosen last, via `.hmac_only(..)` or `.session(..)`.
pub struct HybridBuilder<C = Missing, F = Missing> {
    cookie: Option<CookieSettings>,
    form_field: Option<String>,
    _marker: PhantomData<(C, F)>,
}

impl HybridBuilder<Missing, Missing> {
    pub(crate) fn new() -> Self {
        Self {
            cookie: None,
            form_field: None,
            _marker: PhantomData,
        }
    }
}

impl<F> HybridBuilder<Missing, F> {
    /// The cookie this pattern sets and reads. Its `HttpOnly` attribute is
    /// always `true`, per the pattern's requirements — see the module
    /// docs; [`CookieConfig`] does not expose a setting for it.
    pub fn cookie<S: PrefixState>(self, cookie: CookieConfig<S>) -> HybridBuilder<Present, F> {
        HybridBuilder {
            cookie: Some(cookie.resolve()),
            form_field: self.form_field,
            _marker: PhantomData,
        }
    }
}

impl<C> HybridBuilder<C, Missing> {
    /// The body field name the client submits the token under (always a
    /// form field for this pattern — see the module docs). Rendering the
    /// current token into a hidden form field with this name is your
    /// responsibility — read it from the request extensions via
    /// [`crate::CsrfToken`] in your handler.
    pub fn form_field(self, field: impl Into<String>) -> HybridBuilder<C, Present> {
        HybridBuilder {
            cookie: self.cookie,
            form_field: Some(field.into()),
            _marker: PhantomData,
        }
    }
}

impl HybridBuilder<Present, Present> {
    /// Selects the fully stateless stage 2: the token must carry a valid
    /// HMAC signature and be within `hmac`'s TTL. No session is used.
    pub fn hmac_only(self, hmac: HmacConfig) -> SharedSettingsBuilder<Hybrid<HmacOnlyStage>> {
        SharedSettingsBuilder::new(HybridConfig {
            cookie: self.cookie.expect("Present guarantees this is set"),
            form_field: self.form_field.expect("Present guarantees this is set"),
            stage2: hmac,
        })
    }

    /// Selects the session-backed stage 2, storing the token under
    /// `session_key`. Optionally chain `.with_hmac_precheck(..)` before
    /// `.done()` to verify a signature before the session is ever resolved.
    pub fn session(self, session_key: impl Into<String>) -> HybridSessionSubBuilder {
        HybridSessionSubBuilder {
            cookie: self.cookie.expect("Present guarantees this is set"),
            form_field: self.form_field.expect("Present guarantees this is set"),
            session_key: session_key.into(),
            hmac_precheck: None,
        }
    }
}

/// Continuation builder for the hybrid pattern's session-backed stage 2,
/// letting you optionally attach an HMAC pre-check before finishing.
pub struct HybridSessionSubBuilder {
    cookie: CookieSettings,
    form_field: String,
    session_key: String,
    hmac_precheck: Option<HmacConfig>,
}

impl HybridSessionSubBuilder {
    /// Adds an HMAC pre-check, verified *before* the session is resolved on
    /// every unsafe-method request — so a forged request with an invalid
    /// signature is rejected without a database round trip. Without this,
    /// the session-stored comparison is the sole authority.
    pub fn with_hmac_precheck(mut self, hmac: HmacConfig) -> Self {
        self.hmac_precheck = Some(hmac);
        self
    }

    /// Finishes hybrid-specific configuration.
    pub fn done(self) -> SharedSettingsBuilder<Hybrid<SessionStage>> {
        SharedSettingsBuilder::new(HybridConfig {
            cookie: self.cookie,
            form_field: self.form_field,
            stage2: HybridSessionConfig {
                session_key: self.session_key,
                hmac_precheck: self.hmac_precheck,
            },
        })
    }
}
