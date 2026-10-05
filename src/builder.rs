//! The fluent, type-state builder for [`CsrfLayer`].
//!
//! Construction proceeds in three phases, and the type system enforces the
//! order and completeness of each:
//!
//! 1. **Choose a pattern** — [`CsrfLayerBuilder::synchronizer`],
//!    [`CsrfLayerBuilder::double_submit`], or [`CsrfLayerBuilder::hybrid`].
//!    Each returns a builder exposing *only* the methods relevant to that
//!    pattern (there is no `hmac_secret` method on the synchronizer
//!    builder, no `session_key` on the double-submit builder, and no
//!    `http_only` setting anywhere, because none of those combinations is
//!    meaningful).
//! 2. **Fill that pattern's required fields**, then choose its
//!    sub-approach where one exists (`.naive()`/`.hmac(..)` for
//!    double-submit, `.hmac_only(..)`/`.session(..)` for hybrid). Every
//!    required slot is tracked in the builder's type via
//!    [`Missing`]/[`Present`]; the method that leaves this phase only
//!    exists once every slot reads `Present`.
//! 3. **Fill the settings every pattern shares** — a [`RegenerateToken`]
//!    policy and an [`OriginPolicy`] — via [`SharedSettingsBuilder`], then
//!    `.build()`.
//!
//! If you would rather assemble the pattern's `*Config` yourself and skip
//! the fluent chain, use [`CsrfLayer::new`] directly; the config types are
//! themselves shaped so that invalid combinations cannot be written down
//! (see e.g. [`DoubleSubmitConfig`](crate::double_submit::DoubleSubmitConfig)).

use std::marker::PhantomData;

use crate::layer::CsrfLayer;
use crate::origin::OriginPolicy;
use crate::patterns::double_submit::DoubleSubmitBuilder;
use crate::patterns::hybrid::HybridBuilder;
use crate::patterns::synchronizer::SynchronizerBuilder;
use crate::patterns::CsrfPattern;
use crate::regenerate::RegenerateToken;
use crate::typestate::{Missing, Present};

/// Entry point of the fluent builder. See the [module docs](self).
#[derive(Debug, Clone, Copy, Default)]
pub struct CsrfLayerBuilder(());

impl CsrfLayerBuilder {
    /// Starts a new builder.
    pub fn new() -> Self {
        Self(())
    }

    /// Synchronizer pattern: the token lives in a `tower_sessions::Session`
    /// and is submitted back in a body field.
    pub fn synchronizer(self) -> SynchronizerBuilder {
        SynchronizerBuilder::new()
    }

    /// Double-submit pattern: the token lives in a (non-`HttpOnly`) cookie
    /// and is submitted back in a form field or header.
    pub fn double_submit(self) -> DoubleSubmitBuilder {
        DoubleSubmitBuilder::new()
    }

    /// Hybrid pattern: an `HttpOnly` cookie and a form field must match,
    /// then a second stage (HMAC-only, or session-backed with an optional
    /// HMAC pre-check) is verified.
    pub fn hybrid(self) -> HybridBuilder {
        HybridBuilder::new()
    }
}

/// The settings every pattern shares, filled in after the pattern-specific
/// fields: a [`RegenerateToken`] policy and an [`OriginPolicy`]. Both are
/// required, in either order:
///
/// - [`regenerate_token`](Self::regenerate_token)
/// - one of [`skip_origin_check`](Self::skip_origin_check),
///   [`allowed_origins`](Self::allowed_origins), or
///   [`origin_policy`](Self::origin_policy)
///
/// then [`build`](Self::build).
pub struct SharedSettingsBuilder<P: CsrfPattern, R = Missing, O = Missing> {
    pattern_config: P::Config,
    regenerate: Option<RegenerateToken>,
    origin: Option<OriginPolicy>,
    _marker: PhantomData<(R, O)>,
}

impl<P: CsrfPattern> SharedSettingsBuilder<P, Missing, Missing> {
    pub(crate) fn new(pattern_config: P::Config) -> Self {
        Self {
            pattern_config,
            regenerate: None,
            origin: None,
            _marker: PhantomData,
        }
    }
}

impl<P: CsrfPattern, O> SharedSettingsBuilder<P, Missing, O> {
    /// When the token is regenerated. There is deliberately no default:
    /// choose one explicitly (see [`RegenerateToken`] for the tradeoffs).
    pub fn regenerate_token(self, policy: RegenerateToken) -> SharedSettingsBuilder<P, Present, O> {
        SharedSettingsBuilder {
            pattern_config: self.pattern_config,
            regenerate: Some(policy),
            origin: self.origin,
            _marker: PhantomData,
        }
    }
}

impl<P: CsrfPattern, R> SharedSettingsBuilder<P, R, Missing> {
    /// Sets the origin policy explicitly.
    pub fn origin_policy(self, policy: OriginPolicy) -> SharedSettingsBuilder<P, R, Present> {
        SharedSettingsBuilder {
            pattern_config: self.pattern_config,
            regenerate: self.regenerate,
            origin: Some(policy),
            _marker: PhantomData,
        }
    }

    /// Do not check the `Origin` header.
    pub fn skip_origin_check(self) -> SharedSettingsBuilder<P, R, Present> {
        self.origin_policy(OriginPolicy::Skip)
    }

    /// Reject unsafe-method requests whose `Origin` header is missing or
    /// not exactly one of `origins` (e.g. `"https://example.com"`).
    pub fn allowed_origins(
        self,
        origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> SharedSettingsBuilder<P, R, Present> {
        self.origin_policy(OriginPolicy::enforce(origins))
    }
}

impl<P: CsrfPattern> SharedSettingsBuilder<P, Present, Present> {
    /// Finishes the builder. The resulting layer is immutable.
    pub fn build(self) -> CsrfLayer<P> {
        CsrfLayer::new(
            self.pattern_config,
            self.regenerate.expect("Present guarantees this is set"),
            self.origin.expect("Present guarantees this is set"),
        )
    }
}
