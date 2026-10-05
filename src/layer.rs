//! [`CsrfLayer`]: the immutable `tower::Layer` this crate is about.

use std::sync::Arc;

use tower::Layer;

use crate::origin::OriginPolicy;
use crate::patterns::CsrfPattern;
use crate::regenerate::RegenerateToken;
use crate::service::CsrfService;

/// Everything a built layer holds. Wrapped in an `Arc` by [`CsrfLayer`] so
/// that cloning a layer (or the services it produces) never copies secrets
/// or configuration, and so that nothing about it can be mutated after
/// construction: there is no `&mut` access to this struct anywhere.
pub(crate) struct CsrfLayerInner<P: CsrfPattern> {
    pub(crate) pattern_config: P::Config,
    pub(crate) regenerate: RegenerateToken,
    pub(crate) origin: OriginPolicy,
}

/// A [`tower::Layer`] providing CSRF protection using pattern `P`
/// ([`Synchronizer`](crate::Synchronizer),
/// [`DoubleSubmit`](crate::DoubleSubmit), or [`Hybrid`](crate::Hybrid),
/// each further parameterized by its sub-approach).
///
/// Immutable once built, and cheap to clone.
///
/// Build one with [`CsrfLayerBuilder`](crate::CsrfLayerBuilder), or
/// directly with [`CsrfLayer::new`].
pub struct CsrfLayer<P: CsrfPattern> {
    pub(crate) inner: Arc<CsrfLayerInner<P>>,
}

impl<P: CsrfPattern> Clone for CsrfLayer<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P: CsrfPattern> CsrfLayer<P> {
    /// Constructs a layer directly from a pattern's resolved config plus the
    /// settings every pattern shares, bypassing the fluent builder.
    ///
    /// Every argument is required and there are no defaults, by design: the
    /// point of this crate is that nothing security-relevant is decided on
    /// your behalf. Because each pattern's config type is itself shaped so
    /// that contradictory settings are unrepresentable (e.g. HMAC settings
    /// exist only on the HMAC variants), this path is no less safe than the
    /// builder — only less guided.
    pub fn new(
        pattern_config: P::Config,
        regenerate: RegenerateToken,
        origin: OriginPolicy,
    ) -> Self {
        Self {
            inner: Arc::new(CsrfLayerInner {
                pattern_config,
                regenerate,
                origin,
            }),
        }
    }
}

impl<P: CsrfPattern, S> Layer<S> for CsrfLayer<P> {
    type Service = CsrfService<P, S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService {
            inner,
            layer: self.clone(),
        }
    }
}
