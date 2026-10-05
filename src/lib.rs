//! # tower-csrf-shield
//!
//! CSRF protection as a [`tower::Layer`]. You pick one of three patterns and
//! state every detail of it; the type system rejects incoherent
//! combinations at compile time, and the built layer is immutable.
//!
//! | Pattern | Marker type | Token lives in | Client submits it via |
//! |---|---|---|---|
//! | Synchronizer | [`Synchronizer`] | a `tower_sessions::Session` | body form field |
//! | Double submit | [`DoubleSubmit`]`<`[`Naive`]`>` / `<`[`Hmac`]`>` | non-`HttpOnly` cookie | cookie + (form field **or** header) |
//! | Hybrid | [`Hybrid`]`<`[`HmacOnlyStage`]`>` / `<`[`SessionStage`]`>` | `HttpOnly` cookie (+ session) | cookie + form field |
//!
//! See each pattern's module ([`synchronizer`], [`double_submit`],
//! [`hybrid`]) for what it does and why; this page covers wiring and the
//! compile-time guarantees.
//!
//! # Quick start
//!
//! ```
//! use tower_csrf_shield::{CookieConfig, CookieSameSite, CsrfLayerBuilder, RegenerateToken};
//!
//! let layer = CsrfLayerBuilder::new()
//!     .double_submit()
//!     .cookie(CookieConfig::standard("csrf", CookieSameSite::Lax, true))
//!     .submit_via_form_field("csrf_token")
//!     .naive()
//!     .regenerate_token(RegenerateToken::PerSession)
//!     .skip_origin_check()
//!     .build();
//! # let _ = layer;
//! ```
//!
//! Apply it with `tower::ServiceBuilder` or, in axum, `Router::layer`. In
//! your handler, extract the current token — with axum,
//! `Extension<CsrfToken>` — and render it into a hidden form field with the
//! name you configured; that one step is deliberately left to you (see
//! [`CsrfToken`]). Everything else — issuing, verifying, rotating,
//! attaching `Set-Cookie` — the layer does on its own.
//!
//! # Wiring with `tower_sessions`
//!
//! The synchronizer pattern, and the hybrid pattern's [`SessionStage`],
//! need a [`tower_sessions::Session`] already present in the request's
//! extensions, which means `SessionManagerLayer` must sit *above* (outside)
//! this layer in the stack:
//!
//! ```ignore
//! use tower::ServiceBuilder;
//! use tower_sessions::{MemoryStore, SessionManagerLayer};
//!
//! let app = ServiceBuilder::new()
//!     .layer(SessionManagerLayer::new(MemoryStore::default()))
//!     .layer(csrf_layer) // reads tower_sessions::Session from extensions
//!     .service(app_service);
//! ```
//!
//! If it's missing at request time (session middleware not installed, or
//! installed in the wrong order), the layer responds `500` rather than
//! `403` — a missing session is a deployment bug, not a forged request, and
//! treating it as the latter would hide the bug behind what looks like
//! ordinary, ignorable CSRF noise.
//!
//! # Compile-time guarantees
//!
//! A builder only exposes the methods relevant to the pattern and
//! sub-approach you're already in, so, for example, HMAC configuration is
//! simply not reachable on a naive double-submit builder:
//!
//! ```compile_fail
//! use std::time::Duration;
//! use tower_csrf_shield::{CookieConfig, CookieSameSite, CsrfLayerBuilder, HmacConfig};
//!
//! let _ = CsrfLayerBuilder::new()
//!     .double_submit()
//!     .cookie(CookieConfig::standard("csrf", CookieSameSite::Lax, true))
//!     .submit_via_form_field("csrf_token")
//!     .naive()
//!     .hmac(HmacConfig::new(b"secret", Duration::from_secs(1))); // no such method here
//! ```
//!
//! And a pattern's required fields are tracked in the builder's own type,
//! so the method that finishes it — here, [`synchronizer::SynchronizerBuilder::done`]
//! — only exists once every required field has actually been set:
//!
//! ```compile_fail
//! use tower_csrf_shield::CsrfLayerBuilder;
//!
//! let _ = CsrfLayerBuilder::new()
//!     .synchronizer()
//!     .session_key("csrf")
//!     .done(); // `.form_field(..)` was never called
//! ```
//!
//! [`CookieConfig`] never exposes an `HttpOnly` setting at all (double
//! submit's cookie is always non-`HttpOnly`; hybrid's is always
//! `HttpOnly` — neither is a choice you make), and
//! [`CookieConfig::host_prefixed`] hardcodes `Secure` rather than exposing
//! a setter that could contradict the `__Host-` prefix's own requirements.

mod builder;
mod cookie_config;
mod crypto;
mod csrf_token;
mod error;
mod layer;
mod origin;
mod patterns;
mod regenerate;
mod service;
mod transport;
mod typestate;

pub use builder::{CsrfLayerBuilder, SharedSettingsBuilder};
pub use cookie_config::{CookieConfig, CookieSameSite, HostPrefixed, NotHostPrefixed, PrefixState};
pub use crypto::HmacConfig;
pub use csrf_token::CsrfToken;
pub use error::CsrfError;
pub use layer::CsrfLayer;
pub use origin::OriginPolicy;
pub use patterns::CsrfPattern;
pub use patterns::{double_submit, hybrid, synchronizer};
pub use regenerate::RegenerateToken;
pub use service::CsrfService;
pub use transport::{MaybeBufferedBody, TokenTransport};
pub use typestate::{Missing, Present};

pub use double_submit::{DoubleSubmit, Hmac, Naive};
pub use hybrid::{HmacOnlyStage, Hybrid, SessionStage};
pub use synchronizer::Synchronizer;
