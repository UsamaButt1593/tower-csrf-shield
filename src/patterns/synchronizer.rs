//! The synchronizer token pattern: the token is generated and stored
//! server-side, in a `tower_sessions::Session`, and compared against
//! whatever the client submits back in a body field.
//!
//! Requires a `tower_sessions::SessionManagerLayer` to run *above* (outside)
//! this layer in the stack, so that a `tower_sessions::Session` is already
//! present in the request's extensions by the time this layer runs.

use std::marker::PhantomData;

use async_trait::async_trait;
use http::Extensions;

use crate::builder::SharedSettingsBuilder;
use crate::crypto;
use crate::error::CsrfError;
use crate::patterns::{sealed, CsrfPattern, CsrfPatternDispatch, ExtractedTokens, IssuedToken, RequiredInput};
use crate::typestate::{Missing, Present};

/// Marker type selecting the synchronizer pattern. See the module docs.
#[derive(Debug, Clone, Copy)]
pub struct Synchronizer;

impl sealed::Sealed for Synchronizer {}
impl CsrfPattern for Synchronizer {
    type Config = SynchronizerConfig;
}

/// Configuration for the synchronizer pattern. Both fields are required and
/// there is no `Default`: state each explicitly, either by filling in this
/// struct directly (and passing it to [`CsrfLayer::new`](crate::CsrfLayer::new))
/// or via [`SynchronizerBuilder`].
#[derive(Clone, Debug)]
pub struct SynchronizerConfig {
    /// The key under which the token is stored in the
    /// `tower_sessions::Session` (via `session.insert(key, token)`).
    pub session_key: String,
    /// The body field name the client submits the token under. Rendering
    /// the current token into a hidden form field with this name is your
    /// responsibility — see [`CsrfToken`](crate::CsrfToken).
    pub form_field: String,
}

#[async_trait]
impl CsrfPatternDispatch for Synchronizer {
    fn required_input(config: &Self::Config) -> RequiredInput {
        RequiredInput {
            cookie_name: None,
            body_field: Some(config.form_field.clone()),
            header: None,
        }
    }

    async fn verify(
        config: &Self::Config,
        extracted: ExtractedTokens,
        extensions: &Extensions,
    ) -> Result<(), CsrfError> {
        let submitted = extracted.submitted.ok_or(CsrfError::MissingToken)?;
        let session = extensions
            .get::<tower_sessions::Session>()
            .ok_or(CsrfError::MissingSessionExtension)?;
        let stored: Option<String> = session.get(&config.session_key).await?;
        match stored {
            Some(expected) if crypto::constant_time_eq(&expected, &submitted) => Ok(()),
            _ => Err(CsrfError::SessionTokenMismatch),
        }
    }

    async fn ensure_token(
        config: &Self::Config,
        extensions: &Extensions,
        _existing_cookie_value: Option<&str>,
        force_new: bool,
    ) -> Result<IssuedToken, CsrfError> {
        let session = extensions
            .get::<tower_sessions::Session>()
            .ok_or(CsrfError::MissingSessionExtension)?;

        if !force_new {
            if let Some(existing) = session.get::<String>(&config.session_key).await? {
                return Ok(IssuedToken {
                    value: existing,
                    set_cookie: None,
                });
            }
        }

        let token = crypto::generate_opaque_token();
        session.insert(&config.session_key, &token).await?;
        Ok(IssuedToken {
            value: token,
            set_cookie: None,
        })
    }
}

/// Type-state builder for [`SynchronizerConfig`]. Both fields are required;
/// `.session_key(..)` and `.form_field(..)` may be called in either order,
/// and each is only callable once — the method disappears from the type
/// once its slot reads [`Present`].
pub struct SynchronizerBuilder<K = Missing, F = Missing> {
    session_key: Option<String>,
    form_field: Option<String>,
    _marker: PhantomData<(K, F)>,
}

impl SynchronizerBuilder<Missing, Missing> {
    pub(crate) fn new() -> Self {
        Self {
            session_key: None,
            form_field: None,
            _marker: PhantomData,
        }
    }
}

impl<F> SynchronizerBuilder<Missing, F> {
    /// The key this pattern uses to store the token inside the
    /// `tower_sessions::Session` (via `session.insert(key, token)`).
    pub fn session_key(self, key: impl Into<String>) -> SynchronizerBuilder<Present, F> {
        SynchronizerBuilder {
            session_key: Some(key.into()),
            form_field: self.form_field,
            _marker: PhantomData,
        }
    }
}

impl<K> SynchronizerBuilder<K, Missing> {
    /// The body field name the client submits the token under. Rendering
    /// the current token into a hidden form field with this name is your
    /// responsibility — read it from the request extensions via
    /// [`crate::CsrfToken`] in your handler.
    pub fn form_field(self, field: impl Into<String>) -> SynchronizerBuilder<K, Present> {
        SynchronizerBuilder {
            session_key: self.session_key,
            form_field: Some(field.into()),
            _marker: PhantomData,
        }
    }
}

impl SynchronizerBuilder<Present, Present> {
    /// Finishes synchronizer-specific configuration and moves on to the
    /// settings shared by every pattern (token regeneration policy, origin
    /// check).
    pub fn done(self) -> SharedSettingsBuilder<Synchronizer> {
        SharedSettingsBuilder::new(SynchronizerConfig {
            session_key: self.session_key.expect("Present guarantees this is set"),
            form_field: self.form_field.expect("Present guarantees this is set"),
        })
    }
}
