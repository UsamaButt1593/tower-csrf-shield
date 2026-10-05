/// This enum is to determine
/// at which occurences the CSRF token should be regenerated.
///
/// You could understand these options as modes to choose a level of paranoia, depending on your application's requirements.
///
/// This paranoia level is a trade-off between ergonomics and security; as more frequent
/// token invalidation requires more overhead for handling and renewing tokens on the client side,
/// as well as retrying requests with a fresh token, should they fail.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum RegenerateToken {
    /// Generate one CSRF token per session and use this token until the session ends.
    ///
    /// This is the default behavior and should work for most applications.
    #[default]
    PerSession,
    /// Regenerate the CSRF token after each use. A "use" describes an unsafe HTTP method
    /// (`POST`, `PUT`, `PATCH`, `DELETE`).
    ///
    /// CSRF tokens are not required for, and thus not invalidated by handling requests
    /// using safe HTTP methods (`HEAD`, `GET`, `OPTIONS`, `TRACE`, `CONNECT`).
    PerUse,
    /// Regenerate the CSRF token at each request, including safe HTTP methods (`HEAD`, `GET`, `OPTIONS`, `TRACE`, `CONNECT`).
    ///
    /// This behavior might require elaborate token handling on the client side,
    /// as any concurrent requests mean race conditions from the client's perspective,
    /// and each request's response yields a new token to be used on the consecutive request.
    PerRequest,
}

impl RegenerateToken {
    /// Whether a *successful* unsafe-method request (one that already passed
    /// verification) should rotate the token.
    pub(crate) fn rotates_on_use(self) -> bool {
        matches!(self, Self::PerUse | Self::PerRequest)
    }

    /// Whether every single request (including safe methods) should force a
    /// fresh token regardless of whether an existing one is still usable.
    pub(crate) fn rotates_on_every_request(self) -> bool {
        matches!(self, Self::PerRequest)
    }
}
