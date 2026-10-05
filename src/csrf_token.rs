//! [`CsrfToken`]: how the layer hands the current token to your handler.

use std::fmt;

/// The CSRF token for the current request/response cycle.
///
/// The layer inserts one of these into the request's extensions on *every*
/// request it lets through (safe or unsafe), so your handler can render it
/// into a hidden form field — the one step this crate deliberately leaves
/// to you. With axum, extract it with `axum::Extension<CsrfToken>`; with a
/// bare `http::Request`, use `req.extensions().get::<CsrfToken>()`.
///
/// ```ignore
/// async fn form(Extension(token): Extension<CsrfToken>) -> Html<String> {
///     Html(format!(
///         r#"<form method="post" action="/change-email">
///                <input type="hidden" name="csrf_token" value="{}">
///                <input name="email">
///                <button>Change email</button>
///            </form>"#,
///         token.as_str()
///     ))
/// }
/// ```
///
/// The value is a base64url string (`A–Z a–z 0–9 - _`, plus `.` for the
/// HMAC-signed variants), so it never needs HTML- or URL-escaping; the
/// field name must match whatever you configured on the layer.
///
/// Under [`RegenerateToken::PerUse`](crate::RegenerateToken::PerUse) or
/// [`PerRequest`](crate::RegenerateToken::PerRequest), a token you rendered
/// earlier may have been superseded by the time the form is submitted; see
/// those variants' docs for the client-side consequences.
#[derive(Clone)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// The token, ready to place in a form field's `value` attribute.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CsrfToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Redacted so that `{:?}`-logging a request's extensions doesn't spill live
/// tokens into logs. Use [`CsrfToken::as_str`] or `Display` to get the
/// value.
impl fmt::Debug for CsrfToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfToken(<redacted>)")
    }
}
