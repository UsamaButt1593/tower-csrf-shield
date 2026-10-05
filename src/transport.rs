//! How the client is expected to echo the token back, and the plumbing
//! needed to read it out of a request body without discarding that body for
//! whatever runs after this layer.
//!
//! Reading a header costs nothing extra. Reading a form field requires
//! buffering the *entire* request body into memory (form fields aren't
//! necessarily at a fixed offset), so this module normalizes every request's
//! body into one concrete type — [`MaybeBufferedBody`] — that is either the
//! original, untouched, streaming body (safe methods; header transport) or a
//! fully-buffered one with the original bytes preserved for downstream
//! consumption (form-field transport on an unsafe-method request). Only
//! `application/x-www-form-urlencoded` bodies are supported for form-field
//! transport; multipart bodies are out of scope (see the crate-level docs).

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderMap, HeaderName};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};

use crate::error::CsrfError;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Where the client submits the token, in addition to the cookie, for the
/// double-submit pattern. The hybrid pattern does not expose this choice —
/// it always uses a form field, per its own configuration surface.
#[derive(Clone, Debug)]
pub enum TokenTransport {
    /// A field in an `application/x-www-form-urlencoded` request body.
    Form(String),
    /// An HTTP request header.
    Header(HeaderName),
}

/// A body that is either the original, unread body, or one that has already
/// been fully buffered into memory. Implements [`http_body::Body`] by
/// delegating to whichever variant is active, so an inner `tower::Service`
/// only ever needs to accept this one concrete type regardless of which
/// branch a given request took.
pub enum MaybeBufferedBody<B> {
    Original(B),
    Buffered(Full<Bytes>),
}

impl<B> Body for MaybeBufferedBody<B>
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Original(b) => Pin::new(b)
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(Into::into))),
            Self::Buffered(b) => Pin::new(b)
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(Into::into))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Original(b) => b.is_end_stream(),
            Self::Buffered(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Original(b) => b.size_hint(),
            Self::Buffered(b) => b.size_hint(),
        }
    }
}

/// Buffers `body` fully, parses it as `application/x-www-form-urlencoded`,
/// and returns the requested field's value (if present) alongside the raw
/// bytes, so the caller can hand an intact copy of the body onward.
///
/// Returns [`CsrfError::UnsupportedContentType`] without reading anything if
/// `content_type_is_form` is `false`, since a non-form body cannot contain a
/// form field by definition and there is no reason to buffer it.
pub(crate) async fn buffer_and_read_form_field<B>(
    body: B,
    field: &str,
    content_type_is_form: bool,
) -> Result<(Option<String>, Bytes), CsrfError>
where
    B: Body<Data = Bytes> + Send,
    B::Error: Into<BoxError>,
{
    if !content_type_is_form {
        return Err(CsrfError::UnsupportedContentType);
    }
    let collected = body
        .collect()
        .await
        .map_err(|e| CsrfError::BodyRead(e.into()))?;
    let bytes = collected.to_bytes();
    let value = form_urlencoded::parse(bytes.as_ref())
        .find(|(k, _)| k == field)
        .map(|(_, v)| v.into_owned());
    Ok((value, bytes))
}

/// `true` if the request's `Content-Type` is (ignoring parameters like
/// `charset`) `application/x-www-form-urlencoded`.
pub(crate) fn is_form_urlencoded(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            s.split(';')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_form_content_type_with_charset_param() {
        let mut h = HeaderMap::new();
        h.insert(
            http::header::CONTENT_TYPE,
            "application/x-www-form-urlencoded; charset=utf-8".parse().unwrap(),
        );
        assert!(is_form_urlencoded(&h));
    }

    #[test]
    fn rejects_other_content_types() {
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(!is_form_urlencoded(&h));
    }

    #[test]
    fn missing_content_type_is_not_form() {
        assert!(!is_form_urlencoded(&HeaderMap::new()));
    }

    #[tokio::test]
    async fn reads_field_and_preserves_bytes() {
        let raw = "csrf_token=abc123&other=xyz";
        let body = Full::new(Bytes::from(raw));
        let (value, bytes) = buffer_and_read_form_field(body, "csrf_token", true)
            .await
            .unwrap();
        assert_eq!(value.as_deref(), Some("abc123"));
        assert_eq!(bytes.as_ref(), raw.as_bytes());
    }

    #[tokio::test]
    async fn missing_field_yields_none() {
        let body = Full::new(Bytes::from("other=xyz"));
        let (value, _) = buffer_and_read_form_field(body, "csrf_token", true)
            .await
            .unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn wrong_content_type_errors_without_buffering() {
        let body = Full::new(Bytes::from("csrf_token=abc123"));
        let result = buffer_and_read_form_field(body, "csrf_token", false).await;
        assert!(matches!(result, Err(CsrfError::UnsupportedContentType)));
    }
}
