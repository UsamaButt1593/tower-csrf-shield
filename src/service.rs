//! [`CsrfService`]: the `tower::Service` produced by [`CsrfLayer`].
//!
//! Per request, in order:
//!
//! 1. **Origin check** (unsafe methods only, and only if enabled).
//! 2. **Read what the pattern needs** off the request: the cookie (if the
//!    pattern uses one) and — for unsafe methods — the submitted token,
//!    from a header (free) or a form field (which buffers the body).
//! 3. **Verify** (unsafe methods only), via the pattern's own logic.
//!    Failure short-circuits with `403`; a misconfigured deployment
//!    (missing session middleware, failing store) short-circuits with `500`
//!    instead, so it can't masquerade as "invalid token".
//! 4. **Ensure a token exists** for this response, reusing or regenerating
//!    it per the [`RegenerateToken`](crate::RegenerateToken) policy, and
//!    insert it into the request extensions as a [`CsrfToken`].
//! 5. Call the inner service, then attach any `Set-Cookie` the pattern
//!    needs to the response (appended, never replacing, so a session
//!    layer's own `Set-Cookie` survives).
//!
//! Nothing here is generic over the pattern's *logic*: that all lives behind
//! [`CsrfPatternDispatch`]. This file only orchestrates.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::SET_COOKIE;
use http::request::Parts;
use http::{Method, Request, Response, StatusCode};
use http_body::Body;
use http_body_util::Full;
use tower_service::Service;

use crate::cookie_config::find_cookie;
use crate::csrf_token::CsrfToken;
use crate::error::CsrfError;
use crate::layer::CsrfLayer;
use crate::patterns::{CsrfPattern, CsrfPatternDispatch, ExtractedTokens};
use crate::transport::{self, MaybeBufferedBody};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The [`tower::Service`] produced by [`CsrfLayer`]. See the
/// [module docs](self) for what it does per request.
pub struct CsrfService<P: CsrfPattern, S> {
    pub(crate) inner: S,
    pub(crate) layer: CsrfLayer<P>,
}

impl<P: CsrfPattern, S: Clone> Clone for CsrfService<P, S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            layer: self.layer.clone(),
        }
    }
}

impl<P, S, ReqBody, ResBody> Service<Request<ReqBody>> for CsrfService<P, S>
where
    P: CsrfPatternDispatch,
    S: Service<Request<MaybeBufferedBody<ReqBody>>, Response = Response<ResBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Body<Data = Bytes> + Send + Unpin + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: Default + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // The standard tower idiom: the instance that was just polled ready
        // is the one that must serve this call, so take it and leave a
        // fresh clone behind for the next `poll_ready`.
        let clone = self.inner.clone();
        let inner = std::mem::replace(&mut self.inner, clone);
        let layer = self.layer.clone();
        Box::pin(handle(layer, inner, req))
    }
}

async fn handle<P, S, ReqBody, ResBody>(
    layer: CsrfLayer<P>,
    mut inner: S,
    req: Request<ReqBody>,
) -> Result<Response<ResBody>, S::Error>
where
    P: CsrfPatternDispatch,
    S: Service<Request<MaybeBufferedBody<ReqBody>>, Response = Response<ResBody>>,
    ReqBody: Body<Data = Bytes> + Send + Unpin + 'static,
    ReqBody::Error: Into<BoxError>,
    ResBody: Default,
{
    let cfg = &layer.inner;
    let (mut parts, body) = req.into_parts();
    let is_safe = is_safe_method(&parts.method);

    // 1. Origin check — unsafe methods only, alongside (not instead of)
    //    the pattern's own verification.
    if !is_safe && !cfg.origin.check(&parts.headers) {
        return Ok(rejection(&CsrfError::OriginNotAllowed, &parts));
    }

    // 2. Read what the pattern needs. The cookie is read for *every*
    //    request, because even safe requests use it to decide whether the
    //    current token can be reused.
    let required = P::required_input(&cfg.pattern_config);
    let cookie_value: Option<String> = required
        .cookie_name
        .as_deref()
        .and_then(|name| find_cookie(&parts.headers, name));

    // 3. Unsafe methods: extract the submitted token and verify it. Safe
    //    methods skip verification and never touch the body.
    let new_body = if is_safe {
        MaybeBufferedBody::Original(body)
    } else {
        let (submitted, new_body) = if let Some(header_name) = required.header.as_ref() {
            let value = parts
                .headers
                .get(header_name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            (value, MaybeBufferedBody::Original(body))
        } else if let Some(field) = required.body_field.as_deref() {
            let is_form = transport::is_form_urlencoded(&parts.headers);
            match transport::buffer_and_read_form_field(body, field, is_form).await {
                Ok((value, bytes)) => (value, MaybeBufferedBody::Buffered(Full::new(bytes))),
                Err(e) => return Ok(rejection(&e, &parts)),
            }
        } else {
            (None, MaybeBufferedBody::Original(body))
        };

        let extracted = ExtractedTokens {
            cookie: cookie_value.clone(),
            submitted,
        };
        if let Err(e) = P::verify(&cfg.pattern_config, extracted, &parts.extensions).await {
            return Ok(rejection(&e, &parts));
        }
        new_body
    };

    // 4. Ensure a token for this response. After a *successful* unsafe
    //    request, `PerUse`/`PerRequest` rotate; on safe requests only
    //    `PerRequest` forces a new one.
    let force_new = if is_safe {
        cfg.regenerate.rotates_on_every_request()
    } else {
        cfg.regenerate.rotates_on_use()
    };
    let issued = match P::ensure_token(
        &cfg.pattern_config,
        &parts.extensions,
        cookie_value.as_deref(),
        force_new,
    )
    .await
    {
        Ok(issued) => issued,
        Err(e) => return Ok(rejection(&e, &parts)),
    };

    // 5. Hand the token to the handler, run it, attach any Set-Cookie.
    parts.extensions.insert(CsrfToken::new(issued.value));
    let mut response = inner.call(Request::from_parts(parts, new_body)).await?;
    if let Some(set_cookie) = issued.set_cookie {
        // `append`, never `insert`: a session layer may already have set
        // its own `Set-Cookie` on this response.
        response.headers_mut().append(SET_COOKIE, set_cookie);
    }
    Ok(response)
}

fn is_safe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::CONNECT
    )
}

/// Builds the short-circuit response for `err`, logging the reason
/// server-side only. The response never carries the reason: it would hand
/// an attacker an oracle on which check their forged request failed.
fn rejection<ResBody: Default>(err: &CsrfError, parts: &Parts) -> Response<ResBody> {
    let status = if err.is_server_fault() {
        tracing::error!(
            target: "tower_csrf_shield",
            method = %parts.method,
            uri = %parts.uri,
            error = %err,
            "CSRF layer cannot operate: misconfigured or session store failing"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        tracing::warn!(
            target: "tower_csrf_shield",
            method = %parts.method,
            uri = %parts.uri,
            error = %err,
            "request rejected"
        );
        StatusCode::FORBIDDEN
    };
    let mut response = Response::new(ResBody::default());
    *response.status_mut() = status;
    response
}
