//! Shared harness: a tiny in-process "browser" driving a real
//! `tower-sessions` + `tower-csrf-shield` stack, and a session store that counts
//! how often it is consulted.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{CONTENT_TYPE, COOKIE, SET_COOKIE};
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use tower::{Service, ServiceExt};
use tower_csrf_shield::{CsrfToken, MaybeBufferedBody};
use tower_sessions::session::{Id, Record};
use tower_sessions::session_store::{self, SessionStore};
use tower_sessions_memory_store::MemoryStore;

pub type Body = Full<Bytes>;

/// The innermost "application": replies `"<csrf token>\n<request body>"`, so
/// tests can see both which token the layer exposed and that the request
/// body arrived intact.
pub async fn app(req: Request<MaybeBufferedBody<Body>>) -> Result<Response<Body>, Infallible> {
    let token = req
        .extensions()
        .get::<CsrfToken>()
        .map(|t| t.as_str().to_owned())
        .unwrap_or_default();
    let (_, body) = req.into_parts();
    let bytes = body
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let text = format!("{token}\n{}", String::from_utf8_lossy(&bytes));
    Ok(Response::new(Full::new(Bytes::from(text))))
}

/// Builds `SessionManagerLayer -> $layer -> app`.
#[macro_export]
macro_rules! stack {
    ($layer:expr, $store:expr) => {
        ::tower::ServiceBuilder::new()
            .layer(::tower_sessions::SessionManagerLayer::new($store))
            .layer($layer)
            .service_fn($crate::common::app)
    };
}

/// Builds `$layer -> app` with no session middleware at all.
#[macro_export]
macro_rules! stack_no_session {
    ($layer:expr) => {
        ::tower::ServiceBuilder::new()
            .layer($layer)
            .service_fn($crate::common::app)
    };
}

/// A session store that counts calls, so tests can assert *when* the store
/// was (not) consulted.
#[derive(Debug, Clone, Default)]
pub struct CountingStore {
    inner: MemoryStore,
    pub loads: Arc<AtomicUsize>,
    pub saves: Arc<AtomicUsize>,
}

impl CountingStore {
    pub fn loads(&self) -> usize {
        self.loads.load(Ordering::SeqCst)
    }
    pub fn reset(&self) {
        self.loads.store(0, Ordering::SeqCst);
        self.saves.store(0, Ordering::SeqCst);
    }
}

#[async_trait]
impl SessionStore for CountingStore {
    async fn save(&self, record: &Record) -> session_store::Result<()> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        self.inner.save(record).await
    }
    async fn load(&self, id: &Id) -> session_store::Result<Option<Record>> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.inner.load(id).await
    }
    async fn delete(&self, id: &Id) -> session_store::Result<()> {
        self.inner.delete(id).await
    }
}

/// A minimal browser: keeps a cookie jar, sends it with each request unless
/// the request already carries its own `Cookie` header.
pub struct Client<S> {
    svc: S,
    pub jar: BTreeMap<String, String>,
}

impl<S> Client<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>,
{
    pub fn new(svc: S) -> Self {
        Self {
            svc,
            jar: BTreeMap::new(),
        }
    }

    /// Sends `req` with the jar's cookies (unless it sets its own `Cookie`
    /// header), then absorbs any `Set-Cookie` in the response into the jar.
    pub async fn send(&mut self, mut req: Request<Body>) -> Response<Body> {
        if !req.headers().contains_key(COOKIE) && !self.jar.is_empty() {
            req.headers_mut()
                .insert(COOKIE, self.cookie_header().parse().unwrap());
        }
        let resp = self.svc.ready().await.unwrap().call(req).await.unwrap();
        for sc in set_cookies(&resp) {
            if let Some((k, v)) = parse_set_cookie(&sc) {
                self.jar.insert(k, v);
            }
        }
        resp
    }

    /// Sends `req` exactly as given: no jar in, nothing absorbed out. Models
    /// an attacker's forged request.
    pub async fn raw(&mut self, req: Request<Body>) -> Response<Body> {
        self.svc.ready().await.unwrap().call(req).await.unwrap()
    }

    pub fn cookie_header(&self) -> String {
        self.jar
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

pub fn set_cookies(resp: &Response<Body>) -> Vec<String> {
    resp.headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

pub fn parse_set_cookie(sc: &str) -> Option<(String, String)> {
    let first = sc.split(';').next()?;
    let (k, v) = first.split_once('=')?;
    Some((k.trim().to_owned(), v.trim().to_owned()))
}

/// Finds the `Set-Cookie` header for cookie `name`, if the response has one.
pub fn set_cookie_named(resp: &Response<Body>, name: &str) -> Option<String> {
    set_cookies(resp).into_iter().find(|sc| {
        parse_set_cookie(sc)
            .map(|(k, _)| k == name)
            .unwrap_or(false)
    })
}

/// Splits the app's reply into `(csrf token exposed to the handler, echoed request body)`.
pub async fn read(resp: Response<Body>) -> (StatusCode, String, String) {
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let (token, body) = text.split_once('\n').unwrap_or((&text, ""));
    (status, token.to_owned(), body.to_owned())
}

pub fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::default())
        .unwrap()
}

pub fn post_form(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap()
}

pub fn post_json(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_owned())))
        .unwrap()
}

pub const SECRET: &[u8] = b"an-hmac-secret-of-at-least-32-bytes!!";
