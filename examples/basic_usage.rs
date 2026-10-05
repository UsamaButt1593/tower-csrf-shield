//! Constructs all three patterns, wires the session-backed ones behind
//! `tower_sessions::SessionManagerLayer`, and drives a couple of requests
//! through each — without a real TCP listener, so `cargo run --example
//! basic_usage` just prints what happened.
//!
//! In a real app, replace the `service_fn(handler)` at the bottom of each
//! stack with your actual router (e.g. an axum `Router`), and replace the
//! hand-built `Request`s with real ones from your server.

use std::convert::Infallible;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response};
use http_body_util::{BodyExt, Full};
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_csrf_shield::{
    CookieConfig, CookieSameSite, CsrfLayerBuilder, CsrfToken, HmacConfig, MaybeBufferedBody,
    RegenerateToken,
};
use tower_sessions::SessionManagerLayer;
use tower_sessions_memory_store::MemoryStore;

type Body = Full<Bytes>;

/// The application: reads whatever token the layer exposed and echoes it,
/// standing in for "render the token into a hidden form field".
async fn handler(req: Request<MaybeBufferedBody<Body>>) -> Result<Response<Body>, Infallible> {
    let token = req
        .extensions()
        .get::<CsrfToken>()
        .map(|t| t.as_str().to_owned())
        .unwrap_or_default();
    Ok(Response::new(Full::new(Bytes::from(format!(
        "token handed to the handler: {token}\n"
    )))))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().method(Method::GET).uri(uri).body(Body::default()).unwrap()
}

fn post_form(uri: &str, body: String) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(http::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

async fn body_text(resp: Response<Body>) -> String {
    String::from_utf8_lossy(&resp.into_body().collect().await.unwrap().to_bytes()).into_owned()
}

#[tokio::main]
async fn main() {
    // ---- Double submit, HMAC sub-approach: no session needed at all. ----
    println!("== double submit (hmac) ==");
    let csrf = CsrfLayerBuilder::new()
        .double_submit()
        .cookie(CookieConfig::host_prefixed("csrf", CookieSameSite::Strict))
        .submit_via_form_field("csrf_token")
        .hmac(HmacConfig::with_default_ttl(b"replace-with-a-real-32-byte-secret!"))
        .regenerate_token(RegenerateToken::PerUse)
        .skip_origin_check()
        .build();
    let mut svc = ServiceBuilder::new().layer(csrf).service_fn(handler);

    let resp = svc.ready().await.unwrap().call(get("/form")).await.unwrap();
    let set_cookie = resp.headers().get(http::header::SET_COOKIE).unwrap().to_str().unwrap().to_owned();
    let token = set_cookie.split(';').next().unwrap().split_once('=').unwrap().1.to_owned();
    println!("  GET  -> Set-Cookie: {set_cookie}");
    println!("  GET  -> {}", body_text(resp).await.trim_end());

    let mut req = post_form("/change-email", format!("csrf_token={token}"));
    req.headers_mut().insert(http::header::COOKIE, format!("__Host-csrf={token}").parse().unwrap());
    let resp = svc.ready().await.unwrap().call(req).await.unwrap();
    println!("  POST (valid token) -> {} {}", resp.status(), body_text(resp).await.trim_end());

    let mut forged = post_form("/change-email", "csrf_token=whatever-the-attacker-likes".into());
    forged.headers_mut().insert(http::header::COOKIE, "__Host-csrf=whatever-the-attacker-likes".parse().unwrap());
    let resp = svc.ready().await.unwrap().call(forged).await.unwrap();
    println!("  POST (self-consistent forgery, no valid signature) -> {}", resp.status());

    // ---- Synchronizer: needs SessionManagerLayer above it. ----
    println!("\n== synchronizer ==");
    let csrf = CsrfLayerBuilder::new()
        .synchronizer()
        .session_key("csrf")
        .form_field("csrf_token")
        .done()
        .regenerate_token(RegenerateToken::PerSession)
        .skip_origin_check()
        .build();
    let mut svc = ServiceBuilder::new()
        .layer(SessionManagerLayer::new(MemoryStore::default()))
        .layer(csrf)
        .service_fn(handler);

    let resp = svc.ready().await.unwrap().call(get("/form")).await.unwrap();
    let session_cookie = resp.headers().get(http::header::SET_COOKIE).unwrap().to_str().unwrap().to_owned();
    let session_kv = session_cookie.split(';').next().unwrap().to_owned();
    println!("  GET  -> {}", body_text(resp).await.trim_end());

    // Re-derive the token by asking again with the session cookie attached
    // (a real client would already have it from the GET above).
    let mut req = get("/form");
    req.headers_mut().insert(http::header::COOKIE, session_kv.parse().unwrap());
    let resp = svc.ready().await.unwrap().call(req).await.unwrap();
    let token = body_text(resp).await.trim_end().rsplit(' ').next().unwrap().to_owned();

    let mut req = post_form("/change-email", format!("csrf_token={token}"));
    req.headers_mut().insert(http::header::COOKIE, session_kv.parse().unwrap());
    let resp = svc.ready().await.unwrap().call(req).await.unwrap();
    println!("  POST (valid token, same session) -> {}", resp.status());

    // ---- Hybrid, session stage, with the HMAC pre-check. ----
    println!("\n== hybrid (session stage, hmac pre-check) ==");
    let csrf = CsrfLayerBuilder::new()
        .hybrid()
        .cookie(CookieConfig::host_prefixed("csrf", CookieSameSite::Lax))
        .form_field("csrf_token")
        .session("csrf")
        .with_hmac_precheck(HmacConfig::new(b"another-32-byte-or-longer-secret!!!", Duration::from_secs(300)))
        .done()
        .regenerate_token(RegenerateToken::PerSession)
        .skip_origin_check()
        .build();
    let mut svc = ServiceBuilder::new()
        .layer(SessionManagerLayer::new(MemoryStore::default()))
        .layer(csrf)
        .service_fn(handler);

    let resp = svc.ready().await.unwrap().call(get("/form")).await.unwrap();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .collect();
    println!("  GET  -> Set-Cookie: {}", cookies.join(" | "));
    let combined_cookie = cookies.join("; ");
    let token = body_text(resp).await.trim_end().rsplit(' ').next().unwrap().to_owned();

    let mut req = post_form("/change-email", format!("csrf_token={token}"));
    req.headers_mut().insert(http::header::COOKIE, combined_cookie.parse().unwrap());
    let resp = svc.ready().await.unwrap().call(req).await.unwrap();
    println!("  POST (valid) -> {}", resp.status());

    let mut req = post_form("/change-email", "csrf_token=garbage".into());
    req.headers_mut().insert(
        http::header::COOKIE,
        format!("{}; __Host-csrf=garbage", combined_cookie.split(';').next().unwrap()).parse().unwrap(),
    );
    let resp = svc.ready().await.unwrap().call(req).await.unwrap();
    println!("  POST (garbage token; rejected by the HMAC pre-check, no session lookup) -> {}", resp.status());
}
