#[macro_use]
mod common;

use std::time::Duration;

use common::*;
use http::header::{HeaderName, COOKIE};
use http::{Method, Request, StatusCode};
use tower_csrf_shield::double_submit::DoubleSubmitConfig;
use tower_csrf_shield::{
    CookieConfig, CookieSameSite, CsrfLayer, CsrfLayerBuilder, DoubleSubmit, Hmac, HmacConfig,
    Naive, OriginPolicy, RegenerateToken, TokenTransport,
};
use tower_sessions_memory_store::MemoryStore;

const HDR: &str = "x-csrf-token";

fn naive_form(policy: RegenerateToken) -> CsrfLayer<DoubleSubmit<Naive>> {
    CsrfLayerBuilder::new()
        .double_submit()
        .cookie(CookieConfig::standard("csrf", CookieSameSite::Lax, true))
        .submit_via_form_field("csrf_token")
        .naive()
        .regenerate_token(policy)
        .skip_origin_check()
        .build()
}

fn naive_header() -> CsrfLayer<DoubleSubmit<Naive>> {
    CsrfLayerBuilder::new()
        .double_submit()
        .cookie(CookieConfig::standard("csrf", CookieSameSite::Lax, true))
        .submit_via_header(HeaderName::from_static(HDR))
        .naive()
        .regenerate_token(RegenerateToken::PerSession)
        .skip_origin_check()
        .build()
}

fn hmac_form(ttl: Duration, policy: RegenerateToken) -> CsrfLayer<DoubleSubmit<Hmac>> {
    CsrfLayerBuilder::new()
        .double_submit()
        .cookie(CookieConfig::host_prefixed("csrf", CookieSameSite::Strict))
        .submit_via_form_field("csrf_token")
        .hmac(HmacConfig::new(SECRET, ttl))
        .regenerate_token(policy)
        .skip_origin_check()
        .build()
}

fn store() -> MemoryStore {
    MemoryStore::default()
}

fn post_with_cookie(cookie: &str, body: &str) -> Request<Body> {
    let mut r = post_form("/change", body);
    r.headers_mut().insert(COOKIE, cookie.parse().unwrap());
    r
}

#[tokio::test]
async fn cookie_is_not_http_only_and_carries_the_configured_attributes() {
    let mut c = Client::new(stack!(naive_form(RegenerateToken::PerSession), store()));
    let resp = c.send(get("/form")).await;
    let sc = set_cookie_named(&resp, "csrf").expect("csrf cookie");
    assert!(
        !sc.contains("HttpOnly"),
        "double submit must never be HttpOnly: {sc}"
    );
    assert!(sc.contains("SameSite=Lax"), "{sc}");
    assert!(sc.contains("Secure"), "{sc}");
    assert!(sc.contains("Path=/"), "{sc}");
    let (_, token, _) = read(resp).await;
    assert_eq!(
        parse_set_cookie(&sc).unwrap().1,
        token,
        "cookie and exposed token agree"
    );
}

#[tokio::test]
async fn naive_form_matching_cookie_and_field_pass_and_body_is_preserved() {
    let mut c = Client::new(stack!(naive_form(RegenerateToken::PerSession), store()));
    let (_, token, _) = read(c.send(get("/form")).await).await;
    let form = format!("email=a%40b.example&csrf_token={token}");
    let (status, _, echoed) = read(c.send(post_form("/change", &form)).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(echoed, form);
}

#[tokio::test]
async fn naive_form_rejects_mismatch_missing_cookie_and_missing_field() {
    let mut c = Client::new(stack!(naive_form(RegenerateToken::PerSession), store()));
    let (_, token, _) = read(c.send(get("/form")).await).await;

    let (s, ..) = read(c.send(post_form("/c", "csrf_token=other")).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "mismatch");

    let (s, ..) = read(c.send(post_form("/c", "email=x")).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "cookie present, field missing");

    let (s, ..) = read(c.raw(post_form("/c", &format!("csrf_token={token}"))).await).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "field present, cookie missing (the CSRF case)"
    );
}

#[tokio::test]
async fn naive_header_transport_accepts_json_bodies_and_never_reads_them() {
    let mut c = Client::new(stack!(naive_header(), store()));
    let (_, token, _) = read(c.send(get("/form")).await).await;

    let mut req = post_json("/api", r#"{"a":1}"#);
    req.headers_mut()
        .insert(HeaderName::from_static(HDR), token.parse().unwrap());
    let (status, _, echoed) = read(c.send(req).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(echoed, r#"{"a":1}"#);

    let (status, ..) = read(c.send(post_json("/api", "{}")).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "no header, no entry");

    let mut wrong = post_json("/api", "{}");
    wrong
        .headers_mut()
        .insert(HeaderName::from_static(HDR), "nope".parse().unwrap());
    let (status, ..) = read(c.send(wrong).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn naive_is_fooled_by_a_planted_cookie_but_hmac_is_not() {
    // The attack HMAC exists for: the attacker can set cookies for the
    // target (subdomain / cookie injection), so they choose the value and
    // put it in both channels.
    let planted = "csrf=evil";
    let forged = "csrf_token=evil";

    let mut naive = Client::new(stack!(naive_form(RegenerateToken::PerSession), store()));
    let (s, ..) = read(naive.raw(post_with_cookie(planted, forged)).await).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "naive double submit is defeated by cookie injection (by design)"
    );

    let mut hmac = Client::new(stack!(
        hmac_form(Duration::from_secs(3600), RegenerateToken::PerSession),
        store()
    ));
    let (s, ..) = read(hmac.raw(post_with_cookie("__Host-csrf=evil", forged)).await).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "unsigned values must not pass under HMAC"
    );
}

#[tokio::test]
async fn hmac_legit_flow_passes_and_uses_a_signed_three_part_token() {
    let mut c = Client::new(stack!(
        hmac_form(Duration::from_secs(3600), RegenerateToken::PerSession),
        store()
    ));
    let resp = c.send(get("/form")).await;
    let sc = set_cookie_named(&resp, "__Host-csrf").expect("host-prefixed cookie");
    assert!(
        sc.contains("Secure") && sc.contains("Path=/") && !sc.contains("Domain"),
        "{sc}"
    );
    assert!(!sc.contains("HttpOnly"));
    let (_, token, _) = read(resp).await;
    assert_eq!(token.split('.').count(), 3, "nonce.timestamp.signature");

    let (status, ..) = read(
        c.send(post_form("/c", &format!("csrf_token={token}")))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn hmac_rejects_tokens_signed_with_a_different_secret_and_tampered_ones() {
    let other = CsrfLayerBuilder::new()
        .double_submit()
        .cookie(CookieConfig::host_prefixed("csrf", CookieSameSite::Strict))
        .submit_via_form_field("csrf_token")
        .hmac(HmacConfig::new(
            b"a-completely-different-secret-key!!!!",
            Duration::from_secs(3600),
        ))
        .regenerate_token(RegenerateToken::PerSession)
        .skip_origin_check()
        .build();
    let mut foreign = Client::new(stack!(other, store()));
    let (_, foreign_token, _) = read(foreign.send(get("/")).await).await;

    let mut c = Client::new(stack!(
        hmac_form(Duration::from_secs(3600), RegenerateToken::PerSession),
        store()
    ));
    let cookie = format!("__Host-csrf={foreign_token}");
    let (s, ..) = read(
        c.raw(post_with_cookie(
            &cookie,
            &format!("csrf_token={foreign_token}"),
        ))
        .await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "wrong secret");

    let (_, good, _) = read(c.send(get("/")).await).await;
    let mut tampered = good.clone();
    tampered.replace_range(0..1, if good.starts_with('A') { "B" } else { "A" });
    let cookie = format!("__Host-csrf={tampered}");
    let (s, ..) = read(
        c.raw(post_with_cookie(&cookie, &format!("csrf_token={tampered}")))
            .await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "tampered nonce");
}

#[tokio::test]
async fn hmac_tokens_expire_and_get_reissued_on_the_next_safe_request() {
    let mut c = Client::new(stack!(
        hmac_form(Duration::from_millis(30), RegenerateToken::PerSession),
        store()
    ));
    let (_, old, _) = read(c.send(get("/")).await).await;
    tokio::time::sleep(Duration::from_millis(60)).await;

    let (s, ..) = read(c.send(post_form("/c", &format!("csrf_token={old}"))).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "expired");

    let resp = c.send(get("/")).await;
    assert!(
        set_cookie_named(&resp, "__Host-csrf").is_some(),
        "expired cookie must be replaced"
    );
    let (_, fresh, _) = read(resp).await;
    assert_ne!(old, fresh);
    let (s, ..) = read(
        c.send(post_form("/c", &format!("csrf_token={fresh}")))
            .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn per_session_does_not_resend_the_cookie_while_the_token_is_still_good() {
    let mut c = Client::new(stack!(naive_form(RegenerateToken::PerSession), store()));
    let first = c.send(get("/")).await;
    assert!(set_cookie_named(&first, "csrf").is_some());
    let second = c.send(get("/")).await;
    assert!(
        set_cookie_named(&second, "csrf").is_none(),
        "already have a usable token"
    );
}

#[tokio::test]
async fn per_use_sets_a_fresh_cookie_after_a_successful_post() {
    let mut c = Client::new(stack!(naive_form(RegenerateToken::PerUse), store()));
    let (_, t1, _) = read(c.send(get("/")).await).await;
    let resp = c.send(post_form("/c", &format!("csrf_token={t1}"))).await;
    let sc = set_cookie_named(&resp, "csrf").expect("rotated cookie");
    let (status, t2, _) = read(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(t1, t2);
    assert_eq!(parse_set_cookie(&sc).unwrap().1, t2);
}

#[tokio::test]
async fn per_request_sets_a_fresh_cookie_on_every_get() {
    let mut c = Client::new(stack!(naive_form(RegenerateToken::PerRequest), store()));
    let (_, t1, _) = read(c.send(get("/")).await).await;
    let (_, t2, _) = read(c.send(get("/")).await).await;
    assert_ne!(t1, t2);
}

#[tokio::test]
async fn safe_methods_are_never_verified() {
    let mut c = Client::new(stack!(naive_form(RegenerateToken::PerSession), store()));
    for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
        let req = Request::builder()
            .method(m.clone())
            .uri("/")
            .body(Body::default())
            .unwrap();
        assert_eq!(c.raw(req).await.status(), StatusCode::OK, "{m}");
    }
    for m in [Method::PUT, Method::PATCH, Method::DELETE, Method::POST] {
        let req = Request::builder()
            .method(m.clone())
            .uri("/")
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(Body::default())
            .unwrap();
        assert_eq!(
            c.raw(req).await.status(),
            StatusCode::FORBIDDEN,
            "{m} must be verified"
        );
    }
}

#[tokio::test]
async fn direct_config_path_with_phantom_typed_constructors() {
    let layer = CsrfLayer::<DoubleSubmit<Hmac>>::new(
        DoubleSubmitConfig::<Hmac>::new(
            CookieConfig::standard("csrf", CookieSameSite::Lax, true),
            TokenTransport::Header(HeaderName::from_static(HDR)),
            HmacConfig::with_default_ttl(SECRET),
        ),
        RegenerateToken::PerSession,
        OriginPolicy::Skip,
    );
    let mut c = Client::new(stack!(layer, store()));
    let (_, token, _) = read(c.send(get("/")).await).await;
    let mut req = post_json("/api", "{}");
    req.headers_mut()
        .insert(HeaderName::from_static(HDR), token.parse().unwrap());
    assert_eq!(c.send(req).await.status(), StatusCode::OK);
}
