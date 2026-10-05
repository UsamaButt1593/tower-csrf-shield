#[macro_use]
mod common;

use std::time::Duration;

use common::*;
use http::header::COOKIE;
use http::{Request, StatusCode};
use tower_csrf_shield::hybrid::{HybridConfig, HybridSessionConfig};
use tower_csrf_shield::{
    CookieConfig, CookieSameSite, CsrfLayer, CsrfLayerBuilder, HmacConfig, HmacOnlyStage, Hybrid,
    OriginPolicy, RegenerateToken, SessionStage,
};
use tower_sessions_memory_store::MemoryStore;

fn cookie() -> CookieConfig<tower_csrf_shield::HostPrefixed> {
    CookieConfig::host_prefixed("csrf", CookieSameSite::Lax)
}

fn hmac_only() -> CsrfLayer<Hybrid<HmacOnlyStage>> {
    CsrfLayerBuilder::new()
        .hybrid()
        .cookie(cookie())
        .form_field("csrf_token")
        .hmac_only(HmacConfig::new(SECRET, Duration::from_secs(3600)))
        .regenerate_token(RegenerateToken::PerSession)
        .skip_origin_check()
        .build()
}

fn session_plain(policy: RegenerateToken) -> CsrfLayer<Hybrid<SessionStage>> {
    CsrfLayerBuilder::new()
        .hybrid()
        .cookie(cookie())
        .form_field("csrf_token")
        .session("csrf")
        .done()
        .regenerate_token(policy)
        .skip_origin_check()
        .build()
}

fn session_prechecked(policy: RegenerateToken) -> CsrfLayer<Hybrid<SessionStage>> {
    CsrfLayerBuilder::new()
        .hybrid()
        .cookie(cookie())
        .form_field("csrf_token")
        .session("csrf")
        .with_hmac_precheck(HmacConfig::new(SECRET, Duration::from_secs(3600)))
        .done()
        .regenerate_token(policy)
        .skip_origin_check()
        .build()
}

fn forged(cookie_header: &str, field_value: &str) -> Request<Body> {
    let mut r = post_form("/change", &format!("csrf_token={field_value}"));
    r.headers_mut()
        .insert(COOKIE, cookie_header.parse().unwrap());
    r
}

// ---------------------------------------------------------------- HMAC-only

#[tokio::test]
async fn hmac_only_cookie_is_http_only_and_flow_passes() {
    let mut c = Client::new(stack!(hmac_only(), MemoryStore::default()));
    let resp = c.send(get("/form")).await;
    let sc = set_cookie_named(&resp, "__Host-csrf").expect("cookie");
    assert!(
        sc.contains("HttpOnly"),
        "hybrid cookie must always be HttpOnly: {sc}"
    );
    assert!(
        sc.contains("Secure") && sc.contains("Path=/") && !sc.contains("Domain"),
        "{sc}"
    );
    let (_, token, _) = read(resp).await;

    let form = format!("x=1&csrf_token={token}");
    let (status, _, echoed) = read(c.send(post_form("/c", &form)).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(echoed, form);
}

#[tokio::test]
async fn hmac_only_uses_no_session_at_all() {
    let store = CountingStore::default();
    let mut c = Client::new(stack!(hmac_only(), store.clone()));
    let (_, token, _) = read(c.send(get("/form")).await).await;
    let (s, ..) = read(
        c.send(post_form("/c", &format!("csrf_token={token}")))
            .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(store.loads(), 0);
    assert_eq!(
        store.saves.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no session should even be created"
    );
}

#[tokio::test]
async fn hmac_only_rejects_planted_unsigned_and_cookie_only_or_field_only_requests() {
    let mut c = Client::new(stack!(hmac_only(), MemoryStore::default()));
    let (_, token, _) = read(c.send(get("/form")).await).await;

    let (s, ..) = read(c.raw(forged("__Host-csrf=evil", "evil")).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "planted unsigned pair");

    let (s, ..) = read(c.raw(post_form("/c", &format!("csrf_token={token}"))).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "field only, no cookie");

    let (s, ..) = read(
        c.raw(forged(&format!("__Host-csrf={token}"), "other"))
            .await,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "cookie and field disagree");
}

// ------------------------------------------------- session-backed, no precheck

#[tokio::test]
async fn session_stage_sets_both_the_session_cookie_and_the_csrf_cookie() {
    let mut c = Client::new(stack!(
        session_plain(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let resp = c.send(get("/form")).await;
    let names: Vec<_> = set_cookies(&resp)
        .iter()
        .filter_map(|s| parse_set_cookie(s))
        .map(|(k, _)| k)
        .collect();
    assert!(
        names.contains(&"id".to_string()),
        "session layer's cookie must survive: {names:?}"
    );
    assert!(names.contains(&"__Host-csrf".to_string()), "{names:?}");
}

#[tokio::test]
async fn session_stage_legit_flow_passes() {
    let mut c = Client::new(stack!(
        session_plain(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let (_, token, _) = read(c.send(get("/form")).await).await;
    let (s, ..) = read(
        c.send(post_form("/c", &format!("csrf_token={token}")))
            .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn session_stage_rejects_a_matching_pair_that_is_not_the_sessions_token() {
    // Stage 1 (cookie == field) passes; stage 2 (== session's token) must not.
    let mut c = Client::new(stack!(
        session_plain(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let _ = c.send(get("/form")).await;
    let session_cookie = format!("id={}; __Host-csrf=attackers-choice", c.jar["id"]);
    let (s, ..) = read(c.raw(forged(&session_cookie, "attackers-choice")).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_stage_per_use_rotates_session_and_cookie_together() {
    let mut c = Client::new(stack!(
        session_plain(RegenerateToken::PerUse),
        MemoryStore::default()
    ));
    let (_, t1, _) = read(c.send(get("/form")).await).await;
    let resp = c.send(post_form("/c", &format!("csrf_token={t1}"))).await;
    let rotated = set_cookie_named(&resp, "__Host-csrf").expect("rotated cookie");
    let (s, t2, _) = read(resp).await;
    assert_eq!(s, StatusCode::OK);
    assert_ne!(t1, t2);
    assert_eq!(parse_set_cookie(&rotated).unwrap().1, t2);
    // Old token is dead, new one works.
    let stale = format!("id={}; __Host-csrf={t1}", c.jar["id"]);
    let (s, ..) = read(c.raw(forged(&stale, &t1)).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, ..) = read(c.send(post_form("/c", &format!("csrf_token={t2}"))).await).await;
    assert_eq!(s, StatusCode::OK);
}

// --------------------------------- the HMAC-before-session-resolution guarantee

#[tokio::test]
async fn precheck_failure_never_touches_the_session_store() {
    let store = CountingStore::default();
    let mut c = Client::new(stack!(
        session_prechecked(RegenerateToken::PerSession),
        store.clone()
    ));
    let (_, _token, _) = read(c.send(get("/form")).await).await;
    let session_id = c.jar["id"].clone();
    store.reset();

    // A perfectly good session cookie, with an unsigned (garbage) token pair.
    let cookie = format!("id={session_id}; __Host-csrf=garbage");
    let (s, ..) = read(c.raw(forged(&cookie, "garbage")).await).await;

    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(
        store.loads(),
        0,
        "a failed HMAC pre-check must not cost a session-store load"
    );
    assert_eq!(store.saves.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn precheck_failure_for_wrong_key_or_malformed_also_skips_the_store() {
    let store = CountingStore::default();
    let mut c = Client::new(stack!(
        session_prechecked(RegenerateToken::PerSession),
        store.clone()
    ));
    let _ = c.send(get("/form")).await;
    let sid = c.jar["id"].clone();

    // Validly formed and signed, but with a different secret.
    let foreign = CsrfLayerBuilder::new()
        .hybrid()
        .cookie(cookie())
        .form_field("csrf_token")
        .hmac_only(HmacConfig::new(
            b"some-other-secret-of-sufficient-length!",
            Duration::from_secs(3600),
        ))
        .regenerate_token(RegenerateToken::PerSession)
        .skip_origin_check()
        .build();
    let mut f = Client::new(stack!(foreign, MemoryStore::default()));
    let (_, foreign_token, _) = read(f.send(get("/")).await).await;

    store.reset();
    for (label, token) in [
        ("signed with a foreign key", foreign_token.as_str()),
        ("malformed (two parts)", "a.b"),
        ("malformed (no dots)", "garbage"),
        ("malformed (bad base64 signature)", "abc.123.!!!"),
    ] {
        let cookie = format!("id={sid}; __Host-csrf={token}");
        let (s, ..) = read(c.raw(forged(&cookie, token)).await).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(store.loads(), 0, "{label}: store must not be consulted");
    }
}

#[tokio::test]
async fn an_expired_token_fails_the_precheck_and_skips_the_store() {
    // TTL is the *verifier's* setting (the token only carries its issue
    // time), so expiry is tested with a short-TTL layer under test.
    let store = CountingStore::default();
    let layer = CsrfLayerBuilder::new()
        .hybrid()
        .cookie(cookie())
        .form_field("csrf_token")
        .session("csrf")
        .with_hmac_precheck(HmacConfig::new(SECRET, Duration::from_millis(30)))
        .done()
        .regenerate_token(RegenerateToken::PerSession)
        .skip_origin_check()
        .build();
    let mut c = Client::new(stack!(layer, store.clone()));
    let (_, token, _) = read(c.send(get("/form")).await).await;
    let sid = c.jar["id"].clone();

    tokio::time::sleep(Duration::from_millis(60)).await;
    store.reset();

    let cookie = format!("id={sid}; __Host-csrf={token}");
    let (s, ..) = read(c.raw(forged(&cookie, &token)).await).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "expired");
    assert_eq!(
        store.loads(),
        0,
        "expiry is decided by the HMAC pre-check, before the session"
    );
}

#[tokio::test]
async fn a_validly_signed_token_that_is_not_the_sessions_reaches_the_store_and_is_rejected_there() {
    // An attacker with their own session obtains a *legitimately signed*
    // token and plants it for the victim. The pre-check passes (it is
    // signed); only the session comparison can catch it — and it does.
    let store = CountingStore::default();
    let mut victim = Client::new(stack!(
        session_prechecked(RegenerateToken::PerSession),
        store.clone()
    ));
    let mut attacker = Client::new(stack!(
        session_prechecked(RegenerateToken::PerSession),
        store.clone()
    ));
    let _ = victim.send(get("/form")).await;
    let (_, attackers_token, _) = read(attacker.send(get("/form")).await).await;
    let victim_sid = victim.jar["id"].clone();
    store.reset();

    let cookie = format!("id={victim_sid}; __Host-csrf={attackers_token}");
    let (s, ..) = read(victim.raw(forged(&cookie, &attackers_token)).await).await;

    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "session comparison is the authority"
    );
    assert!(
        store.loads() >= 1,
        "the pre-check passed, so the session had to be consulted"
    );
}

#[tokio::test]
async fn precheck_pass_then_session_match_succeeds_and_consults_the_store_exactly_once() {
    let store = CountingStore::default();
    let mut c = Client::new(stack!(
        session_prechecked(RegenerateToken::PerSession),
        store.clone()
    ));
    let (_, token, _) = read(c.send(get("/form")).await).await;
    store.reset();
    let (s, ..) = read(
        c.send(post_form("/c", &format!("csrf_token={token}")))
            .await,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        store.loads(),
        1,
        "one load, cached by the Session for the rest of the request"
    );
}

#[tokio::test]
async fn precheck_tokens_are_signed_and_plain_session_tokens_are_not() {
    let mut a = Client::new(stack!(
        session_prechecked(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let (_, signed, _) = read(a.send(get("/")).await).await;
    assert_eq!(signed.split('.').count(), 3);

    let mut b = Client::new(stack!(
        session_plain(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let (_, opaque, _) = read(b.send(get("/")).await).await;
    assert_eq!(opaque.split('.').count(), 1);
}

#[tokio::test]
async fn direct_config_path_for_both_stage_two_variants() {
    let stateless = CsrfLayer::<Hybrid<HmacOnlyStage>>::new(
        HybridConfig::<HmacOnlyStage>::new(
            cookie(),
            "csrf_token",
            HmacConfig::with_default_ttl(SECRET),
        ),
        RegenerateToken::PerSession,
        OriginPolicy::Skip,
    );
    let mut c = Client::new(stack!(stateless, MemoryStore::default()));
    let (_, t, _) = read(c.send(get("/")).await).await;
    assert_eq!(
        c.send(post_form("/c", &format!("csrf_token={t}")))
            .await
            .status(),
        StatusCode::OK
    );

    let sessioned = CsrfLayer::<Hybrid<SessionStage>>::new(
        HybridConfig::<SessionStage>::new(
            cookie(),
            "csrf_token",
            HybridSessionConfig {
                session_key: "csrf".into(),
                hmac_precheck: Some(HmacConfig::with_default_ttl(SECRET)),
            },
        ),
        RegenerateToken::PerSession,
        OriginPolicy::Skip,
    );
    let mut c = Client::new(stack!(sessioned, MemoryStore::default()));
    let (_, t, _) = read(c.send(get("/")).await).await;
    assert_eq!(
        c.send(post_form("/c", &format!("csrf_token={t}")))
            .await
            .status(),
        StatusCode::OK
    );
}
