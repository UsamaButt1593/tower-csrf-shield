#[macro_use]
mod common;

use common::*;
use http::StatusCode;
use tower_csrf_shield::synchronizer::SynchronizerConfig;
use tower_csrf_shield::{CsrfLayer, CsrfLayerBuilder, OriginPolicy, RegenerateToken, Synchronizer};
use tower_sessions_memory_store::MemoryStore;

fn layer(policy: RegenerateToken) -> CsrfLayer<Synchronizer> {
    CsrfLayerBuilder::new()
        .synchronizer()
        .session_key("csrf")
        .form_field("csrf_token")
        .done()
        .regenerate_token(policy)
        .skip_origin_check()
        .build()
}

#[tokio::test]
async fn get_issues_a_token_and_creates_a_session() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let resp = c.send(get("/form")).await;
    assert!(
        set_cookie_named(&resp, "id").is_some(),
        "session cookie expected"
    );
    // Synchronizer sets no cookie of its own.
    assert_eq!(set_cookies(&resp).len(), 1);
    let (status, token, _) = read(resp).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!token.is_empty());
}

#[tokio::test]
async fn post_with_the_right_token_passes_and_the_body_reaches_the_handler_intact() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let (_, token, _) = read(c.send(get("/form")).await).await;

    let form = format!("email=a%40b.example&csrf_token={token}");
    let (status, _, echoed) = read(c.send(post_form("/change", &form)).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        echoed, form,
        "downstream must see the original body, byte for byte"
    );
}

#[tokio::test]
async fn post_with_missing_or_wrong_token_is_rejected() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let (_, token, _) = read(c.send(get("/form")).await).await;

    let (status, ..) = read(c.send(post_form("/change", "email=x")).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "missing token");

    let (status, ..) = read(
        c.send(post_form("/change", "csrf_token=nope&email=x"))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "wrong token");

    // Sanity: the right one still works afterwards (rejections don't burn it).
    let (status, ..) = read(
        c.send(post_form("/change", &format!("csrf_token={token}")))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_token_from_another_session_is_rejected() {
    let store = MemoryStore::default();
    let mut victim = Client::new(stack!(layer(RegenerateToken::PerSession), store.clone()));
    let mut attacker = Client::new(stack!(layer(RegenerateToken::PerSession), store));
    let (_, attacker_token, _) = read(attacker.send(get("/form")).await).await;
    let _ = victim.send(get("/form")).await;

    // The classic forgery: the attacker's own valid token, the victim's session.
    let (status, ..) = read(
        victim
            .send(post_form(
                "/change",
                &format!("csrf_token={attacker_token}"),
            ))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_post_with_no_session_at_all_is_rejected() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let (status, ..) = read(c.send(post_form("/change", "csrf_token=anything")).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn non_form_bodies_are_rejected_for_form_transport() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let _ = c.send(get("/form")).await;
    let (status, ..) = read(c.send(post_json("/change", r#"{"csrf_token":"x"}"#)).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn per_session_keeps_the_same_token_across_gets_and_posts() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerSession),
        MemoryStore::default()
    ));
    let (_, t1, _) = read(c.send(get("/a")).await).await;
    let (_, t2, _) = read(c.send(get("/b")).await).await;
    assert_eq!(t1, t2);
    let (status, t3, _) = read(c.send(post_form("/c", &format!("csrf_token={t1}"))).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(t1, t3);
}

#[tokio::test]
async fn per_use_rotates_only_after_a_successful_unsafe_request() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerUse),
        MemoryStore::default()
    ));
    let (_, t1, _) = read(c.send(get("/a")).await).await;
    let (_, t1_again, _) = read(c.send(get("/b")).await).await;
    assert_eq!(t1, t1_again, "safe requests must not rotate under PerUse");

    let (status, t2, _) = read(c.send(post_form("/c", &format!("csrf_token={t1}"))).await).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(
        t1, t2,
        "the handler of a successful POST already sees the next token"
    );

    let (status, ..) = read(c.send(post_form("/c", &format!("csrf_token={t1}"))).await).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the spent token must no longer work"
    );
    let (status, ..) = read(c.send(post_form("/c", &format!("csrf_token={t2}"))).await).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_rejected_request_does_not_rotate_under_per_use() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerUse),
        MemoryStore::default()
    ));
    let (_, t1, _) = read(c.send(get("/a")).await).await;
    let (status, ..) = read(c.send(post_form("/c", "csrf_token=wrong")).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, still, _) = read(c.send(get("/a")).await).await;
    assert_eq!(t1, still);
}

#[tokio::test]
async fn per_request_rotates_on_every_request() {
    let mut c = Client::new(stack!(
        layer(RegenerateToken::PerRequest),
        MemoryStore::default()
    ));
    let (_, t1, _) = read(c.send(get("/a")).await).await;
    let (_, t2, _) = read(c.send(get("/b")).await).await;
    assert_ne!(t1, t2);
    let (status, ..) = read(c.send(post_form("/c", &format!("csrf_token={t1}"))).await).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "t1 was superseded by t2");
    let (_, t3, _) = read(c.send(get("/a")).await).await;
    let (status, ..) = read(c.send(post_form("/c", &format!("csrf_token={t3}"))).await).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn missing_session_middleware_is_a_500_not_a_403() {
    let mut c = Client::new(stack_no_session!(layer(RegenerateToken::PerSession)));
    let resp = c.send(get("/form")).await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn direct_config_path_builds_the_same_layer_as_the_builder() {
    let layer = CsrfLayer::<Synchronizer>::new(
        SynchronizerConfig {
            session_key: "csrf".into(),
            form_field: "csrf_token".into(),
        },
        RegenerateToken::PerSession,
        OriginPolicy::Skip,
    );
    let mut c = Client::new(stack!(layer, MemoryStore::default()));
    let (_, token, _) = read(c.send(get("/form")).await).await;
    let (status, ..) = read(
        c.send(post_form("/c", &format!("csrf_token={token}")))
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}
