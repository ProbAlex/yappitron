//! Link previews: the gateway fetches a page on the sender's behalf. A small local web server
//! plays "the internet"; the fetcher under test is allowed to reach localhost only here, while a
//! separate test proves the real (default) fetcher refuses private addresses.
//!
//! Needs `TEST_DATABASE_URL` (see `just test-server`); tests skip with a notice otherwise.

mod common;

use std::net::SocketAddr;

use axum::Router;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use common::*;
use serde_json::{Value, json};
use yap_server::previews::LinkFetcher;

const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 13, 10, 26, 10, 1, 2, 3, 4];

async fn site() -> SocketAddr {
    async fn page() -> impl IntoResponse {
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            r#"<html><head><title>Fallback</title>
               <meta property="og:title" content="A great article">
               <meta property="og:description" content="Worth reading &amp; sharing">
               <meta property="og:image" content="/cover.png">
               <meta property="og:site_name" content="Example Times"></head><body>hi</body></html>"#,
        )
    }
    async fn svg_page() -> impl IntoResponse {
        (
            [(header::CONTENT_TYPE, "text/html")],
            r#"<head><title>Svg page</title><meta property="og:image" content="/pic.svg"></head>"#,
        )
    }
    async fn huge() -> impl IntoResponse {
        (
            [(header::CONTENT_TYPE, "text/html")],
            format!("<head><title>big</title></head>{}", "x".repeat(600_000)),
        )
    }
    let app = Router::new()
        .route("/page", get(page))
        .route("/svg-page", get(svg_page))
        .route("/huge", get(huge))
        .route(
            "/cover.png",
            get(|| async { ([(header::CONTENT_TYPE, "image/png")], PNG) }),
        )
        .route(
            "/pic.svg",
            get(|| async { ([(header::CONTENT_TYPE, "image/svg+xml")], "<svg/>") }),
        )
        .route(
            "/plain",
            get(|| async { ([(header::CONTENT_TYPE, "text/plain")], "just text") }),
        )
        .route("/missing", get(|| async { StatusCode::NOT_FOUND }))
        .route("/redirect", get(|| async { Redirect::temporary("/page") }))
        .route("/loop", get(|| async { Redirect::temporary("/loop") }))
        .route(
            "/ua",
            get(|headers: HeaderMap| async move {
                let ua = headers
                    .get(header::USER_AGENT)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let cookies = headers.contains_key(header::COOKIE)
                    || headers.contains_key(header::AUTHORIZATION);
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    format!("<head><title>ua={ua} leaked={cookies}</title></head>"),
                )
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

async fn preview(h: &Harness, who: &Client, url: &str) -> (StatusCode, Value) {
    who.post(h, "/api/v1/link-preview", json!({ "url": url }))
        .await
}

#[tokio::test]
async fn builds_a_card_with_title_description_site_and_picture() {
    let Some(h) = link_harness(LinkFetcher::allowing_private_addresses()).await else {
        return;
    };
    let alice = h.user("alice").await;
    let addr = site().await;

    let (s, v) = preview(&h, &alice, &format!("http://{addr}/page")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["title"], "A great article");
    assert_eq!(v["description"], "Worth reading & sharing");
    assert_eq!(v["site"], "Example Times");
    assert_eq!(v["image"]["mime"], "image/png");
    assert_eq!(
        B64.decode(v["image"]["data"].as_str().unwrap()).unwrap(),
        PNG
    );

    // Redirects are followed and the final address is reported.
    let (s, v) = preview(&h, &alice, &format!("http://{addr}/redirect")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["url"], format!("http://{addr}/page"));
    assert_eq!(v["title"], "A great article");
}

#[tokio::test]
async fn refuses_what_is_not_a_page_and_never_sends_identifying_headers() {
    let Some(h) = link_harness(LinkFetcher::allowing_private_addresses()).await else {
        return;
    };
    let alice = h.user("alice").await;
    let addr = site().await;

    for (path, why) in [
        ("plain", "not html"),
        ("missing", "404"),
        ("huge", "over the size cap"),
        ("loop", "redirect loop"),
    ] {
        let (s, v) = preview(&h, &alice, &format!("http://{addr}/{path}")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{why}: {v}");
    }
    // SVG pictures are dropped (they can carry scripts) but the card still works.
    let (s, v) = preview(&h, &alice, &format!("http://{addr}/svg-page")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["title"], "Svg page");
    assert!(v["image"].is_null());
    // The fetch carries no cookies or credentials of the user, only a generic agent string.
    let (_, v) = preview(&h, &alice, &format!("http://{addr}/ua")).await;
    let title = v["title"].as_str().unwrap();
    assert!(
        title.contains("leaked=false") && title.contains("YappitronLinkPreview"),
        "{title}"
    );
}

#[tokio::test]
async fn the_real_fetcher_will_not_touch_private_addresses() {
    let Some(h) = link_harness(LinkFetcher::new()).await else {
        return;
    };
    let alice = h.user("alice").await;
    let addr = site().await; // a live server on localhost: reachable, so only the guard stops us

    for url in [
        format!("http://{addr}/page"),
        "http://127.0.0.1/".to_string(),
        "http://localhost/".to_string(),
        "http://192.168.1.54/".to_string(), // the NAS
        "http://10.0.0.1:80/".to_string(),
        "http://169.254.169.254/latest/meta-data/".to_string(),
        "http://[::1]/".to_string(),
        "http://2130706433/".to_string(),
        "file:///etc/passwd".to_string(),
        "https://user:pw@example.com/".to_string(),
        "not a url".to_string(),
    ] {
        let (s, v) = preview(&h, &alice, &url).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{url} must be refused: {v}");
    }
}

#[tokio::test]
async fn needs_a_signed_in_device_and_is_rate_limited() {
    let Some(h) = link_harness(LinkFetcher::new()).await else {
        return;
    };
    let (s, _) = h
        .post(
            "/api/v1/link-preview",
            json!({ "url": "https://example.com/" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let alice = h.user("alice").await;
    let mut limited = false;
    for _ in 0..40 {
        let (s, _) = preview(&h, &alice, "http://127.0.0.1/").await; // refused fast, still counted
        if s == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
    }
    assert!(limited, "30 previews per 10 minutes per account");
}

#[tokio::test]
async fn off_unless_configured() {
    let Some(h) = harness().await else { return };
    let alice = h.user("alice").await;
    let (s, _) = preview(&h, &alice, "https://example.com/").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
