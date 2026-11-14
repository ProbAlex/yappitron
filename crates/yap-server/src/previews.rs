//! Link previews.
//!
//! Messages are end-to-end encrypted, so the server cannot (and must not) scan them for links.
//! Instead the SENDER's app asks the gateway to fetch a page it is about to send, then puts the
//! finished preview card inside the encrypted message. Recipients never contact the linked site.
//!
//! What the server learns: the address the sender asked to preview, at that moment. It does not
//! learn who the message goes to, and it stores and logs nothing. Apps make this opt-in.
//!
//! This is a server fetching addresses chosen by strangers, which is the classic SSRF hole: the
//! fetcher must never reach the server's own network (databases, the NAS, other containers).
//! Defences, all enforced on every connection including redirects:
//! - only `http`/`https`, only ports 80 and 443, no credentials in the address;
//! - names are resolved by our own resolver, which drops every non-public address, and IP
//!   literals are checked directly, so DNS tricks and rebinding cannot reach private addresses;
//! - at most 3 redirects, a short timeout, and hard caps on how much is read.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use base64::Engine as _;
use futures_util::StreamExt;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::Policy;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::chat;
use crate::error::ApiError;
use crate::state::AppState;

type ApiResult<T> = Result<T, ApiError>;

const MAX_HTML_BYTES: usize = 512 * 1024;
const MAX_IMAGE_BYTES: usize = 600 * 1024;
const MAX_URL_LEN: usize = 2048;
const TIMEOUT: Duration = Duration::from_secs(6);

// ---------------------------------------------------------------- address safety

/// True only for addresses on the public internet.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || a == 0
        || (a == 100 && (64..=127).contains(&b)) // carrier-grade NAT
        || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || a >= 240) // reserved
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_public_v4(v4);
    }
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00 // unique local
        || (s[0] & 0xffc0) == 0xfe80 // link-local
        || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation
        || (s[0] == 0x0064 && s[1] == 0xff9b) // NAT64 can embed any IPv4 address
        || (s[0] == 0x2002) // 6to4 embeds an IPv4 address
        || s[0] == 0x0100) // discard prefix
}

/// Resolves names but returns only public addresses (see the module docs).
struct PublicOnly {
    allow_private: bool,
}

impl Resolve for PublicOnly {
    fn resolve(&self, name: Name) -> Resolving {
        let allow = self.allow_private;
        Box::pin(async move {
            let all: Vec<SocketAddr> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            let ok: Vec<SocketAddr> = all
                .into_iter()
                .filter(|a| allow || is_public_ip(a.ip()))
                .collect();
            if ok.is_empty() {
                return Err("address not allowed".into());
            }
            Ok(Box::new(ok.into_iter()) as Addrs)
        })
    }
}

/// Is this URL one we are willing to fetch at all? (Scheme, port, credentials, IP literals.)
fn check_url(url: &Url, allow_private: bool) -> Result<(), &'static str> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err("only http and https links can be previewed");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("links with credentials cannot be previewed");
    }
    let default = if url.scheme() == "https" { 443 } else { 80 };
    if !allow_private
        && url.port().unwrap_or(default) != default
        && !matches!(url.port(), Some(80 | 443))
    {
        return Err("that port cannot be previewed");
    }
    match url.host() {
        None => Err("no host"),
        Some(url::Host::Domain(d)) => {
            let d = d.to_ascii_lowercase();
            if !allow_private
                && (d == "localhost"
                    || d.ends_with(".localhost")
                    || d.ends_with(".local")
                    || d.ends_with(".internal"))
            {
                return Err("that address cannot be previewed");
            }
            Ok(())
        }
        Some(url::Host::Ipv4(ip)) => {
            if allow_private || is_public_v4(ip) {
                Ok(())
            } else {
                Err("that address cannot be previewed")
            }
        }
        Some(url::Host::Ipv6(ip)) => {
            if allow_private || is_public_v6(ip) {
                Ok(())
            } else {
                Err("that address cannot be previewed")
            }
        }
    }
}

// ---------------------------------------------------------------- fetching

#[derive(Clone)]
pub struct LinkFetcher {
    client: reqwest::Client,
    allow_private: bool,
}

#[derive(Debug, PartialEq)]
pub struct Preview {
    pub url: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub site: Option<String>,
    pub image: Option<(String, Vec<u8>)>,
}

impl LinkFetcher {
    pub fn new() -> Self {
        Self::build(false)
    }

    /// For tests only: lets the fetcher reach localhost.
    pub fn allowing_private_addresses() -> Self {
        Self::build(true)
    }

    fn build(allow_private: bool) -> Self {
        let policy = Policy::custom(move |attempt| {
            if attempt.previous().len() >= 3 {
                return attempt.error("too many redirects");
            }
            match check_url(attempt.url(), allow_private) {
                Ok(()) => attempt.follow(),
                Err(e) => attempt.error(e),
            }
        });
        let client = reqwest::Client::builder()
            .dns_resolver(std::sync::Arc::new(PublicOnly { allow_private }))
            .redirect(policy)
            .timeout(TIMEOUT)
            .connect_timeout(Duration::from_secs(4))
            .user_agent("Mozilla/5.0 (compatible; YappitronLinkPreview/1.0)")
            .no_proxy()
            .build()
            .expect("http client");
        Self {
            client,
            allow_private,
        }
    }

    /// Read at most `max` bytes of a response, or fail if it is longer.
    async fn read_capped(resp: reqwest::Response, max: usize) -> Result<Vec<u8>, &'static str> {
        if resp.content_length().is_some_and(|n| n as usize > max) {
            return Err("too large");
        }
        let mut out = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| "could not read the page")?;
            if out.len() + chunk.len() > max {
                return Err("too large");
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    pub async fn fetch(&self, raw: &str) -> Result<Preview, &'static str> {
        if raw.len() > MAX_URL_LEN {
            return Err("that link is too long");
        }
        let url = Url::parse(raw).map_err(|_| "not a valid link")?;
        check_url(&url, self.allow_private)?;

        let resp = self
            .client
            .get(url.clone())
            .header("accept", "text/html,application/xhtml+xml")
            .header("accept-language", "en")
            .send()
            .await
            .map_err(|_| "could not reach that page")?;
        if !resp.status().is_success() {
            return Err("that page did not load");
        }
        let final_url = resp.url().clone();
        let is_html = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("html"));
        if !is_html {
            return Err("that link is not a web page");
        }
        // A page bigger than the cap is refused rather than half-read.
        let body = Self::read_capped(resp, MAX_HTML_BYTES).await.map_err(|e| {
            if e == "too large" {
                "that page is too large"
            } else {
                e
            }
        })?;
        let html = String::from_utf8_lossy(&body);
        let meta = parse_meta(&html);

        let site = meta.site.clone().or_else(|| {
            final_url
                .host_str()
                .map(|h| h.trim_start_matches("www.").to_string())
        });
        let mut preview = Preview {
            url: final_url.to_string(),
            title: meta.title,
            description: meta.description,
            site,
            image: None,
        };
        if preview.title.is_none() && preview.description.is_none() {
            return Err("nothing to preview");
        }
        if let Some(img) = meta.image.and_then(|i| final_url.join(&i).ok()) {
            preview.image = self.fetch_image(&img).await;
        }
        Ok(preview)
    }

    async fn fetch_image(&self, url: &Url) -> Option<(String, Vec<u8>)> {
        check_url(url, self.allow_private).ok()?;
        let resp = self.client.get(url.clone()).send().await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let mime = resp
            .headers()
            .get("content-type")?
            .to_str()
            .ok()?
            .split(';')
            .next()?
            .trim()
            .to_ascii_lowercase();
        // Only formats every client can decode; never SVG (it can carry scripts).
        if !matches!(
            mime.as_str(),
            "image/png" | "image/jpeg" | "image/gif" | "image/webp"
        ) {
            return None;
        }
        let bytes = Self::read_capped(resp, MAX_IMAGE_BYTES).await.ok()?;
        Some((mime, bytes))
    }
}

impl Default for LinkFetcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------- HTML

#[derive(Default, Debug, PartialEq)]
pub struct Meta {
    pub title: Option<String>,
    pub description: Option<String>,
    pub site: Option<String>,
    pub image: Option<String>,
}

fn clean(s: &str, max_chars: usize) -> Option<String> {
    let decoded = decode_entities(s);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    Some(collapsed.chars().take(max_chars).collect())
}

fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let name = &rest[1..end];
        let ch = match name {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            "nbsp" => Some(' '),
            _ => name
                .strip_prefix('#')
                .and_then(|n| {
                    if let Some(h) = n.strip_prefix(['x', 'X']) {
                        u32::from_str_radix(h, 16).ok()
                    } else {
                        n.parse().ok()
                    }
                })
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Pull the Open Graph / Twitter / standard tags out of a page. Hand-rolled (no HTML engine):
/// it only needs `<meta>` and `<title>`, and anything it cannot make sense of is ignored.
pub fn parse_meta(html: &str) -> Meta {
    let lower = html.to_ascii_lowercase();
    // Only look at the head, where these tags live.
    let end = lower.find("</head").unwrap_or(lower.len());
    let (head, head_lower) = (&html[..end], &lower[..end]);

    let (mut og_title, mut tw_title, mut og_desc, mut tw_desc, mut std_desc) =
        (None, None, None, None, None);
    let (mut og_image, mut tw_image, mut site) = (None, None, None);

    let mut at = 0;
    while let Some(i) = head_lower[at..].find("<meta") {
        let start = at + i;
        let Some(len) = tag_len(&head[start..]) else {
            break;
        };
        let tag = &head[start..start + len];
        at = start + len;
        let (Some(content), name) = (
            attr(tag, "content"),
            attr(tag, "property").or_else(|| attr(tag, "name")),
        ) else {
            continue;
        };
        let Some(name) = name else { continue };
        match name.to_ascii_lowercase().as_str() {
            "og:title" => og_title = og_title.or(clean(&content, 200)),
            "twitter:title" => tw_title = tw_title.or(clean(&content, 200)),
            "og:description" => og_desc = og_desc.or(clean(&content, 300)),
            "twitter:description" => tw_desc = tw_desc.or(clean(&content, 300)),
            "description" => std_desc = std_desc.or(clean(&content, 300)),
            "og:image" | "og:image:url" | "og:image:secure_url" => {
                og_image = og_image.or(Some(content))
            }
            "twitter:image" | "twitter:image:src" => tw_image = tw_image.or(Some(content)),
            "og:site_name" => site = site.or(clean(&content, 80)),
            _ => {}
        }
    }

    let page_title = head_lower.find("<title").and_then(|i| {
        let open_end = head_lower[i..].find('>')? + i + 1;
        let close = head_lower[open_end..].find("</title")? + open_end;
        clean(&head[open_end..close], 200)
    });

    Meta {
        title: og_title.or(tw_title).or(page_title),
        description: og_desc.or(tw_desc).or(std_desc),
        site,
        image: og_image.or(tw_image),
    }
}

/// Length of the tag at the start of `s` (up to its closing `>`), skipping any `>` that sits
/// inside a quoted attribute value, which is legal: `content="a > b"`.
fn tag_len(s: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    for (i, c) in s.char_indices() {
        match (quote, c) {
            (None, '>') => return Some(i),
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            _ => {}
        }
    }
    None
}

/// The value of attribute `name` inside one tag's text (quoted or bare).
fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(i) = lower[from..].find(name) {
        let pos = from + i;
        from = pos + name.len();
        let before_ok = pos == 0
            || lower.as_bytes()[pos - 1].is_ascii_whitespace()
            || lower.as_bytes()[pos - 1] == b'"'
            || lower.as_bytes()[pos - 1] == b'\'';
        let rest = tag[from..].trim_start();
        if !before_ok || !rest.starts_with('=') {
            continue;
        }
        let value = rest[1..].trim_start();
        return match value.chars().next()? {
            q @ ('"' | '\'') => {
                let body = &value[1..];
                Some(body[..body.find(q)?].to_string())
            }
            _ => Some(
                value
                    .split(|c: char| c.is_whitespace() || c == '>')
                    .next()?
                    .to_string(),
            ),
        };
    }
    None
}

// ---------------------------------------------------------------- endpoint

#[derive(Deserialize)]
pub struct PreviewRequest {
    url: String,
}

/// `POST /api/v1/link-preview` `{url}` → `{url, title, description, site, image?: {mime, data}}`.
pub async fn link_preview(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(b): Json<PreviewRequest>,
) -> ApiResult<Json<Value>> {
    let me = chat::caller(&st, &headers).await?;
    let fetcher = st.links.as_deref().ok_or(ApiError::NotFound(
        "link previews are not enabled on this server",
    ))?;
    if !st.limiter.allow(
        &format!("preview:{}", me.account),
        30,
        Duration::from_secs(600),
    ) {
        return Err(ApiError::TooManyRequests);
    }
    let p = fetcher.fetch(&b.url).await.map_err(ApiError::BadRequest)?;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    Ok(Json(json!({
        "url": p.url,
        "title": p.title,
        "description": p.description,
        "site": p.site,
        "image": p.image.map(|(mime, data)| json!({ "mime": mime, "data": b64.encode(data) })),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_addresses_pass() {
        for ok in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
        ] {
            assert!(is_public_ip(ok.parse().unwrap()), "{ok} should be public");
        }
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.54",
            "169.254.169.254",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "100.64.0.1",
            "198.18.0.1",
            "240.0.0.1",
            "192.0.2.1",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "fd12:3456::1",
            "ff02::1",
            "::ffff:192.168.1.1",
            "::ffff:127.0.0.1",
            "64:ff9b::7f00:1",
            "2002:7f00:1::",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(bad.parse().unwrap()), "{bad} must be refused");
        }
    }

    #[test]
    fn urls_are_screened_before_any_request() {
        let ok = |u: &str| check_url(&Url::parse(u).unwrap(), false);
        assert!(ok("https://example.com/a?b=1").is_ok());
        assert!(ok("http://example.com:80/").is_ok());
        assert!(ok("https://example.com:443/").is_ok());
        for bad in [
            "ftp://example.com/",
            "file:///etc/passwd",
            "https://user:pw@example.com/",
            "https://example.com:8443/",
            "http://example.com:22/",
            "http://localhost/",
            "http://foo.localhost/",
            "http://printer.local/",
            "http://db.internal/",
            "http://127.0.0.1/",
            "http://192.168.1.54/",
            "http://[::1]/",
            "http://2130706433/",   // 127.0.0.1 written as one number
            "http://0x7f.0.0.1/",   // hex octet
            "http://017700000001/", // octal
            "http://[::ffff:10.0.0.1]/",
            "http://169.254.169.254/latest/meta-data/",
        ] {
            assert!(ok(bad).is_err(), "{bad} must be refused");
        }
    }

    #[test]
    fn reads_open_graph_twitter_and_plain_tags() {
        let html = r#"<!doctype html><html><head>
            <title>Fallback &amp; title</title>
            <meta name="description" content="plain description">
            <meta property="og:title" content="The &quot;Real&quot; Title">
            <meta property='og:description' content='Open  Graph
               description &#8212; with a dash'>
            <meta property="og:image" content="/img/cover.png">
            <meta property="og:site_name" content="Example News">
            <META NAME="twitter:title" CONTENT="ignored, og wins">
            </head><body><meta property="og:title" content="body tags are ignored"></body></html>"#;
        let m = parse_meta(html);
        assert_eq!(m.title.as_deref(), Some("The \"Real\" Title"));
        assert_eq!(
            m.description.as_deref(),
            Some("Open Graph description \u{2014} with a dash")
        );
        assert_eq!(m.image.as_deref(), Some("/img/cover.png"));
        assert_eq!(m.site.as_deref(), Some("Example News"));
    }

    #[test]
    fn a_greater_than_sign_inside_a_quoted_value_does_not_end_the_tag() {
        let m = parse_meta(
            r#"<head><title>x</title><meta property="og:title" content="A <b>great</b> read > ok"><meta property="og:description" content='5 > 3'>"#,
        );
        assert_eq!(m.title.as_deref(), Some("A <b>great</b> read > ok"));
        assert_eq!(m.description.as_deref(), Some("5 > 3"));
        // An unterminated quote swallows the rest instead of looping or panicking.
        let _ = parse_meta(
            r#"<head><meta property="og:title" content="never closed > <title>t</title>"#,
        );
    }

    #[test]
    fn falls_back_to_the_title_tag_and_survives_junk() {
        let m = parse_meta("<html><head><title>  Just   a title </title></head>");
        assert_eq!(m.title.as_deref(), Some("Just a title"));
        assert_eq!(m.description, None);
        // Broken and hostile markup must not panic or loop.
        for junk in [
            "",
            "<",
            "<meta",
            "<meta content=",
            "<meta content=\"",
            "<title",
            "<head><title>x",
            "&",
            "&#xZZ;&#99999999999;",
            "<meta name=description content=>",
        ] {
            let _ = parse_meta(junk);
        }
    }

    #[test]
    fn long_text_is_trimmed_and_markup_in_text_is_inert() {
        let long = "a".repeat(1000);
        let m = parse_meta(&format!(
            r#"<head><meta property="og:description" content="{long}"><meta property="og:title" content="&lt;script&gt;alert(1)&lt;/script&gt;">"#
        ));
        assert_eq!(m.description.unwrap().chars().count(), 300);
        // It stays text; clients render it as text, never as markup.
        assert_eq!(m.title.as_deref(), Some("<script>alert(1)</script>"));
    }
}
