//! The REALITY "spider": what the client does when the server answers with a
//! real certificate instead of a REALITY one.
//!
//! Xray-core does not abort such a handshake. It finishes TLS (the real
//! certificate already passed ordinary Web PKI verification), crawls the
//! site over HTTP/2 the way a browser would, and only then fails the
//! connection, so a prober or MITM that answers with the real site sees a
//! browser rather than a client that hangs up on it
//! (`transport/internet/reality/reality.go` `UClient`, v26.10.31 lines
//! 207-298). User data is never written to such a connection: the crawl owns
//! the TLS stream and the caller only gets an error.
//!
//! Go leaves the crawl unbounded. Here it is capped: request counts,
//! padding, delays, response bodies, remembered paths and the lifetime of the
//! connection all have limits (see the constants below).

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::Duration,
};

use async_compression::tokio::bufread::GzipDecoder;
use bytes::Bytes;
use futures_util::future::join_all;
use rand::Rng;
use regex::bytes::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::stream::{apply_masquerade, HeaderMap};

/// How long the crawl may hold the connection, idle time included. Go keeps
/// it open until the server closes it.
const SPIDER_LIFETIME: Duration = Duration::from_secs(120);
/// Cap on the `c` (concurrency) and `t` (times) draws. Go has none.
const MAX_SPIDER_REQUESTS: i64 = 32;
/// Cap on the `p` padding cookie length. Go has none.
const MAX_SPIDER_PADDING: i64 = 16 * 1024;
/// Cap on the `i` interval and `r` return delays, in milliseconds.
const MAX_SPIDER_DELAY_MS: i64 = 30_000;
/// Bytes of one (decompressed) response body that are scanned for links.
/// Go reads the whole body with `io.ReadAll`.
const MAX_SPIDER_BODY: usize = 1024 * 1024;
/// Paths remembered per server name. Go's process-wide map grows without
/// limit.
const MAX_SPIDER_PATHS: usize = 256;

/// `golang.org/x/net/http2` Transport defaults: a 4 MiB stream window, a
/// connection window raised by 1 GiB and a 10 MiB header list limit.
const GO_H2_STREAM_WINDOW: u32 = 4 << 20;
const GO_H2_CONNECTION_WINDOW: u32 = (1 << 30) + 65_535;
const GO_H2_MAX_HEADER_LIST_SIZE: u32 = 10 << 20;

/// `href="([/h].*?)"`, `reality.go` line 304.
static HREF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"href="([/h].*?)""#).expect("static href pattern"));

/// Paths learned per server name, shared by every connection in the process
/// like Go's package-level `maps`.
static SPIDER_PATHS: LazyLock<Mutex<HashMap<String, Vec<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `spiderX` split the way Xray-core's config loader splits it
/// (`infra/conf/transport_security.go` lines 214-242): the `p`, `c`, `t`,
/// `i` and `r` query parameters become `SpiderY` and are removed from the
/// crawl path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RealitySpider {
    path: String,
    /// `[padding, concurrency, times, interval, return]` as from-to pairs.
    y: [i64; 10],
}

impl RealitySpider {
    pub(crate) fn parse(spider_x: &str) -> Self {
        let spider_x = if spider_x.starts_with('/') {
            spider_x
        } else {
            // Go rejects a non-empty value without a leading slash at load
            // time and replaces an empty one with "/".
            "/"
        };
        let (path, query) = spider_x.split_once('?').unwrap_or((spider_x, ""));
        let mut y = [0; 10];
        let mut kept = Vec::new();
        let mut seen = [false; 5];
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            let Some(slot) = ["p", "c", "t", "i", "r"]
                .iter()
                .position(|name| *name == key)
            else {
                kept.push((key, pair));
                continue;
            };
            // `url.Values.Get` returns the first value; later ones are dropped
            // together with it by `q.Del`.
            if std::mem::replace(&mut seen[slot], true) || value.is_empty() {
                continue;
            }
            let mut bounds = value.split('-');
            let from = parse_go_int(bounds.next().unwrap_or_default());
            let to = bounds.next().map_or(from, parse_go_int);
            y[slot * 2] = from;
            y[slot * 2 + 1] = to;
        }
        // `url.Values.Encode` sorts by key.
        kept.sort_by_key(|(key, _)| *key);
        let mut path = path.to_owned();
        for (index, (_, pair)) in kept.iter().enumerate() {
            path.push(if index == 0 { '?' } else { '&' });
            path.push_str(pair);
        }
        Self { path, y }
    }

    fn draw(&self, index: usize, max: i64) -> i64 {
        rand_between(self.y[index], self.y[index + 1]).clamp(0, max)
    }

    fn delay(&self, index: usize) -> Duration {
        Duration::from_millis(self.draw(index, MAX_SPIDER_DELAY_MS) as u64)
    }
}

/// `strconv.ParseInt(s, 10, 64)` with the error ignored, as Go does.
fn parse_go_int(value: &str) -> i64 {
    value.parse().unwrap_or(0)
}

/// `crypto.RandBetween`: a value in `[from, to)`, or `from` when the range
/// holds fewer than two values (`common/crypto/crypto.go` lines 12-21).
fn rand_between(from: i64, to: i64) -> i64 {
    let (from, to) = if from > to { (to, from) } else { (from, to) };
    if to.saturating_sub(from) <= 1 {
        return from;
    }
    rand::thread_rng().gen_range(from..to)
}

/// Starts the crawl in the background and waits the configured `r` delay, as
/// Go does before it returns "processed invalid connection".
pub(crate) async fn spider<S>(stream: S, server_name: &str, spider: &RealitySpider)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    tokio::spawn(crawl_bounded(
        stream,
        server_name.to_owned(),
        spider.clone(),
    ));
    tokio::time::sleep(spider.delay(8)).await;
}

async fn crawl_bounded<S>(stream: S, server_name: String, spider: RealitySpider)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let _ = tokio::time::timeout(SPIDER_LIFETIME, crawl(stream, server_name, spider)).await;
}

async fn crawl<S>(stream: S, server_name: String, spider: RealitySpider)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // Go hands the established TLS connection to an `http2.Transport`
    // through `DialTLSContext`, which skips the ALPN check: HTTP/2 is spoken
    // whatever the server negotiated.
    let mut builder = h2::client::Builder::new();
    builder
        .enable_push(false)
        .initial_window_size(GO_H2_STREAM_WINDOW)
        .initial_connection_window_size(GO_H2_CONNECTION_WINDOW)
        .max_header_list_size(GO_H2_MAX_HEADER_LIST_SIZE);
    let Ok((send_request, connection)) = builder.handshake::<_, Bytes>(stream).await else {
        return;
    };
    // Holding a handle keeps the connection open once the crawl is done, as
    // Go's "Do not close the connection" does, until the lifetime ends.
    let _keep_open = send_request.clone();
    let mut connection = std::pin::pin!(connection);
    let prefix = format!("https://{server_name}");
    let first_path = {
        let mut maps = lock_paths();
        let paths = maps
            .entry(server_name.clone())
            .or_insert_with(|| vec![spider.path.clone()]);
        pick_path(paths)
    };
    let crawler = Crawler {
        send_request,
        server_name,
        first_url: format!("{prefix}{first_path}"),
        prefix,
        spider,
    };
    let work = async {
        crawler.get(Some(&first_path)).await;
        let concurrency = crawler.spider.draw(2, MAX_SPIDER_REQUESTS);
        join_all((0..concurrency).map(|_| crawler.get(None))).await;
    };
    tokio::select! {
        _ = &mut connection => return,
        () = work => {}
    }
    let _ = connection.await;
}

struct Crawler {
    send_request: h2::client::SendRequest<Bytes>,
    server_name: String,
    prefix: String,
    first_url: String,
    spider: RealitySpider,
}

impl Crawler {
    /// Go's `get(first)` closure, `reality.go` lines 233-289.
    async fn get(&self, first_path: Option<&str>) {
        let first = first_path.is_some();
        let mut path = match first_path {
            Some(path) => path.to_owned(),
            None => self.pick(),
        };
        let mut headers = HeaderMap::new();
        apply_masquerade(&mut headers, "nav");
        let mut cookies = Vec::new();
        let times = if first {
            1
        } else {
            self.spider.draw(4, MAX_SPIDER_REQUESTS)
        };
        for j in 0..times {
            if !first && j == 0 {
                headers.set("Referer", &self.first_url);
            }
            // `req.AddCookie` on a reused request: every round adds one more
            // padding cookie, and Go's HTTP/2 encoder sends each as its own
            // `cookie` field.
            let padding = self.spider.draw(0, MAX_SPIDER_PADDING) as usize;
            cookies.push(format!("padding={}", "0".repeat(padding)));
            let url = format!("{}{path}", self.prefix);
            let Some(body) = self.fetch(&url, &headers, &cookies).await else {
                break;
            };
            headers.set("Referer", &url);
            path = with_path(&path, &self.learn(&body));
            if !first {
                tokio::time::sleep(self.spider.delay(6)).await;
            }
        }
    }

    async fn fetch(&self, url: &str, headers: &HeaderMap, cookies: &[String]) -> Option<Vec<u8>> {
        let mut request = http::Request::get(url);
        for (name, value) in headers.iter() {
            request = request.header(name, value);
        }
        for cookie in cookies {
            request = request.header(http::header::COOKIE, cookie.as_str());
        }
        // Go's HTTP/2 transport asks for gzip and inflates the reply itself.
        let request = request
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .body(())
            .ok()?;
        let mut send_request = self.send_request.clone().ready().await.ok()?;
        let (response, _) = send_request.send_request(request, true).ok()?;
        let response = response.await.ok()?;
        let gzip = response
            .headers()
            .get(http::header::CONTENT_ENCODING)
            .is_some_and(|encoding| encoding.as_bytes().eq_ignore_ascii_case(b"gzip"));
        let mut body = response.into_body();
        let mut raw = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.ok()?;
            let _ = body.flow_control().release_capacity(chunk.len());
            let room = MAX_SPIDER_BODY.saturating_sub(raw.len());
            raw.extend_from_slice(&chunk[..chunk.len().min(room)]);
            if raw.len() >= MAX_SPIDER_BODY {
                break;
            }
        }
        if !gzip {
            return Some(raw);
        }
        let mut inflated = Vec::new();
        let _ = GzipDecoder::new(raw.as_slice())
            .take(MAX_SPIDER_BODY as u64)
            .read_to_end(&mut inflated)
            .await;
        Some(inflated)
    }

    /// Records the links of one page and draws the next path,
    /// `reality.go` lines 271-278.
    fn learn(&self, body: &[u8]) -> String {
        let mut maps = lock_paths();
        let paths = maps.entry(self.server_name.clone()).or_default();
        for capture in HREF.captures_iter(body) {
            let link = &capture[1];
            let link = link.strip_prefix(self.prefix.as_bytes()).unwrap_or(link);
            if link.contains(&b'.') || paths.len() >= MAX_SPIDER_PATHS {
                continue;
            }
            let Ok(link) = std::str::from_utf8(link) else {
                continue;
            };
            if !paths.iter().any(|known| known == link) {
                paths.push(link.to_owned());
            }
        }
        pick_path(paths)
    }

    fn pick(&self) -> String {
        let mut maps = lock_paths();
        pick_path(maps.entry(self.server_name.clone()).or_default())
    }
}

fn lock_paths() -> std::sync::MutexGuard<'static, HashMap<String, Vec<String>>> {
    SPIDER_PATHS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// `getPathLocked`: one remembered path at random, or "/".
fn pick_path(paths: &[String]) -> String {
    if paths.is_empty() {
        return "/".to_owned();
    }
    paths[rand::thread_rng().gen_range(0..paths.len())].clone()
}

/// `req.URL.Path = next`: the path changes and the query of the current
/// request stays. The learned link is a raw path, so it goes out the way
/// `url.URL.String` writes one: escaped as `EscapedPath` does (`?`, `%`,
/// spaces and the like become `%XX`) and given a leading `/` if it lacks one.
fn with_path(current: &str, next: &str) -> String {
    let mut path = String::with_capacity(next.len() + 1);
    if !next.is_empty() && !next.starts_with('/') {
        path.push('/');
    }
    for byte in next.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.~$&+,/:;=@".contains(&byte) {
            path.push(char::from(byte));
        } else {
            path.push_str(&format!("%{byte:02X}"));
        }
    }
    match current.split_once('?') {
        Some((_, query)) => format!("{path}?{query}"),
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spider_x_query_becomes_spider_y_like_xray_config() {
        let spider = RealitySpider::parse("/index?z=1&p=10-20&c=2&t=3-4&i=5-6&r=7&a=b&p=99");

        assert_eq!(spider.path, "/index?a=b&z=1");
        assert_eq!(spider.y, [10, 20, 2, 2, 3, 4, 5, 6, 7, 7]);
    }

    #[test]
    fn spider_x_defaults_to_root_without_leading_slash() {
        assert_eq!(RealitySpider::parse("").path, "/");
        assert_eq!(RealitySpider::parse("index").path, "/");
        assert_eq!(RealitySpider::parse("/a?c=x").y[2..4], [0, 0]);
    }

    #[test]
    fn rand_between_matches_go_bounds() {
        assert_eq!(rand_between(5, 5), 5);
        assert_eq!(rand_between(5, 6), 5);
        assert_eq!(rand_between(8, 7), 7);
        assert!((7..9).contains(&rand_between(9, 7)));
        for _ in 0..64 {
            assert!((10..20).contains(&rand_between(10, 20)));
        }
    }

    #[test]
    fn next_path_keeps_the_current_query() {
        assert_eq!(with_path("/?a=b", "/next"), "/next?a=b");
        assert_eq!(with_path("/", "/next?x=y"), "/next%3Fx=y");
        assert_eq!(with_path("/", "/a b%20/ü"), "/a%20b%2520/%C3%BC");
        assert_eq!(with_path("/?q", "home"), "/home?q");
    }
}
