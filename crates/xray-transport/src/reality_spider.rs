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
//! padding, delays, response bodies, remembered paths, the lifetime of the
//! connection and the crawls the process runs at once all have limits (see
//! the constants below).

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Duration,
};

use async_compression::tokio::bufread::GzipDecoder;
use bytes::Bytes;
use futures_util::future::join_all;
use rand::Rng;
use regex::bytes::Regex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::{
    memory_class::{memory_class, MemoryClass},
    stream::{apply_masquerade, HeaderMap},
};

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
/// Crawls the process runs at once, by memory class. Go crawls and holds
/// every connection answered with a real certificate. Whoever stands between
/// the client and its server can answer every dial that way, and so can a
/// server the profile no longer matches; without a limit each dial would
/// leave a connection held for [`SPIDER_LIFETIME`] and a response body being
/// read. A connection past the limit is closed instead.
const MAX_CONCURRENT_SPIDERS: usize = 4;
const MAX_CONCURRENT_SPIDERS_CONSTRAINED: usize = 2;

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

/// The crawls running in the process.
static ACTIVE_SPIDERS: LazyLock<Arc<AtomicUsize>> = LazyLock::new(|| Arc::new(AtomicUsize::new(0)));

fn max_concurrent_spiders(class: MemoryClass) -> usize {
    match class {
        MemoryClass::Standard => MAX_CONCURRENT_SPIDERS,
        MemoryClass::Constrained => MAX_CONCURRENT_SPIDERS_CONSTRAINED,
    }
}

/// One crawl's place among those running, given back when it is dropped.
struct SpiderSlot(Arc<AtomicUsize>);

impl SpiderSlot {
    /// A place among `active` while fewer than `limit` are taken.
    fn take(active: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < limit).then_some(taken + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(active)))
    }
}

impl Drop for SpiderSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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
/// Go does before it returns "processed invalid connection". While the
/// process already runs as many crawls as it may, the connection is closed
/// instead of crawled.
pub(crate) async fn spider<S>(stream: S, server_name: &str, spider: &RealitySpider)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    spider_within(
        &ACTIVE_SPIDERS,
        max_concurrent_spiders(memory_class()),
        stream,
        server_name,
        spider,
    )
    .await;
}

/// [`spider`] counting its crawls in `active`, at most `limit` at once.
async fn spider_within<S>(
    active: &Arc<AtomicUsize>,
    limit: usize,
    stream: S,
    server_name: &str,
    spider: &RealitySpider,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    match SpiderSlot::take(active, limit) {
        Some(slot) => {
            tokio::spawn(crawl_bounded(
                stream,
                server_name.to_owned(),
                spider.clone(),
                slot,
            ));
        }
        // Closed as a client without the crawl closes it: nothing is read
        // from it and nothing of it is kept.
        None => drop(stream),
    }
    tokio::time::sleep(spider.delay(8)).await;
}

/// The crawl, for at most [`SPIDER_LIFETIME`]. Its slot is free again once
/// it ends, however it ends.
async fn crawl_bounded<S>(stream: S, server_name: String, spider: RealitySpider, _slot: SpiderSlot)
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

    /// A connection to a peer that never answers: the crawl sends its
    /// preface and first request and then waits.
    fn silent_peer() -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
        tokio::io::duplex(64 * 1024)
    }

    async fn within_five_seconds<T>(what: &str, future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), future)
            .await
            .unwrap_or_else(|_| panic!("{what} did not happen in time"))
    }

    #[tokio::test]
    async fn a_connection_past_the_limit_is_closed_instead_of_crawled() {
        let active = Arc::new(AtomicUsize::new(0));
        let spider = RealitySpider::parse("/");
        let (crawled, mut crawled_peer) = silent_peer();
        spider_within(&active, 1, crawled, "limit.example.com", &spider).await;
        assert_eq!(active.load(Ordering::Acquire), 1);

        let (refused, mut refused_peer) = silent_peer();
        spider_within(&active, 1, refused, "limit.example.com", &spider).await;
        assert_eq!(
            active.load(Ordering::Acquire),
            1,
            "the refused one holds no slot"
        );

        // The refused connection ends without a byte; the crawled one opens
        // HTTP/2.
        let mut byte = [0u8; 1];
        let read =
            within_five_seconds("the refused connection's end", refused_peer.read(&mut byte))
                .await
                .expect("read");
        assert_eq!(read, 0);
        let mut preface = [0u8; 24];
        within_five_seconds("the crawl's preface", crawled_peer.read_exact(&mut preface))
            .await
            .expect("preface");
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        // The slot comes back when the crawl's connection ends, and the next
        // connection is crawled again.
        drop(crawled_peer);
        within_five_seconds("the slot's release", async {
            while active.load(Ordering::Acquire) != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        let (next, mut next_peer) = silent_peer();
        spider_within(&active, 1, next, "limit.example.com", &spider).await;
        assert_eq!(active.load(Ordering::Acquire), 1);
        within_five_seconds(
            "the next crawl's preface",
            next_peer.read_exact(&mut preface),
        )
        .await
        .expect("preface");
    }

    #[tokio::test(start_paused = true)]
    async fn a_crawl_gives_its_slot_back_when_its_lifetime_ends() {
        let active = Arc::new(AtomicUsize::new(0));
        let (stream, _peer) = silent_peer();
        spider_within(
            &active,
            1,
            stream,
            "lifetime.example.com",
            &RealitySpider::parse("/"),
        )
        .await;

        tokio::time::sleep(SPIDER_LIFETIME - Duration::from_secs(1)).await;
        assert_eq!(active.load(Ordering::Acquire), 1);
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn a_constrained_process_runs_fewer_crawls_at_once() {
        assert_eq!(max_concurrent_spiders(MemoryClass::Standard), 4);
        assert_eq!(max_concurrent_spiders(MemoryClass::Constrained), 2);
    }

    #[test]
    fn slots_stop_at_the_limit_and_each_comes_back() {
        let active = Arc::new(AtomicUsize::new(0));
        let mut slots: Vec<_> = (0..3)
            .map(|_| SpiderSlot::take(&active, 3).expect("a free slot"))
            .collect();
        assert!(SpiderSlot::take(&active, 3).is_none());
        assert_eq!(active.load(Ordering::Acquire), 3);

        slots.pop();
        assert_eq!(active.load(Ordering::Acquire), 2);
        slots.push(SpiderSlot::take(&active, 3).expect("the slot given back"));
        assert!(SpiderSlot::take(&active, 3).is_none());
        drop(slots);
        assert_eq!(active.load(Ordering::Acquire), 0);
    }
}
