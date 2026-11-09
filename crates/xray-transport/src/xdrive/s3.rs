//! The `s3` service, as Xray-core v26.10.31's `s3.go` reaches a bucket: keys
//! under `remoteFolder/`, requests signed with AWS Signature Version 4 by
//! hand, path-style or virtual-hosted addressing, ListObjectsV2 with a
//! delimiter and continuation tokens, and up to eight tries with a growing
//! jittered pause, or what `Retry-After` asks, up to eight seconds.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http::Method;
use sha2::{Digest, Sha256};
use tokio::sync::Semaphore;
use xray_proxy::go_url::{self, Encoding};
use zeroize::Zeroizing;

use super::client::{ServiceError, ServiceRequest, ServiceResponse, ServiceUrl};
use super::http_storage::SessionHttp;
use super::storage::{Entry, Storage, StorageError};
use super::xml::{error_code, parse_list_page, ListPage};

/// Xray-core's `driveMaxAttempts`.
pub(crate) const MAX_ATTEMPTS: usize = 8;
/// Xray-core's `driveMaxBackoff`.
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(8);
/// Xray-core's `driveInitialBackoff`.
pub(crate) const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
/// Xray-core's `driveMaxInflight`: requests one session keeps in flight.
pub(crate) const MAX_INFLIGHT: usize = 32;
/// Xray-core's `maxSegmentBytes`: the largest successful answer read.
const MAX_ANSWER: usize = 16 * 1024 * 1024;
/// The largest error answer read.
const MAX_ERROR_ANSWER: usize = 64 << 10;
/// `s3.go`'s object key limit.
const MAX_KEY: usize = 1024;

/// An `s3` service's settings, checked by the configuration as Xray-core's
/// `ValidateS3Config` checks them.
#[derive(Clone, PartialEq, Eq)]
pub struct XdriveS3 {
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub path_style: bool,
    pub remote_folder: String,
    pub access_key: Zeroizing<String>,
    pub secret_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for XdriveS3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdriveS3")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("path_style", &self.path_style)
            .field("remote_folder", &self.remote_folder)
            .finish_non_exhaustive()
    }
}

/// What every session of one bucket shares: where requests go and how they
/// are signed.
#[derive(Debug)]
pub(crate) struct S3Shared {
    secure: bool,
    hostname: String,
    port: u16,
    authority: String,
    /// The escaped path every key follows, ending with `/`.
    base_path: String,
    prefix: String,
    region: String,
    keys: S3Keys,
    pub backoff: Duration,
}

struct S3Keys {
    access: Zeroizing<String>,
    secret: Zeroizing<String>,
    token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for S3Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("S3Keys(<redacted>)")
    }
}

/// `s3Region`.
fn s3_region(region: &str) -> &str {
    if region.is_empty() {
        "us-east-1"
    } else {
        region
    }
}

/// `s3EscapePath`: SigV4's escaping, `%20` for spaces, uppercase escapes,
/// and `/` kept.
pub(crate) fn s3_escape_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl S3Shared {
    /// `newS3Storage`'s addressing: the endpoint's path re-escaped segment by
    /// segment for SigV4, without turning an escaped slash into a separator,
    /// then the bucket in the path or in the host.
    pub(crate) fn new(config: &XdriveS3) -> Result<Self, String> {
        let base = go_url::parse(&config.endpoint).map_err(|error| error.to_string())?;
        let segments: Vec<String> = base
            .escaped_path()
            .split('/')
            .map(|segment| {
                let decoded = go_url::unescape_bytes(segment.as_bytes(), Encoding::PathSegment)
                    .unwrap_or_default();
                s3_escape_path(&String::from_utf8_lossy(&decoded)).replace('/', "%2F")
            })
            .collect();
        let mut base_path = segments.join("/");
        if !base_path.ends_with('/') {
            base_path.push('/');
        }
        let secure = base.scheme == "https";
        let mut hostname = base.hostname().to_owned();
        let mut authority = base.host.clone();
        if config.path_style {
            base_path.push_str(&s3_escape_path(&config.bucket));
            base_path.push('/');
        } else {
            hostname = format!("{}.{}", config.bucket, base.hostname());
            authority = match base.port() {
                "" => hostname.clone(),
                port if hostname.contains(':') => format!("[{hostname}]:{port}"),
                port => format!("{hostname}:{port}"),
            };
        }
        let port = match base.port() {
            "" => {
                if secure {
                    443
                } else {
                    80
                }
            }
            digits => digits
                .parse()
                .map_err(|_| "invalid S3 endpoint port".to_owned())?,
        };
        Ok(Self {
            secure,
            hostname,
            port,
            authority,
            base_path,
            prefix: format!(
                "{}/",
                config
                    .remote_folder
                    .strip_suffix('/')
                    .unwrap_or(&config.remote_folder)
            ),
            region: s3_region(&config.region).to_owned(),
            keys: S3Keys {
                access: config.access_key.clone(),
                secret: config.secret_key.clone(),
                token: config
                    .session_token
                    .clone()
                    .filter(|token| !token.is_empty()),
            },
            backoff: INITIAL_BACKOFF,
        })
    }

    /// `target`: the URL of `key` with `query`, the query encoded with `%20`
    /// for spaces.
    pub(crate) fn url(&self, key: &str, query: &[(&str, &str)]) -> ServiceUrl {
        let mut target = format!("{}{}", self.base_path, s3_escape_path(key));
        let query = go_url::encode_values(query).replace('+', "%20");
        if !query.is_empty() {
            target.push('?');
            target.push_str(&query);
        }
        ServiceUrl {
            secure: self.secure,
            hostname: self.hostname.clone(),
            port: self.port,
            authority: self.authority.clone(),
            target,
        }
    }

    /// `sign`: the SigV4 headers of a request to `url`, as Xray-core writes
    /// them, at `now`.
    pub(crate) fn sign(
        &self,
        method: &Method,
        url: &ServiceUrl,
        content_type: Option<&str>,
        payload_hash: &str,
        now: SystemTime,
    ) -> Vec<(String, String)> {
        let (stamp, date) = amz_date(now);
        let mut headers = vec![
            ("X-Amz-Date".to_owned(), stamp.clone()),
            ("X-Amz-Content-Sha256".to_owned(), payload_hash.to_owned()),
        ];
        let mut canonical_headers = format!(
            "host:{}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{stamp}\n",
            url.authority
        );
        let mut signed = String::from("host;x-amz-content-sha256;x-amz-date");
        if let Some(content_type) = content_type.filter(|value| !value.is_empty()) {
            headers.push(("Content-Type".to_owned(), content_type.to_owned()));
            canonical_headers = format!("content-type:{content_type}\n{canonical_headers}");
            signed = format!("content-type;{signed}");
        }
        if let Some(token) = &self.keys.token {
            headers.push(("X-Amz-Security-Token".to_owned(), token.to_string()));
            let folded: Vec<&str> = token.split_ascii_whitespace().collect();
            canonical_headers.push_str(&format!("x-amz-security-token:{}\n", folded.join(" ")));
            signed.push_str(";x-amz-security-token");
        }
        let (path, query) = match url.target.split_once('?') {
            Some((path, query)) => (path, query),
            None => (url.target.as_str(), ""),
        };
        let canonical = format!(
            "{}\n{path}\n{query}\n{canonical_headers}\n{signed}\n{payload_hash}",
            method.as_str()
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
            hex(&Sha256::digest(canonical.as_bytes()))
        );
        let mut key = hmac(
            format!("AWS4{}", self.keys.secret.as_str()).as_bytes(),
            &date,
        );
        key = hmac(&key, &self.region);
        key = hmac(&key, "s3");
        key = hmac(&key, "aws4_request");
        headers.push((
            "Authorization".to_owned(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={}",
                self.keys.access.as_str(),
                hex(&hmac(&key, &to_sign))
            ),
        ));
        headers
    }

    /// `objectKey`.
    pub(super) fn object_key(&self, name: &str) -> Result<String, StorageError> {
        if !valid_s3_name(name) {
            return Err(StorageError::Failed(
                "invalid relative S3 object name".to_owned(),
            ));
        }
        let key = format!("{}{name}", self.prefix);
        if key.len() > MAX_KEY {
            return Err(StorageError::Failed(
                "S3 object key exceeds 1024 bytes".to_owned(),
            ));
        }
        Ok(key)
    }
}

fn hmac(key: &[u8], value: &str) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
    mac.update(value.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `20060102T150405Z` and `20060102` of `now` in UTC.
fn amz_date(now: SystemTime) -> (String, String) {
    let secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let date = format!("{year:04}{month:02}{day:02}");
    (
        format!(
            "{date}T{:02}{:02}{:02}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        ),
        date,
    )
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Howard Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Xray-core's `validS3Name`.
fn valid_s3_name(name: &str) -> bool {
    !name
        .chars()
        .any(|ch| (ch as u32) < 0x20 || ch == '\u{7f}' || ch == '\\')
        && name
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Xray-core's `retryableStatus`.
pub(crate) fn retryable_status(status: u16) -> bool {
    matches!(status, 429 | 500 | 502 | 503 | 504)
}

/// `jitter`: from half the backoff up to, not including, all of it.
pub(crate) fn jitter(backoff: Duration) -> Duration {
    let half = backoff / 2;
    if half.is_zero() {
        return backoff;
    }
    let nanos = half.as_nanos().min(u128::from(u64::MAX)) as u64;
    half + Duration::from_nanos(rand::random::<u64>() % nanos.max(1))
}

/// What `Retry-After` asks, as Xray-core reads it: whole seconds, or an
/// HTTP date, up to eight seconds either way.
pub(crate) fn retry_after(raw: &str, now: SystemTime) -> Duration {
    if let Ok(seconds) = raw.parse::<i32>() {
        if seconds > 0 {
            return Duration::from_secs(seconds as u64).min(MAX_BACKOFF);
        }
    }
    if let Some(at) = parse_http_date(raw) {
        let until = at.duration_since(now).unwrap_or(Duration::ZERO);
        return until.min(MAX_BACKOFF);
    }
    Duration::ZERO
}

/// Go's `http.ParseTime`: RFC 1123 with `GMT`, RFC 850, or ANSI C asctime.
fn parse_http_date(raw: &str) -> Option<SystemTime> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let month_of = |name: &str| MONTHS.iter().position(|m| *m == name).map(|i| i as u32 + 1);
    let clock = |text: &str| -> Option<(i64, i64, i64)> {
        let mut parts = text.split(':');
        let (h, m, s) = (parts.next()?, parts.next()?, parts.next()?);
        if parts.next().is_some() || h.len() != 2 || m.len() != 2 || s.len() != 2 {
            return None;
        }
        Some((h.parse().ok()?, m.parse().ok()?, s.parse().ok()?))
    };
    let fields: Vec<&str> = raw.split(' ').collect();
    let (year, month, day, time) = match fields.as_slice() {
        // "Mon, 02 Jan 2006 15:04:05 GMT"
        [weekday, day, month, year, time, "GMT"] if weekday.ends_with(',') && day.len() == 2 => (
            year.parse::<i64>().ok()?,
            month_of(month)?,
            day.parse::<u32>().ok()?,
            *time,
        ),
        // "Monday, 02-Jan-06 15:04:05 GMT"
        [weekday, date, time, "GMT"] if weekday.ends_with(',') => {
            let mut parts = date.split('-');
            let (day, month, year) = (parts.next()?, parts.next()?, parts.next()?);
            if day.len() != 2 || year.len() != 2 {
                return None;
            }
            // Go's two-digit years: 69..99 are 1900s, the rest 2000s.
            let year: i64 = year.parse().ok()?;
            let year = if year >= 69 { 1900 + year } else { 2000 + year };
            (year, month_of(month)?, day.parse::<u32>().ok()?, *time)
        }
        // "Mon Jan _2 15:04:05 2006"
        [_, month, rest @ ..] => {
            let rest: Vec<&str> = rest.iter().copied().filter(|f| !f.is_empty()).collect();
            let [day, time, year] = rest.as_slice() else {
                return None;
            };
            (
                year.parse::<i64>().ok()?,
                month_of(month)?,
                day.parse::<u32>().ok()?,
                *time,
            )
        }
        _ => return None,
    };
    let (hour, minute, second) = clock(time)?;
    if !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    let secs = u64::try_from(secs).ok()?;
    Some(std::time::UNIX_EPOCH + Duration::from_secs(secs))
}

/// `s3Missing`.
fn missing(status: u16, payload: &[u8]) -> bool {
    status == 404 && matches!(error_code(payload).as_str(), "NoSuchKey" | "NotFound")
}

/// `s3ResponseError`.
fn response_error(method: &str, status: u16, payload: &[u8]) -> StorageError {
    match error_code(payload).as_str() {
        "" => StorageError::Failed(format!("S3 {method} answered {status}")),
        code => StorageError::Failed(format!("S3 {method} answered {status} ({code:?})")),
    }
}

/// One session's view of a bucket.
#[derive(Debug)]
pub(crate) struct S3Storage {
    shared: Arc<S3Shared>,
    http: SessionHttp,
    inflight: Semaphore,
}

impl S3Storage {
    pub(crate) fn new(shared: Arc<S3Shared>, http: SessionHttp) -> Self {
        Self {
            shared,
            http,
            inflight: Semaphore::new(MAX_INFLIGHT),
        }
    }

    /// `do`: tries again with fresh signatures after a network failure or a
    /// status worth retrying, each try holding an in-flight slot.
    async fn exchange(
        &self,
        method: Method,
        key: &str,
        query: &[(&str, &str)],
        body: Bytes,
    ) -> Result<(u16, Bytes), StorageError> {
        let payload_hash = hex(&Sha256::digest(&body));
        let mut backoff = self.shared.backoff;
        let mut last: Option<StorageError> = None;
        let mut wait_after = Duration::ZERO;
        for attempt in 0..MAX_ATTEMPTS {
            if attempt > 0 {
                let delay = jitter(backoff).max(wait_after);
                tokio::time::sleep(delay.min(MAX_BACKOFF)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
            let permit = self.inflight.acquire().await.map_err(|_| closed())?;
            let outcome = self
                .attempt(&method, key, query, &body, &payload_hash)
                .await;
            drop(permit);
            match outcome {
                Err(error) => {
                    let retry = match &error {
                        Attempt::Failed { error, .. } => error.retryable(),
                        Attempt::Unreadable { .. } => false,
                    };
                    if !retry {
                        return Err(error.into_storage());
                    }
                    last = Some(error.into_storage());
                    wait_after = Duration::ZERO;
                }
                Ok(answer) => {
                    if !retryable_status(answer.status) {
                        return Ok((answer.status, answer.body));
                    }
                    wait_after = answer
                        .retry_after
                        .as_deref()
                        .map(|raw| retry_after(raw, SystemTime::now()))
                        .unwrap_or(Duration::ZERO);
                    last = Some(response_error(method.as_str(), answer.status, &answer.body));
                }
            }
        }
        Err(last.unwrap_or_else(closed))
    }

    async fn attempt(
        &self,
        method: &Method,
        key: &str,
        query: &[(&str, &str)],
        body: &Bytes,
        payload_hash: &str,
    ) -> Result<ServiceResponse, Attempt> {
        let url = self.shared.url(key, query);
        let content_type = (*method == Method::PUT).then_some("application/octet-stream");
        let headers = self
            .shared
            .sign(method, &url, content_type, payload_hash, SystemTime::now());
        let request = ServiceRequest {
            method: method.clone(),
            url,
            headers,
            body: body.clone(),
            max_body: MAX_ANSWER,
        };
        let answer = self
            .http
            .send(&request)
            .await
            .map_err(|error| Attempt::Failed { error })?;
        let limit = if (200..300).contains(&answer.status) {
            MAX_ANSWER
        } else {
            MAX_ERROR_ANSWER
        };
        if answer.body.len() > limit {
            return Err(Attempt::Unreadable {
                message: "S3 response exceeds size limit".to_owned(),
            });
        }
        Ok(answer)
    }

    /// `list`: every page of a listing, its keys checked against `prefix`
    /// before any is used.
    async fn list_pages(
        &self,
        prefix: &str,
        delimiter: &str,
        mut visit: impl FnMut(&ListPage),
    ) -> Result<(), StorageError> {
        let mut seen = HashSet::new();
        let mut token = String::new();
        loop {
            let mut query = vec![("list-type", "2"), ("prefix", prefix), ("max-keys", "1000")];
            if !delimiter.is_empty() {
                query.push(("delimiter", delimiter));
            }
            if !token.is_empty() {
                query.push(("continuation-token", token.as_str()));
            }
            let (status, payload) = self.exchange(Method::GET, "", &query, Bytes::new()).await?;
            if status != 200 {
                return Err(response_error("LIST", status, &payload));
            }
            let page = parse_list_page(&payload)
                .map_err(|_| StorageError::Failed("invalid S3 list response".to_owned()))?;
            if page.keys.iter().any(|key| !key.starts_with(prefix)) {
                return Err(StorageError::Failed(
                    "S3 returned an object outside the requested prefix".to_owned(),
                ));
            }
            if page.prefixes.iter().any(|item| !item.starts_with(prefix)) {
                return Err(StorageError::Failed(
                    "S3 returned a directory outside the requested prefix".to_owned(),
                ));
            }
            if page.is_truncated
                && (page.next_continuation_token.is_empty()
                    || !seen.insert(page.next_continuation_token.clone()))
            {
                return Err(StorageError::Failed(
                    "S3 list pagination did not advance".to_owned(),
                ));
            }
            visit(&page);
            if !page.is_truncated {
                return Ok(());
            }
            token = page.next_continuation_token;
        }
    }

    async fn delete_object(&self, key: &str) -> Result<(), StorageError> {
        let (status, payload) = self
            .exchange(Method::DELETE, key, &[], Bytes::new())
            .await?;
        if status != 204 && status != 200 && !missing(status, &payload) {
            return Err(response_error("DELETE", status, &payload));
        }
        Ok(())
    }
}

enum Attempt {
    Failed { error: ServiceError },
    Unreadable { message: String },
}

impl Attempt {
    fn into_storage(self) -> StorageError {
        match self {
            Self::Failed { error } => StorageError::Failed(format!("S3 request failed > {error}")),
            Self::Unreadable { message } => StorageError::Failed(message),
        }
    }
}

fn closed() -> StorageError {
    StorageError::Failed("the session is closed".to_owned())
}

#[async_trait]
impl Storage for S3Storage {
    async fn put(&self, name: &str, data: Bytes) -> Result<(), StorageError> {
        let key = self.shared.object_key(name)?;
        let (status, payload) = self.exchange(Method::PUT, &key, &[], data).await?;
        if status != 200 {
            return Err(response_error("PUT", status, &payload));
        }
        Ok(())
    }

    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let key = self.shared.object_key(name)?;
        let (status, payload) = self.exchange(Method::GET, &key, &[], Bytes::new()).await?;
        if missing(status, &payload) {
            return Err(StorageError::NotFound);
        }
        if status != 200 {
            return Err(response_error("GET", status, &payload));
        }
        Ok(payload)
    }

    /// The trailing `/` keeps `streams/abc` from deleting `streams/abcd`.
    async fn delete(&self, name: &str) -> Result<(), StorageError> {
        let key = self.shared.object_key(name)?;
        self.delete_object(&key).await?;
        let mut children = Vec::new();
        self.list_pages(&format!("{key}/"), "", |page| {
            children.extend(page.keys.iter().cloned());
        })
        .await?;
        for child in children {
            self.delete_object(&child).await?;
        }
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<Entry>, StorageError> {
        let key = format!("{}/", self.shared.object_key(prefix)?);
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        self.list_pages(&key, "/", |page| {
            for full in page.keys.iter().chain(&page.prefixes) {
                let rest = full.strip_prefix(key.as_str()).unwrap_or(full);
                let name = rest.split('/').next().unwrap_or_default();
                if !name.is_empty() && valid_s3_name(name) && seen.insert(name.to_owned()) {
                    entries.push(Entry::named(name));
                }
            }
        })
        .await?;
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(endpoint: &str, path_style: bool) -> XdriveS3 {
        XdriveS3 {
            endpoint: endpoint.to_owned(),
            region: String::new(),
            bucket: "my-bucket".to_owned(),
            path_style,
            remote_folder: "root/".to_owned(),
            access_key: Zeroizing::new("AKIDEXAMPLE".to_owned()),
            secret_key: Zeroizing::new("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned()),
            session_token: None,
        }
    }

    #[test]
    fn addressing_follows_xray() {
        let shared = S3Shared::new(&config("https://s3.example/a%2Fb/c%20d", true)).unwrap();
        let url = shared.url("root/x y.seg", &[("prefix", "a b"), ("list-type", "2")]);
        assert_eq!(url.authority, "s3.example");
        assert_eq!(
            url.target,
            "/a%2Fb/c%20d/my-bucket/root/x%20y.seg?list-type=2&prefix=a%20b"
        );
        let shared = S3Shared::new(&config("http://s3.example:9000", false)).unwrap();
        let url = shared.url("root/k", &[]);
        assert_eq!(
            (
                url.secure,
                url.hostname.as_str(),
                url.port,
                url.authority.as_str()
            ),
            (
                false,
                "my-bucket.s3.example",
                9000,
                "my-bucket.s3.example:9000"
            )
        );
        assert_eq!(url.target, "/root/k");
        assert_eq!(shared.region, "us-east-1");
        assert_eq!(shared.prefix, "root/");
    }

    #[test]
    fn dates_and_backoff_follow_go() {
        let at = std::time::UNIX_EPOCH + Duration::from_secs(1_440_938_160);
        assert_eq!(
            amz_date(at),
            ("20150830T123600Z".to_owned(), "20150830".to_owned())
        );
        let now = std::time::UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(retry_after("3", now), Duration::from_secs(3));
        assert_eq!(retry_after("30", now), MAX_BACKOFF);
        assert_eq!(retry_after("0", now), Duration::ZERO);
        assert_eq!(
            retry_after("Sun, 06 Nov 1994 08:49:42 GMT", now),
            Duration::from_secs(5)
        );
        assert_eq!(
            retry_after("Sunday, 06-Nov-94 08:49:41 GMT", now),
            Duration::from_secs(4)
        );
        assert_eq!(
            retry_after("Sun Nov  6 08:49:40 1994", now),
            Duration::from_secs(3)
        );
        assert_eq!(
            retry_after("Sun, 06 Nov 1994 08:49:30 GMT", now),
            Duration::ZERO
        );
        assert_eq!(retry_after("soon", now), Duration::ZERO);
        for _ in 0..100 {
            let pause = jitter(Duration::from_millis(200));
            assert!(pause >= Duration::from_millis(100) && pause < Duration::from_millis(200));
        }
    }
}
