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
pub(crate) const MAX_INFLIGHT: usize = super::drive::MAX_INFLIGHT;
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
    if let Some((secs, nanos)) = parse_http_date(raw) {
        // A date before 1970 has passed, as has any before now.
        let at = u64::try_from(secs)
            .ok()
            .and_then(|secs| std::time::UNIX_EPOCH.checked_add(Duration::new(secs, nanos)));
        let until = at
            .and_then(|at| at.duration_since(now).ok())
            .unwrap_or(Duration::ZERO);
        return until.min(MAX_BACKOFF);
    }
    Duration::ZERO
}

/// One piece of a `time.Parse` layout, as far as `http.ParseTime`'s three
/// need them.
#[derive(Clone, Copy)]
enum DatePart {
    /// Text to match as is, where a space takes any run of spaces.
    Text(&'static [u8]),
    /// `Mon` or `Monday`: a day's name, not held against the date.
    Weekday(&'static [&'static str]),
    /// `Jan`.
    Month,
    /// `02`, or with `_2` one digit or two.
    Day { fixed: bool },
    /// `2006`: four digits.
    Year,
    /// `06`: two characters as `atoi` reads them, 69 to 99 in the 1900s.
    ShortYear,
    /// `15`: one digit or two, below 24.
    Hour,
    /// `04`: two digits below 60.
    Minute,
    /// `05`: two digits below 60, and a fraction the layout does not name.
    Second,
    /// `MST`: a zone's abbreviation.
    Zone,
}

const SHORT_DAYS: &[&str] = &["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const LONG_DAYS: &[&str] = &[
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];
const MONTHS: &[&str] = &[
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// `http.TimeFormat`, `time.RFC850` and `time.ANSIC`, in the order
/// `http.ParseTime` tries them.
const HTTP_DATE_LAYOUTS: [&[DatePart]; 3] = {
    use DatePart::*;
    [
        // Mon, 02 Jan 2006 15:04:05 GMT
        &[
            Weekday(SHORT_DAYS),
            Text(b", "),
            Day { fixed: true },
            Text(b" "),
            Month,
            Text(b" "),
            Year,
            Text(b" "),
            Hour,
            Text(b":"),
            Minute,
            Text(b":"),
            Second,
            Text(b" GMT"),
        ],
        // Monday, 02-Jan-06 15:04:05 MST
        &[
            Weekday(LONG_DAYS),
            Text(b", "),
            Day { fixed: true },
            Text(b"-"),
            Month,
            Text(b"-"),
            ShortYear,
            Text(b" "),
            Hour,
            Text(b":"),
            Minute,
            Text(b":"),
            Second,
            Text(b" "),
            Zone,
        ],
        // Mon Jan _2 15:04:05 2006
        &[
            Weekday(SHORT_DAYS),
            Text(b" "),
            Month,
            Text(b" "),
            Day { fixed: false },
            Text(b" "),
            Hour,
            Text(b":"),
            Minute,
            Text(b":"),
            Second,
            Text(b" "),
            Year,
        ],
    ]
};

/// Go's `http.ParseTime`: the Unix seconds and nanoseconds of the first of
/// its layouts the text fits, each read as `time.Parse` reads it. A zone's
/// abbreviation leaves the time as UTC's, as Go leaves it for any zone but
/// the machine's own.
pub(super) fn parse_http_date(raw: &str) -> Option<(i64, u32)> {
    HTTP_DATE_LAYOUTS
        .iter()
        .find_map(|layout| parse_date_layout(raw.as_bytes(), layout))
}

fn parse_date_layout(mut value: &[u8], layout: &[DatePart]) -> Option<(i64, u32)> {
    let (mut year, mut month, mut day) = (0, 0, 0);
    let (mut hour, mut minute, mut second, mut nanos) = (0, 0, 0, 0);
    for part in layout {
        match *part {
            DatePart::Text(text) => value = skip_layout_text(value, text)?,
            DatePart::Weekday(names) => value = lookup_name(names, value)?.1,
            DatePart::Month => {
                let (index, rest) = lookup_name(MONTHS, value)?;
                (month, value) = (index as u32 + 1, rest);
            }
            DatePart::Day { fixed } => {
                let digits = match value {
                    [b' ', rest @ ..] if !fixed => rest,
                    _ => value,
                };
                (day, value) = take_number(digits, fixed)?;
            }
            DatePart::Year => {
                if value.len() < 4 || !value[0].is_ascii_digit() {
                    return None;
                }
                (year, value) = (go_atoi(&value[..4])?, &value[4..]);
            }
            DatePart::ShortYear => {
                let short = go_atoi(value.get(..2)?)?;
                year = if short >= 69 {
                    short + 1900
                } else {
                    short + 2000
                };
                value = &value[2..];
            }
            DatePart::Hour => {
                (hour, value) = take_number(value, false)?;
                if hour >= 24 {
                    return None;
                }
            }
            DatePart::Minute => {
                (minute, value) = take_number(value, true)?;
                if minute >= 60 {
                    return None;
                }
            }
            DatePart::Second => {
                (second, value) = take_number(value, true)?;
                if second >= 60 {
                    return None;
                }
                if let [b'.' | b',', first, ..] = value {
                    if first.is_ascii_digit() {
                        let digits = value[1..].iter().take_while(|b| b.is_ascii_digit()).count();
                        // The first nine digits count; the rest are read past.
                        let kept = &value[1..1 + digits.min(9)];
                        let read = kept
                            .iter()
                            .fold(0u32, |n, digit| n * 10 + u32::from(digit - b'0'));
                        nanos = read * 10u32.pow(9 - kept.len() as u32);
                        value = &value[1 + digits..];
                    }
                }
            }
            DatePart::Zone => value = &value[zone_length(value)?..],
        }
    }
    if !value.is_empty() || day < 1 || day > days_in_month(month, year) {
        return None;
    }
    let secs =
        days_from_civil(year, month, day as u32) * 86_400 + hour * 3600 + minute * 60 + second;
    Some((secs, nanos))
}

/// The `time` package's `skip`: the layout's own text, where a space takes
/// any run of spaces, or none at the end of the value.
fn skip_layout_text<'a>(mut value: &'a [u8], mut text: &[u8]) -> Option<&'a [u8]> {
    let spaces = |s: &[u8]| s.iter().take_while(|&&b| b == b' ').count();
    while let Some(&want) = text.first() {
        if want == b' ' {
            if value.first().is_some_and(|&b| b != b' ') {
                return None;
            }
            text = &text[spaces(text)..];
            value = &value[spaces(value)..];
            continue;
        }
        if value.first() != Some(&want) {
            return None;
        }
        (text, value) = (&text[1..], &value[1..]);
    }
    Some(value)
}

/// The `time` package's `lookup`: the first of `names` the value starts
/// with, its letters in any case.
fn lookup_name<'a>(names: &[&str], value: &'a [u8]) -> Option<(usize, &'a [u8])> {
    let same = |a: u8, b: u8| a == b || (a | 0x20 == b | 0x20 && (a | 0x20).is_ascii_lowercase());
    let index = names.iter().position(|name| {
        value.len() >= name.len() && value.iter().zip(name.bytes()).all(|(&a, b)| same(a, b))
    })?;
    Some((index, &value[names[index].len()..]))
}

/// The `time` package's `getnum`: one digit or two, exactly two when
/// `fixed`.
fn take_number(value: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
    let digit = |i: usize| {
        value
            .get(i)
            .filter(|b| b.is_ascii_digit())
            .map(|b| i64::from(b - b'0'))
    };
    let first = digit(0)?;
    match digit(1) {
        Some(second) => Some((first * 10 + second, &value[2..])),
        None if fixed => None,
        None => Some((first, &value[1..])),
    }
}

/// The `time` package's `atoi`: a sign or none, then digits to the end, as
/// few as none.
fn go_atoi(text: &[u8]) -> Option<i64> {
    let (negative, digits) = match text {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, text),
    };
    let mut number: i64 = 0;
    for &digit in digits {
        if !digit.is_ascii_digit() {
            return None;
        }
        number = number
            .checked_mul(10)?
            .checked_add(i64::from(digit - b'0'))?;
    }
    Some(if negative { -number } else { number })
}

/// How much of the value a zone takes, as `time.Parse` reads `MST`: `UTC`,
/// or `parseTimeZone`'s abbreviations, `GMT` with hours, and signed hours.
fn zone_length(value: &[u8]) -> Option<usize> {
    if value.starts_with(b"UTC") {
        return Some(3);
    }
    if value.len() < 3 {
        return None;
    }
    if value.starts_with(b"ChST") || value.starts_with(b"MeST") {
        return Some(4);
    }
    if value.starts_with(b"GMT") {
        return Some(3 + signed_hours_length(&value[3..]));
    }
    if matches!(value[0], b'+' | b'-') {
        return Some(signed_hours_length(value)).filter(|&n| n > 0);
    }
    let upper = value
        .iter()
        .take(6)
        .take_while(|b| b.is_ascii_uppercase())
        .count();
    match upper {
        5 if value[4] == b'T' => Some(5),
        4 if value[3] == b'T' || value.starts_with(b"WITA") => Some(4),
        3 => Some(3),
        _ => None,
    }
}

/// `parseSignedOffset`: the length of a sign and hours up to 23, or zero.
fn signed_hours_length(value: &[u8]) -> usize {
    let [b'+' | b'-', rest @ ..] = value else {
        return 0;
    };
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let hours = rest[..digits].iter().try_fold(0u64, |n, digit| {
        n.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
    });
    match hours {
        Some(hours) if digits > 0 && hours <= 23 => 1 + digits,
        _ => 0,
    }
}

/// `daysIn`.
fn days_in_month(month: u32, year: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
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
