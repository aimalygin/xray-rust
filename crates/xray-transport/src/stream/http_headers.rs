//! Go-compatible HTTP/1.1 request serialization.
//!
//! Xray writes its requests with Go's `net/http`, whose header order is
//! observable and therefore part of the fingerprint: request line, `Host`,
//! `User-Agent`, then every other header sorted **case-sensitively by the
//! literal map key**. Header names keep whatever casing the caller used —
//! Xray deliberately emits non-canonical names like `Sec-CH-UA` and `DNT`.
//! A Rust HTTP stack would lowercase or reorder these, which is why this is
//! written by hand.

/// Insertion-order-independent header storage that keeps literal key casing.
///
/// Go's `http.Header` is a map, so two keys differing only in case are two
/// distinct headers, and both are emitted. This mirrors that.
#[derive(Debug, Clone, Default)]
pub struct HeaderMap {
    entries: Vec<(String, String)>,
}

impl HeaderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces any existing value for this exact key. Comparison is
    /// case-sensitive, matching Go's map semantics.
    pub fn set(&mut self, key: &str, value: &str) {
        match self.entries.iter_mut().find(|(name, _)| name == key) {
            Some((_, existing)) => *existing = value.to_owned(),
            None => self.entries.push((key.to_owned(), value.to_owned())),
        }
    }

    /// Sets the value only when the key is absent. Xray uses this for
    /// `Accept`, `Cache-Control` and `Pragma`, which never override a
    /// user-supplied value.
    pub fn set_if_absent(&mut self, key: &str, value: &str) {
        if self.get(key).is_none() {
            self.set(key, value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|(name, _)| name != key);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Serializes a request the way Go's `Request.Write` does.
///
/// `host` becomes the `Host` header; Go carries it in `Request.Host` rather
/// than the header map, which is why it is a separate argument and why it is
/// never subject to the sort. `Host` and `User-Agent` are both excluded from
/// the sorted remainder for the same reason: Go writes each from its own
/// `Request` field (`Request.Host`, and the `User-Agent` line emitted above),
/// so a map entry under either name would duplicate a line this function
/// already wrote. Go's own writer excludes both via `reqWriteExcludeHeader`;
/// an unfiltered `Host` entry would produce two `Host:` lines, an RFC 7230
/// §5.4 violation most servers reject outright.
pub fn serialize_request(method: &str, path: &str, host: &str, headers: &HeaderMap) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());

    if let Some(user_agent) = headers.get("User-Agent") {
        out.extend_from_slice(format!("User-Agent: {user_agent}\r\n").as_bytes());
    }

    let mut rest: Vec<&(String, String)> = headers
        .entries
        .iter()
        .filter(|(name, _)| name != "User-Agent" && name != "Host")
        .collect();
    rest.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));

    for (name, value) in rest {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    out.extend_from_slice(b"\r\n");
    out
}
