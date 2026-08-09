//! `serviceName` to `:path`, following Xray's two dialects.
//!
//! Xray reads a name without a leading `/` as an old-school service name and
//! escapes it whole, so an inner `/` becomes `%2F`. A name *with* a leading `/`
//! is a custom path: everything between the first and last `/` is the service
//! name escaped segment by segment, and the last segment is the stream name,
//! optionally split on `|` into the plain and multi-mode names.
//! `Xray-core/transport/internet/grpc/config.go:17-59`.

use super::framing::HunkMode;

/// Go's `url.PathEscape`, i.e. `escape(s, encodePathSegment)`.
///
/// Alphanumerics and `-_.~` pass; of the reserved set, `encodePathSegment`
/// keeps `$ & + : = @` and escapes `/ ; , ?`; everything else is escaped.
/// Go writes the hex digits in upper case.
fn path_escape(input: &str) -> String {
    const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        let keep = matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9')
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || matches!(byte, b'$' | b'&' | b'+' | b':' | b'=' | b'@');
        if keep {
            out.push(*byte as char);
        } else {
            out.push('%');
            out.push(UPPER_HEX[usize::from(byte >> 4)] as char);
            out.push(UPPER_HEX[usize::from(byte & 0x0f)] as char);
        }
    }
    out
}

fn service_name(configured: &str) -> String {
    if !configured.starts_with('/') {
        return path_escape(configured);
    }

    // Go clamps `lastIndex < 1` up to 1. Without the clamp, a bare "/" (its
    // only '/' at index 0) would give `last_slash == 0` and the slice below
    // would be `configured[1..0]` — an inverted range, which is what actually
    // panics here (`configured[1..1]`, the clamped form, is legal and simply
    // empty). Clamping to 1 turns `/hello` into an empty service name instead.
    //
    // `stream_name` below needs no equivalent guard: it always slices from
    // `last_slash + 1` onward, and `last_slash` is a byte index found within
    // `configured`, so `last_slash + 1 <= configured.len()` always holds and
    // that range can never invert.
    let last_slash = configured
        .rfind('/')
        .expect("checked for a leading slash")
        .max(1);
    configured[1..last_slash]
        .split('/')
        .map(path_escape)
        .collect::<Vec<_>>()
        .join("/")
}

fn stream_name(configured: &str, mode: HunkMode) -> String {
    if !configured.starts_with('/') {
        return match mode {
            HunkMode::Multi => "TunMulti",
            HunkMode::Single => "Tun",
        }
        .to_owned();
    }

    let last_slash = configured.rfind('/').expect("checked for a leading slash");
    let ending = &configured[last_slash + 1..];
    let mut parts = ending.split('|');
    let first = parts.next().unwrap_or_default();

    if mode == HunkMode::Single {
        return path_escape(first);
    }

    // One part means the whole ending path is the multi name; two means the
    // second part is. Upstream calls these the client and server spellings,
    // but the client honours both.
    match parts.next() {
        Some(second) => path_escape(second),
        None => path_escape(first),
    }
}

/// The `:path` pseudo-header for one gRPC dial.
///
/// The mode is a [`HunkMode`] rather than Xray's `multiMode` bool because the
/// RPC this names and the message [`HunkDecoder`](super::HunkDecoder) reads off
/// it are two halves of one choice — see [`HunkMode`], and
/// `h2client::GrpcCall`, where the single value both take is derived.
pub fn grpc_request_path(configured_service_name: &str, mode: HunkMode) -> String {
    format!(
        "/{}/{}",
        service_name(configured_service_name),
        stream_name(configured_service_name, mode)
    )
}
