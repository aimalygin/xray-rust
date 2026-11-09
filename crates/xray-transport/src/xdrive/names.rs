//! Where a session's objects live in the storage, named as Xray-core
//! v26.10.31's `xdrive.go` and `wal.go` name them.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::{rngs::OsRng, RngCore};

/// The folder a client announces its sessions in.
pub(crate) const SESSIONS_DIR: &str = "sessions";
/// The folder of every session's streams.
pub(crate) const STREAMS_DIR: &str = "streams";
/// The client's direction, which it writes.
pub(crate) const UPLINK_DIR: &str = "c2s";
/// The server's direction, which the client reads.
pub(crate) const DOWNLINK_DIR: &str = "s2c";

/// A segment of data.
pub(crate) const SEG_SUFFIX: &str = ".seg";
/// The direction ended after the segments before it.
pub(crate) const END_SUFFIX: &str = ".end";
/// The writer could not store the segment of this number.
pub(crate) const ERR_SUFFIX: &str = ".err";

/// Xray-core's `newSessionID`: sixteen random bytes in lowercase hex.
pub(crate) fn new_session_id() -> String {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `announceName`: `sessions/<Unix nanoseconds>-<session>`. Before 1970
/// the nanoseconds are negative, as Go's `UnixNano` makes them.
pub(crate) fn announce_name(session: &str, at: SystemTime) -> String {
    let nanos: i128 = match at.duration_since(UNIX_EPOCH) {
        Ok(after) => after.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    };
    // UnixNano is an int64: it wraps outside 1678..2262, as Go's does.
    format!("{SESSIONS_DIR}/{}-{session}", nanos as i64)
}

/// `sessionPrefix`: the folder of one session's two directions.
pub(crate) fn session_prefix(session: &str) -> String {
    format!("{STREAMS_DIR}/{session}")
}

/// `uplinkPrefix`.
pub(crate) fn uplink_prefix(session: &str) -> String {
    format!("{}/{UPLINK_DIR}", session_prefix(session))
}

/// `downlinkPrefix`.
pub(crate) fn downlink_prefix(session: &str) -> String {
    format!("{}/{DOWNLINK_DIR}", session_prefix(session))
}

/// `objectName`: `fmt.Sprintf("%s/%09d%s", prefix, seq, suffix)`.
pub(crate) fn object_name(prefix: &str, seq: i64, suffix: &str) -> String {
    format!("{prefix}/{seq:09}{suffix}")
}

/// What an entry of a direction holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EntryKind {
    Segment,
    End,
    Failed,
}

/// `parseEntry`: the number and kind of an entry, from the name after its
/// direction's folder. The number is what Go's `strconv.ParseInt(_, 10, 64)`
/// reads before the last dot, sign and leading zeros included, and must not
/// be negative.
pub(crate) fn parse_entry(name: &str) -> Option<(i64, EntryKind)> {
    let dot = name.rfind('.')?;
    let kind = match &name[dot..] {
        SEG_SUFFIX => EntryKind::Segment,
        END_SUFFIX => EntryKind::End,
        ERR_SUFFIX => EntryKind::Failed,
        _ => return None,
    };
    let seq = go_parse_int(&name[..dot])?;
    (seq >= 0).then_some((seq, kind))
}

/// Go's `strconv.ParseInt(s, 10, 64)`: an optional sign, then at least one
/// decimal digit, within the range of an `int64`.
fn go_parse_int(s: &str) -> Option<i64> {
    let (negative, digits) = match s.as_bytes().first()? {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut value: i128 = 0;
    for b in digits.bytes() {
        value = value * 10 + i128::from(b - b'0');
        if value > i128::from(i64::MAX) + 1 {
            return None;
        }
    }
    let value = if negative { -value } else { value };
    i64::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn objects_are_numbered_with_nine_digits_at_least() {
        assert_eq!(
            object_name("streams/ab/c2s", 0, SEG_SUFFIX),
            "streams/ab/c2s/000000000.seg"
        );
        assert_eq!(object_name("p", 42, END_SUFFIX), "p/000000042.end");
        assert_eq!(
            object_name("p", 1_234_567_890, ERR_SUFFIX),
            "p/1234567890.err"
        );
    }

    #[test]
    fn entries_parse_as_go_parses_them() {
        assert_eq!(parse_entry("000000007.seg"), Some((7, EntryKind::Segment)));
        assert_eq!(parse_entry("12.end"), Some((12, EntryKind::End)));
        assert_eq!(parse_entry("3.err"), Some((3, EntryKind::Failed)));
        assert_eq!(parse_entry("+5.seg"), Some((5, EntryKind::Segment)));
        assert_eq!(parse_entry("-0.seg"), Some((0, EntryKind::Segment)));
        assert_eq!(
            parse_entry("9223372036854775807.seg").map(|e| e.0),
            Some(i64::MAX)
        );
        for name in [
            "-1.seg",
            "9223372036854775808.seg",
            "1.tmp",
            "seg",
            ".seg",
            "+.seg",
            "1_000.seg",
            " 1.seg",
            "0x1.seg",
            "1.seg.bak",
            "a.b.seg",
        ] {
            assert_eq!(parse_entry(name), None, "{name}");
        }
        // The last dot counts.
        assert_eq!(parse_entry("1.2.seg"), None);
    }

    #[test]
    fn announcements_carry_unix_nanoseconds() {
        let at = UNIX_EPOCH + Duration::new(1_700_000_000, 123);
        assert_eq!(announce_name("abc", at), "sessions/1700000000000000123-abc");
        let before = UNIX_EPOCH - Duration::from_nanos(5);
        assert_eq!(announce_name("abc", before), "sessions/-5-abc");
    }

    #[test]
    fn sessions_are_sixteen_random_bytes_in_hex() {
        let id = new_session_id();
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_ne!(id, new_session_id());
        assert_eq!(uplink_prefix("s"), "streams/s/c2s");
        assert_eq!(downlink_prefix("s"), "streams/s/s2c");
    }
}
