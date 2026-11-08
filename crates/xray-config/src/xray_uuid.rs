//! User ids as Xray-core's `uuid.ParseString` reads them.

use sha1::{Digest, Sha1};
use uuid::Uuid;

/// The groups of hex digits a UUID is written in.
const GROUPS: [usize; 5] = [8, 4, 4, 4, 12];

/// Reads `text` as Xray-core's `uuid.ParseString` does. Lengths count bytes:
///
/// - 32 to 36 bytes are hex digits in groups of 8, 4, 4, 4 and 12, any of
///   which may be preceded by one `-`; whatever follows the last group is
///   ignored.
/// - 1 to 30 bytes of any text name the UUID made of the first 16 bytes of
///   SHA-1 over 16 zero bytes and the text, with version 5 and the RFC 4122
///   variant, so a custom id needs no UUID.
/// - Anything else is no id.
pub(crate) fn parse(text: &str) -> Option<Uuid> {
    let bytes = text.as_bytes();
    match bytes.len() {
        1..=30 => {
            let mut hash = Sha1::new();
            hash.update([0_u8; 16]);
            hash.update(bytes);
            let digest = hash.finalize();
            let mut id = [0_u8; 16];
            id.copy_from_slice(&digest[..16]);
            id[6] = (id[6] & 0x0f) | (5 << 4);
            id[8] = (id[8] & 0x3f) | 0x80;
            Some(Uuid::from_bytes(id))
        }
        32..=36 => {
            let mut id = [0_u8; 16];
            let mut rest = bytes;
            let mut offset = 0;
            for group in GROUPS {
                if let [b'-', after @ ..] = rest {
                    rest = after;
                }
                let digits = rest.get(..group)?;
                for (index, pair) in digits.chunks_exact(2).enumerate() {
                    id[offset + index] = hex(pair[0])? << 4 | hex(pair[1])?;
                }
                rest = &rest[group..];
                offset += group / 2;
            }
            Some(Uuid::from_bytes(id))
        }
        _ => None,
    }
}

/// Reads `text` as `github.com/google/uuid` v1.6.0's `Parse` does, which
/// Xray-core's `xmc` profiles use. By length in bytes:
///
/// - 36: hex digits in groups of 8, 4, 4, 4 and 12, joined by `-`;
/// - 45: the same after `urn:uuid:`, in any case;
/// - 38: the same after any first byte, with any last byte, which `Parse`
///   never checks for braces;
/// - 32: 32 hex digits.
pub(crate) fn parse_google(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    let mut id = [0_u8; 16];
    let grouped = match bytes.len() {
        36 => bytes,
        45 if bytes[..9].eq_ignore_ascii_case(b"urn:uuid:") => &bytes[9..],
        38 => &bytes[1..],
        32 => {
            for (index, pair) in bytes.chunks_exact(2).enumerate() {
                id[index] = hex(pair[0])? << 4 | hex(pair[1])?;
            }
            return Some(id);
        }
        _ => return None,
    };
    if [8, 13, 18, 23].iter().any(|&dash| grouped[dash] != b'-') {
        return None;
    }
    let starts = [0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34];
    for (index, start) in starts.into_iter().enumerate() {
        id[index] = hex(grouped[start])? << 4 | hex(grouped[start + 1])?;
    }
    Some(id)
}

fn hex(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "27848739-7e62-4138-9fd3-098a63964b6b";

    #[test]
    fn hex_ids_read_as_xray_core_reads_them() {
        let id = Uuid::parse_str(ID).unwrap();
        for text in [
            ID,
            "27848739-7E62-4138-9FD3-098A63964B6B",
            "278487397e6241389fd3098a63964b6b",
            "-278487397e62-41389fd3098a63964b6b",
            // Whatever follows the last group is ignored.
            "278487397e6241389fd3098a63964b6b----",
            "278487397e6241389fd3098a63964b6bzz",
        ] {
            assert_eq!(parse(text), Some(id), "{text}");
        }
        for text in [
            "",
            // 31 bytes is too long for a custom id and too short for a UUID.
            "278487397e6241389fd3098a63964b6",
            "{27848739-7e62-4138-9fd3-098a63964b6b}",
            "urn:uuid:27848739-7e62-4138-9fd3-098a63964b6b",
            "27848739--7e62-4138-9fd3-098a63964b6b",
            "g7848739-7e62-4138-9fd3-098a63964b6b",
            "27848739 7e62 4138 9fd3 098a63964b6b",
        ] {
            assert_eq!(parse(text), None, "{text}");
        }
    }

    #[test]
    fn google_parse_reads_its_four_forms() {
        let id = *Uuid::parse_str(ID).unwrap().as_bytes();
        for text in [
            ID,
            "27848739-7E62-4138-9FD3-098A63964B6B",
            "urn:uuid:27848739-7e62-4138-9fd3-098a63964b6b",
            "URN:UUID:27848739-7e62-4138-9fd3-098a63964b6b",
            "{27848739-7e62-4138-9fd3-098a63964b6b}",
            // Parse drops the first byte and never reads the last.
            "x27848739-7e62-4138-9fd3-098a63964b6bx",
            "278487397e6241389fd3098a63964b6b",
        ] {
            assert_eq!(parse_google(text), Some(id), "{text}");
        }
        for text in [
            "",
            "27848739-7e62-4138-9fd3-098a63964b6",
            "urn:uuix:27848739-7e62-4138-9fd3-098a63964b6b",
            "27848739_7e62-4138-9fd3-098a63964b6b",
            "g7848739-7e62-4138-9fd3-098a63964b6b",
            "278487397e6241389fd3098a63964b6g",
            "-278487397e62-41389fd3098a63964b6b",
            // Xray's own short ids are not UUIDs here.
            "my-short-id",
        ] {
            assert_eq!(parse_google(text), None, "{text}");
        }
    }

    /// Values from Xray-core v26.10.31's `uuid.ParseString`.
    #[test]
    fn short_text_names_a_version_5_id() {
        for (text, expected) in [
            ("a", "35b65f33-a679-5e76-af3c-273ea349ede4"),
            ("my-short-id", "ed39ef4a-c613-54b3-9b2a-2a6cf18cc74f"),
            (
                "123456789012345678901234567890",
                "3d2e4120-1e1e-52f0-b92d-f67cfbfb1982",
            ),
            ("пароль", "656bdd3f-a339-5420-8c71-4b561ae81ec7"),
        ] {
            assert_eq!(
                parse(text).map(|id| id.to_string()),
                Some(expected.to_owned()),
                "{text}"
            );
        }
    }
}
