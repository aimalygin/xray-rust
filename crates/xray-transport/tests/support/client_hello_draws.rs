//! What uTLS draws anew for every ClientHello, taken out of a byte
//! comparison: the GREASE value of each slot, and the extension order of a
//! Chrome profile whose spec runs `ShuffleChromeTLSExtensions`. A hello and a
//! fixture made under another draw compare equal once both are canonical.
//!
//! The ECH GREASE payload length is drawn too, but a byte comparison keeps it:
//! each of Chrome's four lengths has a fixture of its own, and a test draws
//! hellos until one carries the length of the fixture it is held to
//! (`ech_length`). Only a comparison between two fresh hellos takes it out,
//! with the padding that follows from it (`without_drawn_lengths`).

// Each test crate that includes this module uses part of it.
#![allow(dead_code)]

/// The fingerprints whose uTLS spec runs `ShuffleChromeTLSExtensions`
/// (`u_parrots.go`), with Chrome 155's two other names.
pub const SHUFFLED_FINGERPRINTS: [&str; 12] = [
    "chrome",
    "hellochrome_auto",
    "hellochrome_106_shuffle",
    "hellochrome_112_psk_shuf",
    "hellochrome_114_padding_psk_shuf",
    "hellochrome_115_pq",
    "hellochrome_115_pq_psk",
    "hellochrome_120",
    "hellochrome_120_pq",
    "hellochrome_131",
    "hellochrome_133",
    "hellochrome_155",
];

const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PADDING: u16 = 0x0015;
const EXT_ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
const CANONICAL_GREASE: [u8; 2] = [0x0a, 0x0a];

/// The ECH GREASE extension lengths Chrome's `BoringGREASEECH` draws one of
/// for every hello: payloads of 128, 160, 192 or 224 bytes, with the 16-byte
/// AEAD tag and the outer header.
pub const CHROME_ECH_LENGTHS: [usize; 4] = [186, 218, 250, 282];

/// The fingerprints whose hello carries Chrome's ECH GREASE.
pub const CHROME_ECH_FINGERPRINTS: [&str; 7] = [
    "chrome",
    "hellochrome_auto",
    "hellochrome_120",
    "hellochrome_120_pq",
    "hellochrome_131",
    "hellochrome_133",
    "hellochrome_155",
];

/// How many hellos a test draws to meet one ECH GREASE length: with four
/// lengths drawn evenly, all 256 miss a given one with probability
/// `(3/4)^256`, below `10^-31`.
pub const ECH_DRAWS: usize = 256;

/// Whether uTLS shuffles this fingerprint's extensions for every hello.
pub fn shuffles(fingerprint: &str) -> bool {
    SHUFFLED_FINGERPRINTS.contains(&fingerprint)
}

/// RFC 8701's reserved values, `0x?a?a`.
pub fn is_grease(value: u16) -> bool {
    let [high, low] = value.to_be_bytes();
    high == low && high & 0x0f == 0x0a
}

/// `hello`, a ClientHello handshake message from its type byte, with every
/// GREASE value uTLS draws written as `0x0a0a` -- in the cipher suites, the
/// extension types, supported_groups, supported_versions, the key share
/// groups and signature_algorithms -- and, with `sort_extensions`, its
/// extensions in order of type, length and body. Lengths do not change.
pub fn canonical_client_hello(hello: &[u8], sort_extensions: bool) -> Vec<u8> {
    let mut out = hello.to_vec();
    let mut cursor = 4 + 2 + 32;
    cursor += 1 + usize::from(out[cursor]);
    let cipher_suites_len = usize::from(u16_at(&out, cursor));
    cursor += 2;
    for at in (cursor..cursor + cipher_suites_len).step_by(2) {
        regrease(&mut out, at);
    }
    cursor += cipher_suites_len;
    cursor += 1 + usize::from(out[cursor]);
    let extensions_len = usize::from(u16_at(&out, cursor));
    cursor += 2;
    let start = cursor;
    let end = start + extensions_len;
    assert_eq!(end, out.len(), "the extensions end the ClientHello");

    let mut extensions = Vec::new();
    while cursor < end {
        let extension_type = u16_at(&out, cursor);
        let body = cursor + 4;
        let body_end = body + usize::from(u16_at(&out, cursor + 2));
        regrease(&mut out, cursor);
        match extension_type {
            EXT_SUPPORTED_GROUPS | EXT_SIGNATURE_ALGORITHMS => {
                let list_end = body + 2 + usize::from(u16_at(&out, body));
                for at in (body + 2..list_end).step_by(2) {
                    regrease(&mut out, at);
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let list_end = body + 1 + usize::from(out[body]);
                for at in (body + 1..list_end).step_by(2) {
                    regrease(&mut out, at);
                }
            }
            EXT_KEY_SHARE => {
                let mut share = body + 2;
                while share < body_end {
                    regrease(&mut out, share);
                    share += 4 + usize::from(u16_at(&out, share + 2));
                }
            }
            _ => {}
        }
        extensions.push(out[cursor..body_end].to_vec());
        cursor = body_end;
    }
    assert_eq!(cursor, end, "the last extension ends the ClientHello");
    if sort_extensions {
        extensions.sort();
    }
    out.splice(start..end, extensions.concat());
    out
}

/// The body of the `wanted` extension of a ClientHello handshake message.
pub fn extension_body(hello: &[u8], wanted: u16) -> Option<&[u8]> {
    extensions(hello)
        .into_iter()
        .find(|(extension_type, _)| *extension_type == wanted)
        .map(|(_, body)| body)
}

/// The length of a ClientHello handshake message's ECH extension.
pub fn ech_length(hello: &[u8]) -> Option<usize> {
    extension_body(hello, EXT_ENCRYPTED_CLIENT_HELLO).map(<[u8]>::len)
}

/// `hello`, a ClientHello handshake message, without the two lengths an ECH
/// GREASE draw moves: the outer ECH payload cut to nothing, and no padding
/// extension, since BoringSSL decides the padding from the rest of the hello
/// (`utls_shaping` holds that rule to uTLS's). The lengths framing either are
/// rewritten.
pub fn without_drawn_lengths(hello: &[u8]) -> Vec<u8> {
    let start = extensions_start(hello);
    let mut extensions_out = Vec::new();
    for (extension_type, body) in extensions(hello) {
        let body = match extension_type {
            EXT_PADDING => continue,
            // An outer hello: type, KDF and AEAD ids, config id, then the
            // encapsulated key and the payload, each behind a two-byte length.
            EXT_ENCRYPTED_CLIENT_HELLO if body.first() == Some(&0) => {
                let enc_end = 8 + usize::from(u16_at(body, 6));
                [&body[..enc_end], &[0, 0]].concat()
            }
            _ => body.to_vec(),
        };
        extensions_out.extend_from_slice(&extension_type.to_be_bytes());
        extensions_out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        extensions_out.extend(body);
    }
    let mut out = hello[..start].to_vec();
    out.extend_from_slice(&(extensions_out.len() as u16).to_be_bytes());
    out.extend(extensions_out);
    let length = (out.len() - 4) as u32;
    out[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
    out
}

/// Where a ClientHello handshake message's extensions length sits.
fn extensions_start(hello: &[u8]) -> usize {
    let mut cursor = 4 + 2 + 32;
    cursor += 1 + usize::from(hello[cursor]);
    cursor += 2 + usize::from(u16_at(hello, cursor));
    cursor + 1 + usize::from(hello[cursor])
}

/// The extensions of a ClientHello handshake message, type and body, in order.
fn extensions(hello: &[u8]) -> Vec<(u16, &[u8])> {
    let mut cursor = extensions_start(hello);
    let end = cursor + 2 + usize::from(u16_at(hello, cursor));
    cursor += 2;
    let mut extensions = Vec::new();
    while cursor < end {
        let body_len = usize::from(u16_at(hello, cursor + 2));
        extensions.push((
            u16_at(hello, cursor),
            &hello[cursor + 4..cursor + 4 + body_len],
        ));
        cursor += 4 + body_len;
    }
    extensions
}

/// The extension types of a ClientHello handshake message, in order.
pub fn extension_types(hello: &[u8]) -> Vec<u16> {
    let mut cursor = 4 + 2 + 32;
    cursor += 1 + usize::from(hello[cursor]);
    cursor += 2 + usize::from(u16_at(hello, cursor));
    cursor += 1 + usize::from(hello[cursor]);
    let end = cursor + 2 + usize::from(u16_at(hello, cursor));
    cursor += 2;
    let mut types = Vec::new();
    while cursor < end {
        types.push(u16_at(hello, cursor));
        cursor += 4 + usize::from(u16_at(hello, cursor + 2));
    }
    types
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

fn regrease(bytes: &mut [u8], at: usize) {
    if is_grease(u16_at(bytes, at)) {
        bytes[at..at + 2].copy_from_slice(&CANONICAL_GREASE);
    }
}
