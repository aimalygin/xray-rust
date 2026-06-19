use std::net::IpAddr;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use xray_config::{InboundSniffingConfig, SniffingDestination};
use xray_routing::{Target, TargetAddr};

const QUIC_V1: u32 = 1;
const QUIC_V1_INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_CLIENT_INITIAL_SECRET_LEN: usize = 32;
const QUIC_INITIAL_KEY_LEN: usize = 16;
const QUIC_INITIAL_IV_LEN: usize = 12;
const QUIC_INITIAL_HP_LEN: usize = 16;
const QUIC_TAG_LEN: usize = 16;
const QUIC_HP_SAMPLE_LEN: usize = 16;
const QUIC_MAX_CRYPTO_STREAM_SIZE: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SniffedTarget {
    pub route_target: Target,
    pub dial_target: Target,
    pub protocol: SniffingDestination,
}

pub(crate) fn should_sniff_tcp(config: Option<&InboundSniffingConfig>) -> bool {
    let Some(config) = config else {
        return false;
    };
    config.enabled
        && !config.metadata_only
        && config.dest_override.iter().any(|override_kind| {
            matches!(
                override_kind,
                SniffingDestination::Http | SniffingDestination::Tls
            )
        })
}

pub(crate) fn should_sniff_udp(config: Option<&InboundSniffingConfig>) -> bool {
    let Some(config) = config else {
        return false;
    };
    config.enabled
        && !config.metadata_only
        && config
            .dest_override
            .iter()
            .any(|override_kind| matches!(override_kind, SniffingDestination::Quic))
}

pub(crate) fn sniff_tcp_initial_payload(
    config: &InboundSniffingConfig,
    original: &Target,
    payload: &[u8],
) -> Option<SniffedTarget> {
    if config.metadata_only || payload.is_empty() {
        return None;
    }

    for override_kind in &config.dest_override {
        let domain = match override_kind {
            SniffingDestination::Http => sniff_http_host(payload),
            SniffingDestination::Tls => sniff_tls_client_hello_sni(payload),
            SniffingDestination::Quic => None,
        };
        if let Some(domain) = domain {
            return Some(sniffed_target(config, original, domain, *override_kind));
        }
    }

    None
}

pub(crate) fn sniff_udp_initial_payload(
    config: &InboundSniffingConfig,
    original: &Target,
    payload: &[u8],
) -> Option<SniffedTarget> {
    if config.metadata_only || payload.is_empty() {
        return None;
    }

    for override_kind in &config.dest_override {
        let domain = match override_kind {
            SniffingDestination::Quic => sniff_quic_initial_sni(payload),
            SniffingDestination::Http | SniffingDestination::Tls => None,
        };
        if let Some(domain) = domain {
            return Some(sniffed_target(config, original, domain, *override_kind));
        }
    }

    None
}

fn sniffed_target(
    config: &InboundSniffingConfig,
    original: &Target,
    domain: String,
    protocol: SniffingDestination,
) -> SniffedTarget {
    let route_target = Target::new(TargetAddr::Domain(domain), original.port, original.network);
    let dial_target = if config.route_only {
        original.clone()
    } else {
        route_target.clone()
    };
    SniffedTarget {
        route_target,
        dial_target,
        protocol,
    }
}

fn sniff_http_host(payload: &[u8]) -> Option<String> {
    let header_end = find_subslice(payload, b"\r\n\r\n")?;
    let head = std::str::from_utf8(&payload[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    if !is_http_request_line(request_line) {
        return None;
    }

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            return normalize_host(value.trim());
        }
    }

    None
}

fn is_http_request_line(line: &str) -> bool {
    let mut parts = line.split_ascii_whitespace();
    let Some(method) = parts.next() else {
        return false;
    };
    let Some(_) = parts.next() else {
        return false;
    };
    let Some(version) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && matches!(
            method,
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT"
        )
        && version.starts_with("HTTP/")
}

fn sniff_tls_client_hello_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 9 || payload[0] != 22 {
        return None;
    }
    let record_len = read_u16(payload, 3)? as usize;
    if payload.len() < 5 + record_len {
        return None;
    }
    sniff_tls_client_hello_handshake_sni(&payload[5..5 + record_len])
}

fn sniff_tls_client_hello_handshake_sni(handshake: &[u8]) -> Option<String> {
    if handshake.len() < 4 || handshake[0] != 1 {
        return None;
    }
    let handshake_len = read_u24(handshake, 1)? as usize;
    let body_start = 4usize;
    let body_end = body_start.checked_add(handshake_len)?;
    if body_end > handshake.len() {
        return None;
    }
    sniff_tls_client_hello_body_sni(&handshake[body_start..body_end])
}

fn sniff_tls_client_hello_body_sni(body: &[u8]) -> Option<String> {
    let mut offset = 0usize;
    offset = offset.checked_add(2 + 32)?;
    let session_id_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + session_id_len)?;
    let cipher_suites_len = read_u16(body, offset)? as usize;
    offset = offset.checked_add(2 + cipher_suites_len)?;
    let compression_methods_len = *body.get(offset)? as usize;
    offset = offset.checked_add(1 + compression_methods_len)?;
    let extensions_len = read_u16(body, offset)? as usize;
    offset += 2;
    let extensions_end = offset.checked_add(extensions_len)?;
    if extensions_end > body.len() {
        return None;
    }

    while offset + 4 <= extensions_end {
        let extension_type = read_u16(body, offset)?;
        let extension_len = read_u16(body, offset + 2)? as usize;
        offset += 4;
        let extension_end = offset.checked_add(extension_len)?;
        if extension_end > extensions_end {
            return None;
        }
        if extension_type == 0 {
            return parse_tls_sni_extension(&body[offset..extension_end]);
        }
        offset = extension_end;
    }

    None
}

fn sniff_quic_initial_sni(packet: &[u8]) -> Option<String> {
    // Single-datagram QUIC v1 Initial sniffing, not general QUIC stream reassembly.
    let header = parse_quic_initial_header(packet)?;
    let keys = quic_initial_keys(header.version, header.dcid)?;
    let unprotected = unprotect_quic_initial_header(packet, &header, &keys.hp)?;
    let plaintext = decrypt_quic_initial_packet(packet, &unprotected, &keys)?;
    let crypto_stream = collect_quic_crypto_stream(&plaintext)?;
    sniff_tls_client_hello_handshake_sni(&crypto_stream)
}

struct QuicInitialHeader<'a> {
    version: u32,
    dcid: &'a [u8],
    packet_number_offset: usize,
    payload_end: usize,
    length: usize,
}

struct QuicInitialKeys {
    key: [u8; QUIC_INITIAL_KEY_LEN],
    iv: [u8; QUIC_INITIAL_IV_LEN],
    hp: [u8; QUIC_INITIAL_HP_LEN],
}

struct QuicUnprotectedHeader {
    header: Vec<u8>,
    packet_number: u64,
    ciphertext_offset: usize,
    payload_end: usize,
}

fn parse_quic_initial_header(packet: &[u8]) -> Option<QuicInitialHeader<'_>> {
    let first = *packet.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = read_u32(packet, 1)?;
    if version != QUIC_V1 || first & 0x30 != 0 {
        return None;
    }

    let mut offset = 5usize;
    let dcid_len = usize::from(*packet.get(offset)?);
    offset += 1;
    let dcid_end = offset.checked_add(dcid_len)?;
    let dcid = packet.get(offset..dcid_end)?;
    offset = dcid_end;

    let scid_len = usize::from(*packet.get(offset)?);
    offset += 1;
    let scid_end = offset.checked_add(scid_len)?;
    packet.get(offset..scid_end)?;
    offset = scid_end;

    let (token_len, token_len_size) = read_quic_varint(packet, offset)?;
    offset = offset.checked_add(token_len_size)?;
    offset = offset.checked_add(usize::try_from(token_len).ok()?)?;
    packet.get(..offset)?;

    let (length, length_size) = read_quic_varint(packet, offset)?;
    offset = offset.checked_add(length_size)?;
    let length = usize::try_from(length).ok()?;
    if length <= QUIC_TAG_LEN {
        return None;
    }
    let payload_end = offset.checked_add(length)?;
    packet.get(..payload_end)?;

    Some(QuicInitialHeader {
        version,
        dcid,
        packet_number_offset: offset,
        payload_end,
        length,
    })
}

fn quic_initial_keys(version: u32, dcid: &[u8]) -> Option<QuicInitialKeys> {
    let salt = match version {
        QUIC_V1 => QUIC_V1_INITIAL_SALT,
        _ => return None,
    };
    let hk = Hkdf::<Sha256>::new(Some(&salt), dcid);
    let mut client_initial_secret = [0; QUIC_CLIENT_INITIAL_SECRET_LEN];
    hk.expand(
        &tls13_hkdf_label(QUIC_CLIENT_INITIAL_SECRET_LEN as u16, b"client in"),
        &mut client_initial_secret,
    )
    .ok()?;

    let hk = Hkdf::<Sha256>::from_prk(&client_initial_secret).ok()?;
    let mut key = [0; QUIC_INITIAL_KEY_LEN];
    hk.expand(
        &tls13_hkdf_label(QUIC_INITIAL_KEY_LEN as u16, b"quic key"),
        &mut key,
    )
    .ok()?;
    let mut iv = [0; QUIC_INITIAL_IV_LEN];
    hk.expand(
        &tls13_hkdf_label(QUIC_INITIAL_IV_LEN as u16, b"quic iv"),
        &mut iv,
    )
    .ok()?;
    let mut hp = [0; QUIC_INITIAL_HP_LEN];
    hk.expand(
        &tls13_hkdf_label(QUIC_INITIAL_HP_LEN as u16, b"quic hp"),
        &mut hp,
    )
    .ok()?;

    Some(QuicInitialKeys { key, iv, hp })
}

fn unprotect_quic_initial_header(
    packet: &[u8],
    header: &QuicInitialHeader<'_>,
    hp_key: &[u8; QUIC_INITIAL_HP_LEN],
) -> Option<QuicUnprotectedHeader> {
    let sample_offset = header.packet_number_offset.checked_add(4)?;
    let sample = packet.get(sample_offset..sample_offset + QUIC_HP_SAMPLE_LEN)?;
    let mask = aes128_encrypt_block(hp_key, sample)?;
    let first = packet[0] ^ (mask[0] & 0x0f);
    let packet_number_len = usize::from((first & 0x03) + 1);
    if header.length <= packet_number_len + QUIC_TAG_LEN {
        return None;
    }
    let packet_number_end = header.packet_number_offset.checked_add(packet_number_len)?;
    if packet_number_end > header.payload_end {
        return None;
    }

    let mut unprotected = packet[..header.packet_number_offset].to_vec();
    unprotected[0] = first;
    let mut packet_number = 0u64;
    for index in 0..packet_number_len {
        let byte = packet[header.packet_number_offset + index] ^ mask[index + 1];
        unprotected.push(byte);
        packet_number = (packet_number << 8) | u64::from(byte);
    }

    Some(QuicUnprotectedHeader {
        header: unprotected,
        packet_number,
        ciphertext_offset: packet_number_end,
        payload_end: header.payload_end,
    })
}

fn decrypt_quic_initial_packet(
    packet: &[u8],
    header: &QuicUnprotectedHeader,
    keys: &QuicInitialKeys,
) -> Option<Vec<u8>> {
    let ciphertext = packet.get(header.ciphertext_offset..header.payload_end)?;
    let mut nonce = keys.iv;
    for (index, byte) in header.packet_number.to_be_bytes().iter().enumerate() {
        nonce[4 + index] ^= byte;
    }
    let cipher = Aes128Gcm::new_from_slice(&keys.key).ok()?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &header.header,
            },
        )
        .ok()
}

fn collect_quic_crypto_stream(plaintext: &[u8]) -> Option<Vec<u8>> {
    let mut offset = 0usize;
    let mut crypto_stream = Vec::new();
    let mut found_crypto = false;

    while offset < plaintext.len() {
        let frame_type = plaintext[offset];
        offset += 1;
        match frame_type {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                offset = skip_quic_ack_frame(plaintext, offset, frame_type == 0x03)?;
            }
            0x06 => {
                let (crypto_offset, used) = read_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(used)?;
                let (crypto_len, used) = read_quic_varint(plaintext, offset)?;
                offset = offset.checked_add(used)?;
                let crypto_offset = usize::try_from(crypto_offset).ok()?;
                let crypto_len = usize::try_from(crypto_len).ok()?;
                let data_end = offset.checked_add(crypto_len)?;
                let stream_end = crypto_offset.checked_add(crypto_len)?;
                if data_end > plaintext.len() || stream_end > QUIC_MAX_CRYPTO_STREAM_SIZE {
                    return None;
                }
                if crypto_stream.len() < stream_end {
                    crypto_stream.resize(stream_end, 0);
                }
                crypto_stream[crypto_offset..stream_end]
                    .copy_from_slice(&plaintext[offset..data_end]);
                offset = data_end;
                found_crypto = true;
            }
            _ => return None,
        }
    }

    found_crypto.then_some(crypto_stream)
}

fn skip_quic_ack_frame(plaintext: &[u8], mut offset: usize, has_ecn: bool) -> Option<usize> {
    let (_, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;
    let (_, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;
    let (range_count, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;
    let (_, used) = read_quic_varint(plaintext, offset)?;
    offset = offset.checked_add(used)?;

    for _ in 0..range_count {
        let (_, used) = read_quic_varint(plaintext, offset)?;
        offset = offset.checked_add(used)?;
        let (_, used) = read_quic_varint(plaintext, offset)?;
        offset = offset.checked_add(used)?;
    }

    if has_ecn {
        for _ in 0..3 {
            let (_, used) = read_quic_varint(plaintext, offset)?;
            offset = offset.checked_add(used)?;
        }
    }

    Some(offset)
}

fn aes128_encrypt_block(key: &[u8; QUIC_INITIAL_HP_LEN], block: &[u8]) -> Option<[u8; 16]> {
    let cipher = Aes128::new_from_slice(key).ok()?;
    let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(block);
    cipher.encrypt_block(&mut block);
    Some(block.into())
}

fn parse_tls_sni_extension(extension: &[u8]) -> Option<String> {
    let list_len = read_u16(extension, 0)? as usize;
    if list_len + 2 > extension.len() {
        return None;
    }
    let mut offset = 2;
    let list_end = 2 + list_len;
    while offset + 3 <= list_end {
        let name_type = *extension.get(offset)?;
        let name_len = read_u16(extension, offset + 1)? as usize;
        offset += 3;
        let name_end = offset.checked_add(name_len)?;
        if name_end > list_end {
            return None;
        }
        if name_type == 0 {
            let host = std::str::from_utf8(&extension[offset..name_end]).ok()?;
            return normalize_host(host);
        }
        offset = name_end;
    }
    None
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    if host.starts_with('[') {
        return None;
    }
    let host_without_port = strip_port(host);
    if host_without_port.is_empty() {
        return None;
    }
    if host_without_port.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host_without_port.to_ascii_lowercase())
}

fn strip_port(host: &str) -> &str {
    let Some((domain, port)) = host.rsplit_once(':') else {
        return host;
    };
    if domain.contains(':') || port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return host;
    }
    domain
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}

fn read_u24(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(
        (u32::from(*bytes.get(offset)?) << 16)
            | (u32::from(*bytes.get(offset + 1)?) << 8)
            | u32::from(*bytes.get(offset + 2)?),
    )
}

fn read_quic_varint(bytes: &[u8], offset: usize) -> Option<(u64, usize)> {
    let first = *bytes.get(offset)?;
    let len = 1usize << usize::from(first >> 6);
    let raw = bytes.get(offset..offset + len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &raw[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

fn tls13_hkdf_label(length: u16, label: &[u8]) -> Vec<u8> {
    let full_label_len = b"tls13 ".len() + label.len();
    let mut output = Vec::with_capacity(2 + 1 + full_label_len + 1);
    output.extend_from_slice(&length.to_be_bytes());
    output.push(full_label_len as u8);
    output.extend_from_slice(b"tls13 ");
    output.extend_from_slice(label);
    output.push(0);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_config::SniffingDestination;
    use xray_routing::Network;

    fn sniffing_config(route_only: bool) -> InboundSniffingConfig {
        InboundSniffingConfig {
            enabled: true,
            dest_override: vec![SniffingDestination::Http, SniffingDestination::Tls],
            metadata_only: false,
            route_only,
        }
    }

    fn original_ip_target() -> Target {
        Target::new(
            TargetAddr::Ip("127.0.0.1".parse().unwrap()),
            443,
            Network::Tcp,
        )
    }

    fn original_udp_target() -> Target {
        Target::new(
            TargetAddr::Ip("127.0.0.1".parse().unwrap()),
            443,
            Network::Udp,
        )
    }

    fn quic_sniffing_config(route_only: bool) -> InboundSniffingConfig {
        InboundSniffingConfig {
            enabled: true,
            dest_override: vec![SniffingDestination::Quic],
            metadata_only: false,
            route_only,
        }
    }

    #[test]
    fn sniffs_http_host_header() {
        let payload = b"GET / HTTP/1.1\r\nHost: Routed.Example:443\r\nUser-Agent: test\r\n\r\n";
        let sniffed =
            sniff_tcp_initial_payload(&sniffing_config(true), &original_ip_target(), payload)
                .expect("HTTP host should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("routed.example".to_owned())
        );
        assert_eq!(sniffed.protocol, SniffingDestination::Http);
    }

    #[test]
    fn sniffs_tls_client_hello_sni() {
        let payload = tls_client_hello_with_sni("tls.example");
        let sniffed =
            sniff_tcp_initial_payload(&sniffing_config(true), &original_ip_target(), &payload)
                .expect("TLS SNI should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("tls.example".to_owned())
        );
        assert_eq!(sniffed.protocol, SniffingDestination::Tls);
    }

    #[test]
    fn route_only_keeps_original_target_for_dialing() {
        let original = original_ip_target();
        let payload = b"GET / HTTP/1.1\r\nHost: routed.example\r\n\r\n";
        let sniffed = sniff_tcp_initial_payload(&sniffing_config(true), &original, payload)
            .expect("HTTP host should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("routed.example".to_owned())
        );
        assert_eq!(sniffed.dial_target, original);
    }

    #[test]
    fn rejects_empty_http_host_after_stripping_port() {
        let payload = b"GET / HTTP/1.1\r\nHost: :443\r\n\r\n";

        assert!(
            sniff_tcp_initial_payload(&sniffing_config(true), &original_ip_target(), payload)
                .is_none()
        );
    }

    #[test]
    fn non_route_only_replaces_dial_target() {
        let original = original_ip_target();
        let payload = b"GET / HTTP/1.1\r\nHost: routed.example\r\n\r\n";
        let sniffed = sniff_tcp_initial_payload(&sniffing_config(false), &original, payload)
            .expect("HTTP host should be sniffed");

        assert_eq!(sniffed.dial_target, sniffed.route_target);
    }

    #[test]
    fn sniffs_quic_initial_sni() {
        let payload = quic_initial_packet_with_sni("quic.example");
        let sniffed = sniff_udp_initial_payload(
            &quic_sniffing_config(true),
            &original_udp_target(),
            &payload,
        )
        .expect("QUIC SNI should be sniffed");

        assert_eq!(
            sniffed.route_target.addr,
            TargetAddr::Domain("quic.example".to_owned())
        );
        assert_eq!(sniffed.dial_target, original_udp_target());
        assert_eq!(sniffed.protocol, SniffingDestination::Quic);
    }

    #[test]
    fn rejects_non_v1_quic_initial_sni() {
        let mut payload = quic_initial_packet_with_sni("quic.example");
        payload[1..5].copy_from_slice(&2u32.to_be_bytes());

        assert!(sniff_udp_initial_payload(
            &quic_sniffing_config(true),
            &original_udp_target(),
            &payload
        )
        .is_none());
    }

    #[test]
    fn rejects_malformed_quic_initial_sni() {
        let payload = [0xc0, 0, 0, 0, 1, 8, 1, 2, 3];

        assert!(sniff_udp_initial_payload(
            &quic_sniffing_config(true),
            &original_udp_target(),
            &payload
        )
        .is_none());
    }

    fn tls_client_hello_handshake_with_sni(host: &str) -> Vec<u8> {
        let mut sni_entry = Vec::new();
        sni_entry.push(0);
        sni_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni_entry.extend_from_slice(host.as_bytes());

        let mut sni_extension = Vec::new();
        sni_extension.extend_from_slice(&((sni_entry.len()) as u16).to_be_bytes());
        sni_extension.extend_from_slice(&sni_entry);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni_extension.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni_extension);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = Vec::new();
        handshake.push(1);
        handshake.extend_from_slice(&[
            ((body.len() >> 16) & 0xff) as u8,
            ((body.len() >> 8) & 0xff) as u8,
            (body.len() & 0xff) as u8,
        ]);
        handshake.extend_from_slice(&body);
        handshake
    }

    fn tls_client_hello_with_sni(host: &str) -> Vec<u8> {
        let handshake = tls_client_hello_handshake_with_sni(host);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn quic_initial_packet_with_sni(host: &str) -> Vec<u8> {
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes128;
        use aes_gcm::aead::{Aead, Payload};
        use aes_gcm::{Aes128Gcm, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha256;

        const INITIAL_SALT: [u8; 20] = [
            0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
            0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
        ];

        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let scid = [0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];
        let packet_number = 0u64;
        let packet_number_len = 1usize;

        let mut plaintext = Vec::new();
        let handshake = tls_client_hello_handshake_with_sni(host);
        plaintext.push(0x06);
        encode_quic_varint(0, &mut plaintext);
        encode_quic_varint(handshake.len() as u64, &mut plaintext);
        plaintext.extend_from_slice(&handshake);

        let initial_secret = {
            let hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), &dcid);
            let mut secret = [0u8; 32];
            hk.expand(&hkdf_label(32, b"client in"), &mut secret)
                .expect("initial secret label is valid");
            secret
        };
        let hk = Hkdf::<Sha256>::from_prk(&initial_secret).expect("initial secret is valid");
        let mut key = [0u8; 16];
        hk.expand(&hkdf_label(16, b"quic key"), &mut key)
            .expect("key label is valid");
        let mut iv = [0u8; 12];
        hk.expand(&hkdf_label(12, b"quic iv"), &mut iv)
            .expect("iv label is valid");
        let mut hp = [0u8; 16];
        hk.expand(&hkdf_label(16, b"quic hp"), &mut hp)
            .expect("hp label is valid");

        let mut header = Vec::new();
        header.push(0xc0);
        header.extend_from_slice(&1u32.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(&dcid);
        header.push(scid.len() as u8);
        header.extend_from_slice(&scid);
        encode_quic_varint(0, &mut header);
        encode_quic_varint(
            packet_number_len as u64 + plaintext.len() as u64 + 16,
            &mut header,
        );
        let packet_number_offset = header.len();
        header.push(packet_number as u8);

        let mut nonce = iv;
        for (index, byte) in packet_number.to_be_bytes().iter().enumerate() {
            nonce[4 + index] ^= byte;
        }
        let cipher = Aes128Gcm::new_from_slice(&key).expect("key length is valid");
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .expect("fixture encryption should succeed");

        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        let sample_offset = packet_number_offset + 4;
        let mask = {
            let cipher = Aes128::new_from_slice(&hp).expect("hp key length is valid");
            let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(
                &packet[sample_offset..sample_offset + 16],
            );
            cipher.encrypt_block(&mut block);
            block
        };
        packet[0] ^= mask[0] & 0x0f;
        for index in 0..packet_number_len {
            packet[packet_number_offset + index] ^= mask[index + 1];
        }
        packet
    }

    fn encode_quic_varint(value: u64, output: &mut Vec<u8>) {
        if value < 64 {
            output.push(value as u8);
        } else if value < 16_384 {
            let encoded = (value as u16) | 0x4000;
            output.extend_from_slice(&encoded.to_be_bytes());
        } else {
            panic!("test varint value is too large: {value}");
        }
    }

    fn hkdf_label(length: u16, label: &[u8]) -> Vec<u8> {
        let full_label_len = b"tls13 ".len() + label.len();
        let mut output = Vec::with_capacity(2 + 1 + full_label_len + 1);
        output.extend_from_slice(&length.to_be_bytes());
        output.push(full_label_len as u8);
        output.extend_from_slice(b"tls13 ");
        output.extend_from_slice(label);
        output.push(0);
        output
    }
}
