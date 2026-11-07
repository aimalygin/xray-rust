//! The masks against what Xray-core v26.10.31's own finalmask code does,
//! recorded by `tools/kcp-oracle`.
use super::*;
use crate::udp_noise::{NoiseRange, UdpNoiseItem};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/kcp/mask-vectors.json"
    ))
    .unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn none() -> NoiseRange {
    NoiseRange { from: 0, to: 0 }
}

/// The oracle's noise: one fixed packet, no pause, sent once.
fn noise() -> UdpNoiseConfig {
    UdpNoiseConfig {
        items: vec![UdpNoiseItem {
            packet: b"NZ".to_vec(),
            random_length: none(),
            random_bytes: none(),
            delay_ms: none(),
        }],
        reset_secs: none(),
        before_salamander: false,
    }
}

fn masks(names: &Value) -> Masks {
    let masks: Vec<KcpMask> = names
        .as_array()
        .unwrap()
        .iter()
        .map(|name| {
            let name = name.as_str().unwrap();
            if let Some(password) = name.strip_prefix("aes:") {
                return KcpMask::Aes128Gcm(password.to_owned().into());
            }
            if let Some(domain) = name.strip_prefix("dns:") {
                return KcpMask::Header(KcpHeader::Dns(domain.to_owned()));
            }
            match name {
                "original" => KcpMask::Original,
                "noise" => KcpMask::Noise,
                "dtls" => KcpMask::Header(KcpHeader::Dtls),
                "srtp" => KcpMask::Header(KcpHeader::Srtp),
                "utp" => KcpMask::Header(KcpHeader::Utp),
                "wechat" => KcpMask::Header(KcpHeader::Wechat),
                "wireguard" => KcpMask::Header(KcpHeader::Wireguard),
                other => panic!("unknown mask {other}"),
            }
        })
        .collect();
    Masks::new(&masks, Some(&noise())).unwrap()
}

/// What goes on the wire for `datagram`, noise first.
fn wire(masks: &mut Masks, datagram: Vec<u8>) -> Vec<Vec<u8>> {
    let now = Instant::now();
    let Some(wrapped) = masks.wrap(datagram, now) else {
        return Vec::new();
    };
    masks.sent(now);
    let mut sent: Vec<Vec<u8>> = wrapped
        .noise
        .into_iter()
        .filter_map(|(noise, _)| noise)
        .collect();
    sent.extend(wrapped.datagram);
    sent
}

#[test]
fn every_write_puts_on_the_wire_what_xray_puts() {
    let vectors = vectors();
    let mut connection = (0, None);
    for write in vectors["writes"].as_array().unwrap() {
        let id = write["connection"].as_u64().unwrap();
        if connection.0 != id {
            connection = (id, Some(masks(&write["masks"])));
        }
        let masks = connection.1.as_mut().unwrap();
        let sent = wire(masks, hex(write["payload"].as_str().unwrap()));
        let expected: Vec<&str> = write["sent"]
            .as_array()
            .map(|sent| sent.iter().map(|s| s.as_str().unwrap()).collect())
            .unwrap_or_default();
        let actual: Vec<String> = sent
            .iter()
            .zip(expected.iter().chain(std::iter::repeat(&"")))
            .map(|(datagram, expected)| {
                // The AES nonce is random: compare its length only.
                if expected.starts_with("len:") {
                    format!("len:{}", datagram.len())
                } else {
                    to_hex(datagram)
                }
            })
            .collect();
        assert_eq!(actual, expected, "{} {}", write["masks"], write["payload"]);
    }
}

#[test]
fn every_dns_header_packs_as_xray_packs_it() {
    for case in vectors()["dns"].as_array().unwrap() {
        let domain = case["domain"].as_str().unwrap();
        match (dns_header(domain), case["header"].as_str()) {
            (Ok(mut header), Some(expected)) => {
                header[0] = 0;
                header[1] = 0;
                assert_eq!(to_hex(&header), expected, "{domain:?}");
            }
            (Err(error), None) => {
                // Xray panics past its buffer; this says so instead.
                let expected = match case["error"].as_str().unwrap() {
                    "panic" => "buffer size too small",
                    other => other,
                };
                assert_eq!(error.to_string(), expected, "{domain:?}");
            }
            (result, expected) => panic!("{domain:?}: {result:?} against {expected:?}"),
        }
    }
}

#[test]
fn every_read_unwraps_as_xray_unwraps_it() {
    for read in vectors()["reads"].as_array().unwrap() {
        let masks = masks(&read["masks"]);
        let mut incoming = hex(read["incoming"].as_str().unwrap());
        let payload = masks
            .open(&mut incoming)
            .map(|range| to_hex(&incoming[range]));
        assert_eq!(
            payload.as_deref(),
            read["payload"].as_str(),
            "{} {}",
            read["masks"],
            read["incoming"]
        );
    }
}

#[test]
fn an_aes_datagram_opens_to_what_was_sealed() {
    let mut masks = masks(&serde_json::json!(["aes:seed"]));
    let mut sent = wire(&mut masks, b"segment".to_vec()).remove(0);
    assert_eq!(sent.len(), 12 + 7 + 16);
    let range = masks.open(&mut sent).unwrap();
    assert_eq!(&sent[range], b"segment");
    // A different value cannot open it, nor can a flipped bit.
    let other = Masks::new(&[KcpMask::Aes128Gcm("other".to_owned().into())], None).unwrap();
    let mut again = wire(&mut masks, b"segment".to_vec()).remove(0);
    assert!(other.open(&mut again.clone()).is_none());
    again[20] ^= 1;
    assert!(masks.open(&mut again).is_none());
    // The nonce is fresh every time.
    let first = wire(&mut masks, b"x".to_vec()).remove(0);
    let second = wire(&mut masks, b"x".to_vec()).remove(0);
    assert_ne!(first[..12], second[..12]);
}

/// A checksum over a wrong length still fails: the original mask checks the
/// length after the checksum.
#[test]
fn the_original_mask_checks_the_length_too() {
    let payload = b"segment";
    let mut region = vec![0; ORIGINAL];
    region.extend_from_slice(payload);
    region[4..6].copy_from_slice(&(payload.len() as u16 + 1).to_be_bytes());
    let hash = fnv1a(&region[4..]);
    region[..4].copy_from_slice(&hash.to_be_bytes());
    for i in 4..region.len() {
        region[i] ^= region[i - 4];
    }
    let masks = Masks::new(&[KcpMask::Original], None).unwrap();
    assert!(masks.open(&mut region).is_none());
}

#[test]
fn noise_needs_its_settings_and_comes_once() {
    assert!(Masks::new(&[KcpMask::Noise], None).is_err());
    assert!(Masks::new(&[KcpMask::Noise, KcpMask::Noise], Some(&noise())).is_err());
    assert!(Masks::new(&[], None).is_ok());
    let dns = KcpMask::Header(KcpHeader::Dns(format!("{}.b", "a".repeat(64))));
    assert!(Masks::new(&[dns], None).is_err());
}

#[test]
fn noise_comes_back_after_the_connection_idles_past_its_reset() {
    let mut config = noise();
    config.reset_secs = NoiseRange { from: 5, to: 5 };
    let mut masks = Masks::new(&[KcpMask::Noise], Some(&config)).unwrap();
    let start = Instant::now();
    let send = |masks: &mut Masks, at: Duration| {
        let wrapped = masks.wrap(b"d".to_vec(), start + at).unwrap();
        masks.sent(start + at);
        wrapped.noise.len()
    };
    assert_eq!(send(&mut masks, Duration::ZERO), 1);
    assert_eq!(send(&mut masks, Duration::from_secs(5)), 0);
    // Each datagram pushes the reset out again.
    assert_eq!(send(&mut masks, Duration::from_secs(10)), 0);
    assert_eq!(send(&mut masks, Duration::from_millis(15_001)), 1);
    // Without a reset, noise goes out once.
    let mut once = Masks::new(&[KcpMask::Noise], Some(&noise())).unwrap();
    assert_eq!(send(&mut once, Duration::ZERO), 1);
    assert_eq!(send(&mut once, Duration::from_secs(3600)), 0);
}
