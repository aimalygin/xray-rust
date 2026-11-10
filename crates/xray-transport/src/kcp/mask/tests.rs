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
            segments: Vec::new(),
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
            if let Some(password) = name.strip_prefix("salamander:") {
                return KcpMask::Salamander(password.to_owned().into());
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
    wire_at(masks, datagram, Instant::now())
}

fn peer() -> SocketAddr {
    "127.0.0.1:12345".parse().unwrap()
}

fn wire_at(masks: &mut Masks, datagram: Vec<u8>, now: Instant) -> Vec<Vec<u8>> {
    masks.start(datagram);
    let mut sent = Vec::new();
    while let Some(action) = masks.next(now, None, peer()) {
        match action {
            Action::Send(packet) => sent.push(packet),
            Action::Pause(_) => {}
            Action::Wait => panic!("unexpected handshake"),
        }
    }
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
        let mut masks = masks(&read["masks"]);
        let mut incoming = hex(read["incoming"].as_str().unwrap());
        let payload = masks
            .open(&mut incoming, peer(), Instant::now())
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
    let range = masks.open(&mut sent, peer(), Instant::now()).unwrap();
    assert_eq!(&sent[range], b"segment");
    // A different value cannot open it, nor can a flipped bit.
    let mut other = Masks::new(&[KcpMask::Aes128Gcm("other".to_owned().into())], None).unwrap();
    let mut again = wire(&mut masks, b"segment".to_vec()).remove(0);
    assert!(other
        .open(&mut again.clone(), peer(), Instant::now())
        .is_none());
    again[20] ^= 1;
    assert!(masks.open(&mut again, peer(), Instant::now()).is_none());
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
    let mut masks = Masks::new(&[KcpMask::Original], None).unwrap();
    assert!(masks.open(&mut region, peer(), Instant::now()).is_none());
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
    let send =
        |masks: &mut Masks, at: Duration| wire_at(masks, b"d".to_vec(), start + at).len() - 1;
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

/// `exp` noise is built only when its turn comes: its counter runs in the
/// items' order and across resets, as Xray-core's per-connection counter.
#[test]
fn exp_noise_counts_in_item_order_and_across_resets() {
    use crate::udp_noise::NoiseSegment;
    let item = |tag: u8| UdpNoiseItem {
        packet: Vec::new(),
        random_length: none(),
        random_bytes: none(),
        delay_ms: NoiseRange { from: 1, to: 1 },
        segments: vec![NoiseSegment::Bytes(vec![tag]), NoiseSegment::Counter],
    };
    let config = UdpNoiseConfig {
        items: vec![item(0xa), item(0xb)],
        reset_secs: NoiseRange { from: 5, to: 5 },
        before_salamander: false,
    };
    let mut masks = Masks::new(&[KcpMask::Noise], Some(&config)).unwrap();
    let start = Instant::now();
    let first = wire_at(&mut masks, b"d".to_vec(), start);
    assert_eq!(
        first
            .iter()
            .map(|packet| to_hex(packet))
            .collect::<Vec<_>>(),
        ["0a00000001", "0b00000002", "64"]
    );
    let again = wire_at(&mut masks, b"d".to_vec(), start + Duration::from_secs(6));
    assert_eq!(
        again
            .iter()
            .map(|packet| to_hex(packet))
            .collect::<Vec<_>>(),
        ["0a00000003", "0b00000004", "64"]
    );
}

fn custom(standalone: bool) -> KcpMask {
    use crate::header_custom::{CustomItem, HeaderCustomUdpConfig};
    let item = CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: b"HC".to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    };
    KcpMask::HeaderCustom(std::sync::Arc::new(HeaderCustomUdpConfig {
        standalone,
        client: vec![item.clone()],
        server: vec![item],
    }))
}

#[test]
fn custom_prefix_and_noise_keep_array_order() {
    let mut inner = Masks::new(&[custom(false), KcpMask::Noise], Some(&noise())).unwrap();
    assert_eq!(
        wire(&mut inner, b"p".to_vec()),
        [b"NZ".to_vec(), b"HCp".to_vec()]
    );
    let mut outer = Masks::new(&[KcpMask::Noise, custom(false)], Some(&noise())).unwrap();
    assert_eq!(
        wire(&mut outer, b"p".to_vec()),
        [b"HCNZ".to_vec(), b"HCp".to_vec()]
    );
    let mut incoming = b"HCp".to_vec();
    assert_eq!(
        outer.open(&mut incoming, peer(), Instant::now()),
        Some(2..3)
    );
}

#[test]
fn standalone_exchanges_traverse_only_masks_after_the_header() {
    for before_noise in [false, true] {
        let ordered = if before_noise {
            vec![KcpMask::Noise, custom(true), KcpMask::Original]
        } else {
            vec![custom(true), KcpMask::Noise, KcpMask::Original]
        };
        let now = Instant::now();
        let mut masks = Masks::new(&ordered, Some(&noise())).unwrap();
        let mut outer = Masks::new(&[KcpMask::Original], None).unwrap();
        masks.start(b"payload".to_vec());
        let mut before = Vec::new();
        loop {
            match masks.next(now, None, peer()).unwrap() {
                Action::Send(mut packet) => {
                    let range = outer.open(&mut packet, peer(), now).unwrap();
                    before.push(packet[range].to_vec());
                }
                Action::Pause(_) => {}
                Action::Wait => break,
            }
        }
        let expected = if before_noise {
            vec![b"HC".to_vec()]
        } else {
            vec![b"NZ".to_vec(), b"HC".to_vec()]
        };
        assert_eq!(before, expected);
        let mut reply = wire(&mut outer, b"HC".to_vec()).remove(0);
        assert!(masks.open(&mut reply, peer(), now).is_none());
        let mut after = Vec::new();
        while let Some(action) = masks.next(now, None, peer()) {
            match action {
                Action::Send(mut packet) => {
                    let range = outer.open(&mut packet, peer(), now).unwrap();
                    after.push(packet[range].to_vec());
                }
                Action::Pause(_) => {}
                Action::Wait => panic!("completed handshake waited again"),
            }
        }
        let expected = if before_noise {
            vec![b"NZ".to_vec(), b"payload".to_vec()]
        } else {
            vec![b"payload".to_vec()]
        };
        assert_eq!(after, expected);
    }
}

#[test]
fn standalone_receive_buffer_matches_xrays_4096_byte_limit() {
    let mut masks = Masks::new(&[custom(true)], None).unwrap();
    let mut packet = vec![0; 5000];
    assert_eq!(
        masks.open(&mut packet, peer(), Instant::now()),
        Some(0..4096)
    );
    // A prefix reads all the carrier received.
    let mut masks = Masks::new(&[custom(false)], None).unwrap();
    let mut packet = vec![0; 5000];
    packet[..2].copy_from_slice(b"HC");
    assert_eq!(
        masks.open(&mut packet, peer(), Instant::now()),
        Some(2..5000)
    );
}

#[test]
fn sudoku_encodes_each_datagram_and_drops_what_does_not_decode() {
    let config = crate::sudoku::SudokuConfig {
        password: "synthetic".into(),
        ..Default::default()
    };
    let sudoku = KcpMask::Sudoku(std::sync::Arc::new(config));
    // Inside the original mask: its checksum covers sudoku's bytes.
    let mut masks = Masks::new(&[sudoku.clone(), KcpMask::Original], None).unwrap();
    let mut sent = wire(&mut masks, b"segment".to_vec()).remove(0);
    assert!(sent.len() >= 4 + 7 * 4);
    let range = masks.open(&mut sent, peer(), Instant::now()).unwrap();
    assert_eq!(&sent[range], b"segment");
    // Without padding every byte is four clues: a datagram cut by one
    // ends in an unfinished tuple and is dropped, as one that is not sudoku.
    let mut alone = Masks::new(&[sudoku], None).unwrap();
    let datagram = wire(&mut alone, b"segment".to_vec()).remove(0);
    assert_eq!(datagram.len(), 7 * 4);
    let mut short = datagram[..datagram.len() - 1].to_vec();
    assert!(alone.open(&mut short, peer(), Instant::now()).is_none());
    let mut whole = datagram.clone();
    let range = alone.open(&mut whole, peer(), Instant::now()).unwrap();
    assert_eq!(&whole[range], b"segment");
    let mut garbage = vec![0x41; 8];
    assert!(alone.open(&mut garbage, peer(), Instant::now()).is_none());
}

/// What Salamander puts on the wire opens again: a random salt each time and
/// the payload behind it, XORed with the key the password and salt derive.
#[test]
fn salamander_salts_every_datagram_and_opens_its_own() {
    let mut masks =
        Masks::new(&[KcpMask::Salamander("synthetic".to_owned().into())], None).unwrap();
    let first = wire(&mut masks, b"datagram".to_vec());
    let second = wire(&mut masks, b"datagram".to_vec());
    assert_eq!(first[0].len(), 8 + 8);
    assert_ne!(
        first[0][..8],
        second[0][..8],
        "a fresh salt for each datagram"
    );
    for mut datagram in [first[0].clone(), second[0].clone()] {
        let range = masks.open(&mut datagram, peer(), Instant::now()).unwrap();
        assert_eq!(&datagram[range], b"datagram");
    }
    assert!(Masks::new(&[KcpMask::Salamander("abc".to_owned().into())], None).is_err());
}

/// An AES mask takes its tag as well as its nonce, so what it leaves for the
/// masks inside it can be shorter than they need. A peer that knows the
/// password sends such a datagram; it is dropped, not unwrapped.
#[test]
fn a_datagram_too_short_for_the_masks_inside_aes_is_dropped() {
    for inner in ["original", "dtls", "salamander:seed"] {
        let mut victim = masks(&serde_json::json!([inner, "aes:seed"]));
        let mut peer_side =
            Masks::new(&[KcpMask::Aes128Gcm("seed".to_owned().into())], None).unwrap();
        for plaintext in [&b""[..], &b"abc"[..], &b"abcde"[..]] {
            let mut datagram = wire(&mut peer_side, plaintext.to_vec()).remove(0);
            assert!(
                victim.open(&mut datagram, peer(), Instant::now()).is_none(),
                "{inner} inside aes, {} bytes",
                plaintext.len()
            );
        }
    }
}
