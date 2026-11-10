//! A QUIC client's first flight, taken apart off the wire, and the shape
//! Xray-core's ChromeParrot gives it.
//!
//! Shared by the live Hysteria (`xray-transport`) and XHTTP H3
//! (`xray-core-rs`) interoperability tests: a [`RecordingRelay`] sits between
//! the client and the pinned Xray server and keeps every datagram the client
//! sends; [`assert_chrome_first_flight`] decrypts the Initial packets with the
//! keys their destination connection ID derives (RFC 9001 section 5.2) and
//! checks what quic-go's ChromeParrot and uTLS's Chrome QUIC spec put there.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::net::UdpSocket;

/// Forwards one client's datagrams to `upstream` and back, keeping a copy of
/// every datagram the client sends.
pub struct RecordingRelay {
    pub address: SocketAddr,
    datagrams: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}

impl RecordingRelay {
    pub async fn start(upstream: SocketAddr) -> Self {
        let front = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let back = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        back.connect(upstream).await.unwrap();
        let address = front.local_addr().unwrap();
        let datagrams = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&datagrams);
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut forward = vec![0; 65_536];
            let mut backward = vec![0; 65_536];
            loop {
                tokio::select! {
                    received = front.recv_from(&mut forward) => {
                        let Ok((len, source)) = received else { return };
                        client = Some(source);
                        recorded.lock().unwrap().push(forward[..len].to_vec());
                        let _ = back.send(&forward[..len]).await;
                    }
                    received = back.recv(&mut backward) => {
                        let Ok(len) = received else { continue };
                        if let Some(client) = client {
                            let _ = front.send_to(&backward[..len], client).await;
                        }
                    }
                }
            }
        });
        Self {
            address,
            datagrams,
            task,
        }
    }

    /// The client's datagrams since the last call
    pub fn take(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut *self.datagrams.lock().unwrap())
    }
}

impl Drop for RecordingRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Padding(usize),
    Ping,
    Ack,
    Crypto { offset: u64, data: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct Initial {
    pub datagram_len: usize,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub token_len: usize,
    pub packet_number: u64,
    pub packet_number_len: usize,
    pub frames: Vec<Frame>,
}

fn varint(bytes: &mut &[u8]) -> Result<u64, String> {
    let first = *bytes.first().ok_or("truncated varint")?;
    let len = 1 << (first >> 6);
    if bytes.len() < len {
        return Err("truncated varint".into());
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = value << 8 | u64::from(*byte);
    }
    *bytes = &bytes[len..];
    Ok(value)
}

fn varint_len(first: u8) -> usize {
    1 << (first >> 6)
}

/// Decrypts a datagram holding one client Initial packet.
pub fn decrypt_initial(datagram: &[u8]) -> Result<Initial, String> {
    if datagram.len() < 7 || datagram[0] & 0xf0 != 0xc0 {
        return Err(format!("not an Initial: first byte {:#04x}", datagram[0]));
    }
    let version = u32::from_be_bytes(datagram[1..5].try_into().unwrap());
    let mut p = 5;
    let dcid = datagram[p + 1..p + 1 + usize::from(datagram[p])].to_vec();
    p += 1 + dcid.len();
    let scid = datagram[p + 1..p + 1 + usize::from(datagram[p])].to_vec();
    p += 1 + scid.len();
    let mut rest = &datagram[p..];
    let token_len = varint(&mut rest)? as usize;
    rest = &rest[token_len..];
    let length = varint(&mut rest)? as usize;
    let pn_offset = datagram.len() - rest.len();
    if pn_offset + length != datagram.len() {
        return Err(format!(
            "one packet per datagram expected: {pn_offset} + {length} != {}",
            datagram.len()
        ));
    }

    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .quic_suite()
        .unwrap();
    let keys = rustls::quic::Keys::initial(
        rustls::quic::Version::V1,
        suite.suite,
        suite.quic,
        &dcid,
        rustls::Side::Server,
    );
    let mut packet = datagram.to_vec();
    let sample = packet[pn_offset + 4..pn_offset + 20].to_vec();
    let (head, tail) = packet.split_at_mut(pn_offset);
    keys.remote
        .header
        .decrypt_in_place(&sample, &mut head[0], &mut tail[..4])
        .map_err(|e| format!("header protection: {e}"))?;
    let packet_number_len = usize::from(packet[0] & 0x03) + 1;
    let mut packet_number = 0;
    for byte in &packet[pn_offset..pn_offset + packet_number_len] {
        packet_number = packet_number << 8 | u64::from(*byte);
    }
    let header_len = pn_offset + packet_number_len;
    let (header, payload) = packet.split_at_mut(header_len);
    let payload = keys
        .remote
        .packet
        .decrypt_in_place(packet_number, header, payload)
        .map_err(|e| format!("decrypt: {e}"))?
        .to_vec();

    let mut frames = Vec::new();
    let mut rest = payload.as_slice();
    while let Some(&kind) = rest.first() {
        match kind {
            0x00 => {
                let run = rest.iter().take_while(|b| **b == 0).count();
                frames.push(Frame::Padding(run));
                rest = &rest[run..];
            }
            0x01 => {
                frames.push(Frame::Ping);
                rest = &rest[1..];
            }
            0x02 | 0x03 => {
                rest = &rest[1..];
                let _largest = varint(&mut rest)?;
                let _delay = varint(&mut rest)?;
                let ranges = varint(&mut rest)?;
                let _first = varint(&mut rest)?;
                for _ in 0..ranges {
                    varint(&mut rest)?;
                    varint(&mut rest)?;
                }
                if kind == 0x03 {
                    for _ in 0..3 {
                        varint(&mut rest)?;
                    }
                }
                frames.push(Frame::Ack);
            }
            0x06 => {
                rest = &rest[1..];
                let offset = varint(&mut rest)?;
                let len = varint(&mut rest)? as usize;
                frames.push(Frame::Crypto {
                    offset,
                    data: rest[..len].to_vec(),
                });
                rest = &rest[len..];
            }
            other => return Err(format!("unexpected frame type {other:#04x}")),
        }
    }
    Ok(Initial {
        datagram_len: datagram.len(),
        version,
        dcid,
        scid,
        token_len,
        packet_number,
        packet_number_len,
        frames,
    })
}

/// The client's Initial packets that carry its ClientHello, and the
/// ClientHello. The flight starts at the first Initial with CRYPTO data at
/// offset 0, which skips what an earlier connection sent late, and ends at
/// the first datagram that is not an Initial of the same connection.
pub fn first_flight(datagrams: &[Vec<u8>]) -> Result<(Vec<Initial>, Vec<u8>), String> {
    let starts_flight = |initial: &Initial| {
        initial
            .frames
            .iter()
            .any(|frame| matches!(frame, Frame::Crypto { offset: 0, .. }))
    };
    let start = datagrams
        .iter()
        .position(|datagram| decrypt_initial(datagram).is_ok_and(|i| starts_flight(&i)))
        .ok_or("no Initial with the start of a ClientHello")?;
    let mut initials = Vec::new();
    let mut pieces = BTreeMap::new();
    for datagram in &datagrams[start..] {
        let Ok(initial) = decrypt_initial(datagram) else {
            break;
        };
        if initials
            .first()
            .is_some_and(|first: &Initial| first.dcid != initial.dcid)
        {
            break;
        }
        let mut carries_crypto = false;
        for frame in &initial.frames {
            if let Frame::Crypto { offset, data } = frame {
                carries_crypto = true;
                let entry = pieces.entry(*offset).or_insert_with(Vec::new);
                if data.len() > entry.len() {
                    *entry = data.clone();
                }
            }
        }
        if !carries_crypto {
            break;
        }
        initials.push(initial);
        if let Some(hello) = reassemble(&pieces) {
            return Ok((initials, hello));
        }
    }
    Err(format!(
        "no complete ClientHello in the first {} Initial datagrams",
        initials.len()
    ))
}

fn reassemble(pieces: &BTreeMap<u64, Vec<u8>>) -> Option<Vec<u8>> {
    let mut hello = Vec::new();
    for (offset, data) in pieces {
        let offset = usize::try_from(*offset).ok()?;
        if offset > hello.len() {
            return None;
        }
        if offset + data.len() > hello.len() {
            hello.extend_from_slice(&data[hello.len() - offset..]);
        }
    }
    if hello.len() < 4 || hello[0] != 1 {
        return None;
    }
    let total =
        4 + (usize::from(hello[1]) << 16 | usize::from(hello[2]) << 8 | usize::from(hello[3]));
    (hello.len() == total).then_some(hello)
}

pub struct ClientHello {
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub extensions: Vec<(u16, Vec<u8>)>,
}

pub fn parse_client_hello(hello: &[u8]) -> ClientHello {
    let mut p = 4 + 2 + 32;
    let session_id = hello[p + 1..p + 1 + usize::from(hello[p])].to_vec();
    p += 1 + session_id.len();
    let suites_len = usize::from(u16::from_be_bytes([hello[p], hello[p + 1]]));
    let cipher_suites = hello[p + 2..p + 2 + suites_len]
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect();
    p += 2 + suites_len;
    let compression = hello[p + 1..p + 1 + usize::from(hello[p])].to_vec();
    p += 1 + compression.len();
    let end = p + 2 + usize::from(u16::from_be_bytes([hello[p], hello[p + 1]]));
    p += 2;
    let mut extensions = Vec::new();
    while p < end {
        let typ = u16::from_be_bytes([hello[p], hello[p + 1]]);
        let len = usize::from(u16::from_be_bytes([hello[p + 2], hello[p + 3]]));
        extensions.push((typ, hello[p + 4..p + 4 + len].to_vec()));
        p += 4 + len;
    }
    assert_eq!(p, hello.len(), "the extensions end the ClientHello");
    ClientHello {
        session_id,
        cipher_suites,
        compression,
        extensions,
    }
}

pub fn transport_parameters(data: &[u8]) -> Vec<(u64, Vec<u8>)> {
    let mut rest = data;
    let mut params = Vec::new();
    while !rest.is_empty() {
        let first = rest[0];
        let id = varint(&mut rest).unwrap();
        let id_len = varint_len(first);
        let len = varint(&mut rest).unwrap() as usize;
        let mut value = rest[..len].to_vec();
        rest = &rest[len..];
        // Mark an 8-byte identifier, which the GREASE parameter uses.
        if id_len == 8 {
            value.insert(0, 0xff);
        }
        params.push((id, value));
    }
    params
}

fn varint_value(value: &[u8]) -> u64 {
    let mut rest = value;
    let parsed = varint(&mut rest).unwrap();
    assert!(rest.is_empty(), "one varint");
    parsed
}

const CHROME_EXTENSIONS: [u16; 11] = [
    0x0000, 0x000a, 0x000d, 0x0010, 0x001b, 0x002b, 0x002d, 0x0033, 0x0039, 0x44cd, 0xfe0d,
];

/// Checks a first flight against Xray-core's ChromeParrot: 1250-byte Initial
/// datagrams from zero-length source to 8-byte destination connection IDs,
/// numbered from 1, chaos-protected, a large ClientHello's head and tail
/// first, uTLS's Chrome QUIC ClientHello and Chrome's transport parameters.
pub fn assert_chrome_first_flight(datagrams: &[Vec<u8>], alpn: &[u8]) {
    let (initials, hello) = first_flight(datagrams).unwrap();
    for (index, initial) in initials.iter().enumerate() {
        assert_eq!(initial.datagram_len, 1250, "datagram {index}");
        assert_eq!(initial.version, 1);
        assert_eq!(initial.dcid.len(), 8, "an 8-byte first destination ID");
        assert!(initial.scid.is_empty(), "zero-length source IDs");
        assert_eq!(initial.token_len, 0);
        assert_eq!(initial.packet_number, index as u64 + 1, "numbered from 1");
        let pings = initial.frames.iter().filter(|f| **f == Frame::Ping).count();
        assert!(
            pings >= 2,
            "chaos protection mixes in PINGs: {:?}",
            initial.frames
        );
        assert_eq!(initial.dcid, initials[0].dcid);
    }
    assert_eq!(initials[0].packet_number_len, 1);
    if initials.len() > 1 {
        // The room the first Initial left sizes the congestion window in
        // packets: over 64 of them, so two bytes.
        assert_eq!(initials[1].packet_number_len, 2);
        // The head (55..86 bytes) and the tail ride in the first packet.
        let mut covered: Vec<(u64, u64)> = initials[0]
            .frames
            .iter()
            .filter_map(|f| match f {
                Frame::Crypto { offset, data } => Some((*offset, *offset + data.len() as u64)),
                _ => None,
            })
            .collect();
        covered.sort();
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (start, end) in covered {
            match merged.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => merged.push((start, end)),
            }
        }
        assert_eq!(merged.len(), 2, "head and tail: {merged:?}");
        assert_eq!(merged[0].0, 0);
        assert!((55..=86).contains(&merged[0].1), "head length {merged:?}");
        assert_eq!(
            merged[1].1,
            hello.len() as u64,
            "the tail ends the ClientHello"
        );
    }

    let hello = parse_client_hello(&hello);
    assert!(hello.session_id.is_empty());
    assert_eq!(hello.cipher_suites, [0x1301, 0x1302, 0x1303]);
    assert_eq!(hello.compression, [0]);
    let types: BTreeSet<u16> = hello.extensions.iter().map(|(t, _)| *t).collect();
    let expected: BTreeSet<u16> = CHROME_EXTENSIONS.into_iter().collect();
    // An IP literal carries no server name, there or in uTLS.
    let without_sni: BTreeSet<u16> = expected.iter().copied().filter(|t| *t != 0).collect();
    assert!(types == expected || types == without_sni, "{types:x?}");
    let extension = |typ: u16| {
        hello
            .extensions
            .iter()
            .find(|(t, _)| *t == typ)
            .map(|(_, data)| data.clone())
            .unwrap()
    };
    assert_eq!(
        extension(0x000a),
        [0x00, 0x08, 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]
    );
    assert_eq!(
        extension(0x000d),
        [
            0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
            0x08, 0x06, 0x06, 0x01, 0x02, 0x01
        ]
    );
    let mut protocols = vec![0, alpn.len() as u8 + 1, alpn.len() as u8];
    protocols.extend_from_slice(alpn);
    assert_eq!(extension(0x0010), protocols, "ALPN");
    assert_eq!(extension(0x44cd), protocols, "ALPS");
    assert_eq!(extension(0x001b), [0x02, 0x00, 0x02], "brotli");
    assert_eq!(extension(0x002b), [0x02, 0x03, 0x04]);
    assert_eq!(extension(0x002d), [0x01, 0x01]);
    let shares = extension(0x0033);
    assert_eq!(
        &shares[2..6],
        [0x11, 0xec, 0x04, 0xc0],
        "X25519MLKEM768, 1216 bytes"
    );
    assert_eq!(&shares[6 + 1216..6 + 1216 + 4], [0x00, 0x1d, 0x00, 0x20]);
    let ech = extension(0xfe0d);
    assert_eq!(
        &ech[..5],
        [0x00, 0x00, 0x01, 0x00, 0x01],
        "outer, HKDF-SHA256, AES-128-GCM"
    );
    assert_eq!(&ech[6..8], [0x00, 0x20]);
    let payload = usize::from(u16::from_be_bytes([ech[40], ech[41]]));
    assert!([144, 176, 208, 240].contains(&payload), "{payload}");
    assert_eq!(ech.len(), 42 + payload);

    let params = transport_parameters(&extension(0x0039));
    assert_eq!(params.len(), 13, "{params:x?}");
    let mut seen = BTreeSet::new();
    for (id, value) in &params {
        match id {
            0x01 => assert_eq!(varint_value(value), 30_000),
            0x03 => assert_eq!(varint_value(value), 1472),
            0x04 => assert_eq!(varint_value(value), 15_728_640),
            0x05..=0x07 => assert_eq!(varint_value(value), 6_291_456),
            0x08 => assert_eq!(varint_value(value), 100),
            0x09 => assert_eq!(varint_value(value), 103),
            0x0f => assert!(value.is_empty()),
            0x11 => {
                assert_eq!(value.len(), 12);
                assert_eq!(value[..4], [0, 0, 0, 1]);
                let mut versions = [value[4..8].to_vec(), value[8..].to_vec()];
                versions.sort();
                assert_eq!(versions[0], [0, 0, 0, 1]);
                assert!(
                    versions[1].iter().all(|b| b & 0x0f == 0x0a),
                    "GREASE version"
                );
            }
            0x20 => assert_eq!(varint_value(value), 65_536),
            0x3128 => assert_eq!(value, b"ORIG"),
            grease => {
                assert_eq!((grease - 27) % 31, 0, "GREASE {grease:#x}");
                assert_eq!(value[0], 0xff, "an 8-byte identifier");
                assert!(value.len() <= 16);
            }
        }
        seen.insert(if *id >= 1 << 30 { u64::MAX } else { *id });
    }
    assert_eq!(seen.len(), 13, "thirteen distinct parameters");
}

/// Checks a first flight is not ChromeParrot's: numbered from 0, without
/// Chrome's connection options or ALPS.
pub fn assert_stock_first_flight(datagrams: &[Vec<u8>]) {
    let (initials, hello) = first_flight(datagrams).unwrap();
    assert_eq!(initials[0].packet_number, 0);
    let hello = parse_client_hello(&hello);
    assert!(hello.extensions.iter().all(|(t, _)| *t != 0x44cd));
    let (_, params) = hello.extensions.iter().find(|(t, _)| *t == 0x39).unwrap();
    assert!(transport_parameters(params)
        .iter()
        .all(|(id, _)| *id != 0x3128));
}
