//! Bounded Mux.Cool/XUDP frames from Xray-core v26.7.28.
//! Decoding is stateless so a cancelled read never consumes a partial frame.
use std::{io, net::IpAddr};
use xray_routing::{Network, Target, TargetAddr};

pub const MAX_METADATA: usize = 512;
pub const MAX_PAYLOAD: usize = 8192;
pub const MAX_FRAME: usize = 2 + MAX_METADATA + 2 + MAX_PAYLOAD;

/// Keyed association identity, stable within one handler and unlinkable across
/// independent cores/handlers. Zero denotes a non-user flow (for example DNS).
pub struct FlowIds(zeroize::Zeroizing<[u8; 32]>);
impl Default for FlowIds {
    fn default() -> Self {
        Self(zeroize::Zeroizing::new(rand::random()))
    }
}
impl std::fmt::Debug for FlowIds {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FlowIds(<redacted>)")
    }
}
impl FlowIds {
    pub fn derive(&self, flow: [u8; 8]) -> [u8; 8] {
        if flow == [0; 8] {
            return flow;
        }
        blake3::keyed_hash(&self.0, &flow).as_bytes()[..8]
            .try_into()
            .unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    New = 1,
    Keep = 2,
    End = 3,
    KeepAlive = 4,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub session_id: u16,
    pub status: Status,
    pub error: bool,
    pub target: Option<Target>,
    pub global_id: Option<[u8; 8]>,
    pub payload: Option<&'a [u8]>,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Mux frame")
}

pub fn encode(frame: &Frame<'_>) -> io::Result<Vec<u8>> {
    if frame.payload.is_some_and(|p| p.len() > MAX_PAYLOAD)
        || frame.error && frame.status != Status::End
        || frame.status == Status::New && frame.target.is_none()
        || frame.global_id.is_some()
            && (frame.status != Status::New
                || frame
                    .target
                    .as_ref()
                    .is_none_or(|t| t.network != Network::Udp))
    {
        return Err(invalid());
    }
    let mut meta = frame.session_id.to_be_bytes().to_vec();
    meta.extend([
        frame.status as u8,
        u8::from(frame.payload.is_some()) | (u8::from(frame.error) << 1),
    ]);
    if let Some(target) = &frame.target {
        if !matches!(frame.status, Status::New | Status::Keep)
            || frame.status == Status::Keep && target.network != Network::Udp
        {
            return Err(invalid());
        }
        meta.push(if target.network == Network::Tcp { 1 } else { 2 });
        meta.extend(target.port.to_be_bytes());
        if target.port == 0 {
            return Err(invalid());
        }
        match &target.addr {
            TargetAddr::Ip(IpAddr::V4(ip)) => {
                meta.push(1);
                meta.extend(ip.octets());
            }
            TargetAddr::Ip(IpAddr::V6(ip)) => {
                meta.push(3);
                meta.extend(ip.octets());
            }
            TargetAddr::Domain(name) => {
                if name.is_empty()
                    || name.len() > 255
                    || name.chars().any(|c| c.is_control() || c.is_whitespace())
                {
                    return Err(invalid());
                }
                meta.extend([2, name.len() as u8]);
                meta.extend(name.as_bytes());
            }
        }
    }
    if let Some(id) = frame.global_id {
        meta.extend(id);
    }
    let mut wire = (meta.len() as u16).to_be_bytes().to_vec();
    wire.extend(meta);
    if let Some(payload) = frame.payload {
        wire.extend((payload.len() as u16).to_be_bytes());
        wire.extend(payload);
    }
    Ok(wire)
}

/// `None` means incomplete input. Invalid lengths fail before payload allocation.
pub fn decode(input: &[u8]) -> io::Result<Option<(Frame<'_>, usize)>> {
    Ok(decode_with(input, false)?.map(|(frame, consumed)| (frame.frame, consumed)))
}

/// A frame of a reverse Mux.Cool connection, as the bridge of Xray-core's
/// VLESS reverse proxy reads what the portal sends: a new session names,
/// in place of an XUDP global ID, the address of the portal's client and
/// the address that client reached, each when the portal knows it.
#[derive(Debug, PartialEq, Eq)]
pub struct ReverseFrame<'a> {
    pub frame: Frame<'a>,
    /// The portal's client (Xray-core's `inbound.Source`).
    pub source: Option<Target>,
    /// Where that client arrived (`inbound.Local`).
    pub local: Option<Target>,
}

/// Decodes a frame the portal of a reverse proxy sends, as Xray-core's
/// `FrameMetadata.Unmarshal` with `readSourceAndLocal` reads it. Port 0 is
/// read as any other, since the portal's control session goes to
/// `reverse:0`. `None` means incomplete input.
pub fn decode_reverse(input: &[u8]) -> io::Result<Option<(ReverseFrame<'_>, usize)>> {
    decode_with(input, true)
}

/// Reads a port, then an address, as Xray-core's Mux address parser does.
fn read_port_address(rest: &[u8], allow_port_zero: bool) -> io::Result<(u16, TargetAddr, usize)> {
    if rest.len() < 3 {
        return Err(invalid());
    }
    let port = u16::from_be_bytes(rest[..2].try_into().unwrap());
    if port == 0 && !allow_port_zero {
        return Err(invalid());
    }
    let (addr, count) = match rest[2] {
        1 if rest.len() >= 7 => (
            TargetAddr::Ip(IpAddr::from(<[u8; 4]>::try_from(&rest[3..7]).unwrap())),
            7,
        ),
        3 if rest.len() >= 19 => (
            TargetAddr::Ip(IpAddr::from(<[u8; 16]>::try_from(&rest[3..19]).unwrap())),
            19,
        ),
        2 if rest.len() >= 4 => {
            let n = rest[3] as usize;
            if n == 0 || rest.len() < 4 + n {
                return Err(invalid());
            }
            let name = std::str::from_utf8(&rest[4..4 + n]).map_err(|_| invalid())?;
            if name.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err(invalid());
            }
            (TargetAddr::Domain(name.into()), 4 + n)
        }
        _ => return Err(invalid()),
    };
    Ok((port, addr, count))
}

/// Reads a network byte, then a port and an address. `None` when the network
/// byte is zero, which Xray-core reads as padding after a session's target.
fn read_endpoint(rest: &[u8], allow_port_zero: bool) -> io::Result<Option<(Target, usize)>> {
    let network = match rest.first() {
        None | Some(0) => return Ok(None),
        Some(1) => Network::Tcp,
        Some(2) => Network::Udp,
        Some(_) => return Err(invalid()),
    };
    let (port, addr, count) = read_port_address(&rest[1..], allow_port_zero)?;
    Ok(Some((Target::new(addr, port, network), 1 + count)))
}

fn decode_with(input: &[u8], reverse: bool) -> io::Result<Option<(ReverseFrame<'_>, usize)>> {
    if input.len() < 2 {
        return Ok(None);
    }
    let length = u16::from_be_bytes(input[..2].try_into().unwrap()) as usize;
    if !(4..=MAX_METADATA).contains(&length) {
        return Err(invalid());
    }
    if input.len() < 2 + length {
        return Ok(None);
    }
    let meta = &input[2..2 + length];
    let session_id = u16::from_be_bytes(meta[..2].try_into().unwrap());
    let status = match meta[2] {
        1 => Status::New,
        2 => Status::Keep,
        3 => Status::End,
        4 => Status::KeepAlive,
        _ => return Err(invalid()),
    };
    if meta[3] & !3 != 0 || meta[3] & 2 != 0 && status != Status::End {
        return Err(invalid());
    }
    let mut rest = &meta[4..];
    let target = if status == Status::New || status == Status::Keep && rest.first() == Some(&2) {
        // Xray-core wants the network byte, port and address type at least.
        if rest.len() < 4 {
            return Err(invalid());
        }
        let Some((target, count)) = read_endpoint(rest, reverse)? else {
            return Err(invalid());
        };
        rest = &rest[count..];
        Some(target)
    } else {
        None
    };
    let (mut source, mut local) = (None, None);
    let global_id = if reverse {
        // A reverse session names its client and where it arrived instead.
        if status == Status::New {
            if let Some((endpoint, count)) = read_endpoint(rest, true)? {
                source = Some(endpoint);
                rest = &rest[count..];
                if let Some((endpoint, count)) = read_endpoint(rest, true)? {
                    local = Some(endpoint);
                    rest = &rest[count..];
                }
            }
        }
        None
    } else if status == Status::New
        && target.as_ref().is_some_and(|t| t.network == Network::Udp)
        && rest.len() >= 8
    {
        let id = rest[..8].try_into().unwrap();
        rest = &rest[8..];
        Some(id)
    } else {
        None
    };
    // The pinned peer permits metadata padding; accepting zeros does not
    // silently discard additional target or reverse-Mux metadata.
    if rest.iter().any(|&b| b != 0) {
        return Err(invalid());
    }
    let mut consumed = 2 + length;
    let payload = if meta[3] & 1 != 0 {
        if input.len() < consumed + 2 {
            return Ok(None);
        }
        let size = u16::from_be_bytes(input[consumed..consumed + 2].try_into().unwrap()) as usize;
        if size > MAX_PAYLOAD {
            return Err(invalid());
        }
        consumed += 2;
        if input.len() < consumed + size {
            return Ok(None);
        }
        let data = &input[consumed..consumed + size];
        consumed += size;
        Some(data)
    } else {
        None
    };
    Ok(Some((
        ReverseFrame {
            frame: Frame {
                session_id,
                status,
                error: meta[3] & 2 != 0,
                target,
                global_id,
                payload,
            },
            source,
            local,
        },
        consumed,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mux_frames_match_pinned_go_oracle() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/v08/protocol-primitives.json"
        ))
        .unwrap();
        for case in fixture["mux"].as_array().unwrap() {
            let network = if case["network"] == "tcp" {
                Network::Tcp
            } else {
                Network::Udp
            };
            let address = case["address"].as_str().unwrap();
            let target = Target::new(
                address
                    .parse()
                    .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip),
                8443,
                network,
            );
            let status = match case["status"].as_u64().unwrap() {
                1 => Status::New,
                2 => Status::Keep,
                3 => Status::End,
                4 => Status::KeepAlive,
                _ => unreachable!(),
            };
            let frame = Frame {
                session_id: 37,
                status,
                error: false,
                target: (status == Status::New
                    || status == Status::Keep && network == Network::Udp)
                    .then_some(target),
                global_id: (status == Status::New && network == Network::Udp)
                    .then_some([1, 2, 3, 4, 5, 6, 7, 8]),
                payload: matches!(status, Status::New | Status::Keep).then_some(&[0, 1, 127, 255]),
            };
            let text = case["wire"].as_str().unwrap();
            let golden: Vec<u8> = (0..text.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
                .collect();
            assert_eq!(encode(&frame).unwrap(), golden);
            assert_eq!(decode(&golden).unwrap(), Some((frame, golden.len())));
        }
    }
    #[test]
    fn xudp_ids_are_stable_within_handler_and_separate_across_handlers() {
        let a = FlowIds::default();
        let b = FlowIds::default();
        assert_eq!(a.derive([7; 8]), a.derive([7; 8]));
        assert_ne!(a.derive([7; 8]), b.derive([7; 8]));
        assert_ne!(a.derive([7; 8]), a.derive([8; 8]));
        assert_eq!(a.derive([0; 8]), [0; 8]);
        assert_eq!(format!("{a:?}"), "FlowIds(<redacted>)");
    }
    #[test]
    fn mux_matches_existing_xudp_and_decodes_every_prefix_without_state() {
        for addr in [
            TargetAddr::Ip("192.0.2.1".parse().unwrap()),
            TargetAddr::Ip("2001:db8::1".parse().unwrap()),
            TargetAddr::Domain("example.test".into()),
        ] {
            let target = Target::new(addr, 53, Network::Udp);
            let frame = Frame {
                session_id: 0,
                status: Status::New,
                error: false,
                target: Some(target.clone()),
                global_id: Some([7; 8]),
                payload: Some(b"data"),
            };
            let wire = encode(&frame).unwrap();
            assert_eq!(
                wire,
                crate::vless::encode_xudp_new_packet(&target, b"data", [7; 8]).unwrap()
            );
            for n in 0..wire.len() {
                assert!(decode(&wire[..n]).unwrap().is_none());
            }
            assert_eq!(decode(&wire).unwrap(), Some((frame, wire.len())));
        }
    }
    #[test]
    fn reverse_frames_name_the_portals_client_and_allow_port_zero() {
        // The portal's control session: `udp reverse:0`, no data, no client.
        let control = [
            0, 16, 0, 1, 1, 0, 2, 0, 0, 2, 7, b'r', b'e', b'v', b'e', b'r', b's', b'e',
        ];
        let (frame, consumed) = decode_reverse(&control).unwrap().unwrap();
        assert_eq!(consumed, control.len());
        assert_eq!(
            frame,
            ReverseFrame {
                frame: Frame {
                    session_id: 1,
                    status: Status::New,
                    error: false,
                    target: Some(Target::new(
                        TargetAddr::Domain("reverse".into()),
                        0,
                        Network::Udp
                    )),
                    global_id: None,
                    payload: None,
                },
                source: None,
                local: None,
            }
        );
        // The client mode keeps refusing port 0.
        assert!(decode(&control).is_err());

        // A TCP session from 192.0.2.7:40000 that arrived at [2001:db8::1]:443.
        let mut meta = vec![0, 2, 1, 1, 1, 0x1f, 0x90, 1, 127, 0, 0, 1];
        meta.extend([1, 0x9c, 0x40, 1, 192, 0, 2, 7]);
        meta.extend([1, 1, 0xbb, 3]);
        meta.extend(
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        let mut wire = (meta.len() as u16).to_be_bytes().to_vec();
        wire.extend(&meta);
        wire.extend([0, 3, b'a', b'b', b'c']);
        let (frame, consumed) = decode_reverse(&wire).unwrap().unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(frame.frame.payload, Some(&b"abc"[..]));
        assert_eq!(
            frame.source,
            Some(Target::new(
                TargetAddr::Ip("192.0.2.7".parse().unwrap()),
                40000,
                Network::Tcp
            ))
        );
        assert_eq!(
            frame.local,
            Some(Target::new(
                TargetAddr::Ip("2001:db8::1".parse().unwrap()),
                443,
                Network::Tcp
            ))
        );
        // A client mode reader would take the client for metadata it cannot place.
        assert!(decode(&wire).is_err());
        for n in 0..wire.len() {
            assert!(decode_reverse(&wire[..n]).unwrap().is_none());
        }

        // A UDP session names no global ID; zero padding after the target
        // stops the client fields, other bytes or networks fail closed.
        let udp = [
            0, 14, 0, 9, 1, 1, 2, 0, 53, 1, 10, 0, 0, 1, 0, 0, 0, 1, 0xff,
        ];
        let (frame, _) = decode_reverse(&udp).unwrap().unwrap();
        assert_eq!(frame.frame.global_id, None);
        assert_eq!(frame.source, None);
        assert_eq!(frame.frame.payload, Some(&[0xff][..]));
        for meta in [
            &[0, 9, 1, 0, 2, 0, 53, 1, 10, 0, 0, 1, 3][..],
            &[0, 9, 1, 0, 2, 0, 53, 1, 10, 0, 0, 1, 0, 7],
            &[
                0, 9, 1, 0, 2, 0, 53, 1, 10, 0, 0, 1, 1, 0, 1, 1, 10, 0, 0, 2, 9,
            ],
        ] {
            let mut wire = (meta.len() as u16).to_be_bytes().to_vec();
            wire.extend(meta);
            assert!(decode_reverse(&wire).is_err(), "{meta:?}");
        }
    }
    #[test]
    fn mux_bounds_and_unknown_metadata_fail_closed() {
        let mut frame = Frame {
            session_id: 1,
            status: Status::Keep,
            error: false,
            target: None,
            global_id: None,
            payload: Some(&[0; MAX_PAYLOAD]),
        };
        let wire = encode(&frame).unwrap();
        assert_eq!(decode(&wire).unwrap().unwrap().1, wire.len());
        frame.payload = Some(&[0; MAX_PAYLOAD + 1]);
        assert!(encode(&frame).is_err());
        for bytes in [
            &[0, 3][..],
            &[2, 1],
            &[0, 4, 0, 0, 255, 0],
            &[0, 4, 0, 0, 2, 4],
            &[0, 4, 0, 0, 2, 1, 32, 1],
        ] {
            assert!(decode(bytes).is_err());
        }
    }
}
