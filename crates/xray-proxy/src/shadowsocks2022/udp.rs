use super::{
    crypto::{self, Aead},
    *,
};
use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    XChaCha20Poly1305,
};
use rand::RngCore;
use std::sync::Arc;

/// A native UDP association. Authentication, response binding and address
/// validation precede replay-state changes. Memory stays constant per session.
pub struct UdpSession {
    method: Arc<Method>,
    id: u64,
    next: Option<u64>,
    local: Aead,
    current: Option<Remote>,
    previous: Option<Remote>,
    previous_seen: u64,
}
struct Remote {
    id: u64,
    aead: Aead,
    replay: Window,
}
struct Window {
    highest: u64,
    ring: [u64; 128],
}
impl Window {
    fn new() -> Self {
        Self {
            highest: 0,
            ring: [0; 128],
        }
    }
    fn check(&self, id: u64) -> bool {
        if id > self.highest {
            return true;
        }
        if self.highest - id > 8128 {
            return false;
        }
        self.ring[((id >> 6) & 127) as usize] & (1 << (id & 63)) == 0
    }
    fn add(&mut self, id: u64) {
        if id > self.highest {
            let old = self.highest >> 6;
            for i in 1..=((id >> 6) - old).min(128) {
                self.ring[((old + i) & 127) as usize] = 0;
            }
            self.highest = id;
        }
        self.ring[((id >> 6) & 127) as usize] |= 1 << (id & 63);
    }
}
impl UdpSession {
    pub fn new(method: Arc<Method>) -> io::Result<Self> {
        let mut id = [0; 8];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| invalid("Shadowsocks 2022 random source failed"))?;
        Ok(Self::with_id(method, u64::from_be_bytes(id)))
    }
    fn with_id(method: Arc<Method>, id: u64) -> Self {
        let local = Aead::session(&method, &id.to_be_bytes());
        Self {
            method,
            id,
            next: Some(0),
            local,
            current: None,
            previous: None,
            previous_seen: 0,
        }
    }
    pub fn encode(&mut self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut nonce = [0; 24];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| invalid("Shadowsocks 2022 random source failed"))?;
        self.encode_at(target, payload, now()?, nonce)
    }
    fn encode_at(
        &mut self,
        target: &Target,
        payload: &[u8],
        timestamp: u64,
        nonce: [u8; 24],
    ) -> io::Result<Vec<u8>> {
        let address = encode_address(target)?;
        let extra = if self.method.cipher == Cipher::ChaCha20Poly1305 {
            24
        } else {
            (self.method.keys.len() - 1) * 16
        };
        if target.network != Network::Udp
            || 16 + extra + 11 + address.len() + payload.len() + TAG_LENGTH > MAX_UDP_WIRE_LENGTH
        {
            return Err(invalid("invalid Shadowsocks 2022 datagram size or network"));
        }
        let packet_id = self
            .next
            .ok_or_else(|| invalid("Shadowsocks 2022 packet counter exhausted"))?;
        self.next = packet_id.checked_add(1);
        let mut separate = [0; 16];
        separate[..8].copy_from_slice(&self.id.to_be_bytes());
        separate[8..].copy_from_slice(&packet_id.to_be_bytes());
        let mut body = Zeroizing::new(vec![0]);
        body.extend_from_slice(&timestamp.to_be_bytes());
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(&address);
        body.extend_from_slice(payload);
        if self.method.cipher == Cipher::ChaCha20Poly1305 {
            let mut plain = Zeroizing::new(separate.to_vec());
            plain.extend_from_slice(&body);
            XChaCha20Poly1305::new_from_slice(self.method.psk())
                .unwrap()
                .encrypt_in_place((&nonce).into(), &[], &mut *plain)
                .map_err(|_| invalid("Shadowsocks 2022 encryption failed"))?;
            let mut wire = nonce.to_vec();
            wire.extend_from_slice(&plain);
            Ok(wire)
        } else {
            self.local
                .seal(separate[4..].try_into().unwrap(), &mut body)?;
            let mut wire = separate.to_vec();
            for keys in self.method.keys.windows(2) {
                let mut identity = crypto::identity_hash(&keys[1]);
                for (byte, hdr) in identity.iter_mut().zip(separate) {
                    *byte ^= hdr;
                }
                crypto::block(&keys[0], &mut identity, false);
                wire.extend_from_slice(&*identity);
            }
            crypto::block(&self.method.keys[0], &mut separate, false);
            wire[..16].copy_from_slice(&separate);
            wire.extend_from_slice(&body);
            Ok(wire)
        }
    }
    pub fn decode(&mut self, wire: &[u8]) -> io::Result<(Target, Vec<u8>)> {
        self.decode_at(wire, now()?)
    }
    fn decode_at(&mut self, wire: &[u8], timestamp: u64) -> io::Result<(Target, Vec<u8>)> {
        if wire.len() < 16 + 19 + 7 + TAG_LENGTH || wire.len() > MAX_UDP_WIRE_LENGTH {
            return Err(invalid("invalid Shadowsocks 2022 packet length"));
        }
        let mut body;
        let mut separate = [0; 16];
        if self.method.cipher == Cipher::ChaCha20Poly1305 {
            body = Zeroizing::new(wire[24..].to_vec());
            XChaCha20Poly1305::new_from_slice(self.method.psk())
                .unwrap()
                .decrypt_in_place(wire[..24].into(), &[], &mut *body)
                .map_err(|_| invalid("Shadowsocks 2022 authentication failed"))?;
            if body.len() < 16 {
                return Err(invalid("truncated Shadowsocks 2022 packet"));
            }
            separate.copy_from_slice(&body[..16]);
            body.drain(..16);
        } else {
            separate.copy_from_slice(&wire[..16]);
            crypto::block(self.method.psk(), &mut separate, true);
            body = Zeroizing::new(wire[16..].to_vec());
        }
        let id = u64::from_be_bytes(separate[..8].try_into().unwrap());
        let packet_id = u64::from_be_bytes(separate[8..].try_into().unwrap());
        if id == self.id {
            return Err(invalid("Shadowsocks 2022 reflected session"));
        }
        let remote = self
            .current
            .as_ref()
            .filter(|r| r.id == id)
            .or_else(|| self.previous.as_ref().filter(|r| r.id == id));
        if remote.is_some_and(|r| !r.replay.check(packet_id)) {
            return Err(invalid("replayed Shadowsocks 2022 packet"));
        }
        let candidate = if remote.is_none() {
            Some(Aead::session(&self.method, &separate[..8]))
        } else {
            None
        };
        if self.method.cipher != Cipher::ChaCha20Poly1305 {
            let aead = remote.map(|r| &r.aead).or(candidate.as_ref()).unwrap();
            aead.open(separate[4..].try_into().unwrap(), &mut body)?;
        }
        let mut cursor = Cursor(&body);
        if cursor.u8()? != 1 {
            return Err(invalid("invalid Shadowsocks 2022 packet type"));
        }
        check_time(cursor.u64()?, timestamp)?;
        if cursor.u64()? != self.id {
            return Err(invalid("Shadowsocks 2022 client session mismatch"));
        }
        let padding = cursor.u16()? as usize;
        cursor.take(padding)?;
        let target = cursor.target()?;
        if self.current.as_ref().is_some_and(|r| r.id == id) {
            self.current.as_mut().unwrap().replay.add(packet_id);
        } else if self.previous.as_ref().is_some_and(|r| r.id == id) {
            self.previous.as_mut().unwrap().replay.add(packet_id);
            self.previous_seen = timestamp;
        } else {
            if self.previous.is_some() && timestamp.saturating_sub(self.previous_seen) < 60 {
                return Err(invalid("too many Shadowsocks 2022 remote sessions"));
            }
            self.previous = self.current.take();
            self.previous_seen = timestamp;
            let mut replay = Window::new();
            replay.add(packet_id);
            self.current = Some(Remote {
                id,
                aead: candidate.unwrap(),
                replay,
            });
        }
        Ok((target, cursor.0.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixtures, unhex};
    use super::*;
    #[test]
    fn ss2022_udp_matches_pinned_go_all_ciphers_and_identity_chains() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let mut session = UdpSession::with_id(method, case["udpSessionId"].as_u64().unwrap());
            let nonce = unhex(case["udpNonce"].as_str().unwrap());
            let mut fixed = [0; 24];
            if !nonce.is_empty() {
                fixed.copy_from_slice(&nonce);
            }
            let target = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Udp);
            let wire = session
                .encode_at(
                    &target,
                    &unhex(case["udpPayload"].as_str().unwrap()),
                    1700000000,
                    fixed,
                )
                .unwrap();
            assert_eq!(
                wire,
                unhex(case["udpWire"].as_str().unwrap()),
                "{}",
                case["method"]
            );
        }
    }
    fn response(
        session: &UdpSession,
        remote: u64,
        packet: u64,
        client: u64,
        timestamp: u64,
        padding: u16,
    ) -> Vec<u8> {
        let mut separate = remote.to_be_bytes().to_vec();
        separate.extend(packet.to_be_bytes());
        let mut body = vec![1];
        body.extend(timestamp.to_be_bytes());
        body.extend(client.to_be_bytes());
        body.extend(padding.to_be_bytes());
        body.extend(
            encode_address(&Target::new(
                TargetAddr::Ip("2001:db8::8".parse().unwrap()),
                53,
                Network::Udp,
            ))
            .unwrap(),
        );
        body.extend(b"reply");
        if session.method.cipher == Cipher::ChaCha20Poly1305 {
            separate.extend(body);
            let nonce = [7; 24];
            XChaCha20Poly1305::new_from_slice(session.method.psk())
                .unwrap()
                .encrypt_in_place((&nonce).into(), &[], &mut separate)
                .unwrap();
            let mut wire = nonce.to_vec();
            wire.extend(separate);
            wire
        } else {
            Aead::session(&session.method, &remote.to_be_bytes())
                .seal(separate[4..].try_into().unwrap(), &mut body)
                .unwrap();
            let mut block: [u8; 16] = separate.try_into().unwrap();
            crypto::block(session.method.psk(), &mut block, false);
            let mut wire = block.to_vec();
            wire.extend(body);
            wire
        }
    }
    #[test]
    fn ss2022_udp_checks_authentication_binding_time_padding_before_replay_commit() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let mut session = UdpSession::with_id(method, 10);
            let time = 1700000000;
            for bad in [
                response(&session, 20, 0, 11, time, 0),
                response(&session, 20, 0, 10, time - 31, 0),
                response(&session, 20, 0, 10, time, 65535),
                response(&session, 10, 0, 10, time, 0),
            ] {
                assert!(session.decode_at(&bad, time).is_err());
            }
            let good = response(&session, 20, 0, 10, time, 0);
            for i in 0..good.len() {
                let mut bad = good.clone();
                bad[i] ^= 1;
                assert!(session.decode_at(&bad, time).is_err());
            }
            assert_eq!(session.decode_at(&good, time).unwrap().1, b"reply");
            assert!(session.decode_at(&good, time).is_err());
            let next = response(&session, 21, 1, 10, time, 0);
            session.decode_at(&next, time).unwrap();
            let overflow = response(&session, 22, 1, 10, time, 0);
            assert!(session.decode_at(&overflow, time).is_err());
            let rotated = response(&session, 22, 1, 10, time + 61, 0);
            session.decode_at(&rotated, time + 61).unwrap();
        }
    }
    #[test]
    fn ss2022_replay_window_and_sender_limits() {
        let mut window = Window::new();
        assert!(window.check(0));
        window.add(0);
        assert!(!window.check(0));
        window.add(10000);
        assert!(!window.check(0));
        assert!(window.check(9999));
        window.add(9999);
        assert!(!window.check(9999));
        window.add(u64::MAX);
        assert!(window.check(u64::MAX - 1));
        assert!(!window.check(10000));
        let method =
            Arc::new(Method::new("2022-blake3-aes-128-gcm", &STANDARD.encode([1; 16])).unwrap());
        let mut session = UdpSession::with_id(method, 10);
        let target = Target::new(
            TargetAddr::Ip("192.0.2.8".parse().unwrap()),
            53,
            Network::Udp,
        );
        assert!(session
            .encode(&target, &vec![0; MAX_UDP_WIRE_LENGTH])
            .is_err());
        assert_eq!(session.next, Some(0));
        session.next = Some(u64::MAX);
        session.encode(&target, b"last").unwrap();
        assert!(session.encode(&target, b"exhausted").is_err());
    }
}
