use super::{Method, Records, TAG_LENGTH};
use crate::shadowsocks::{address, MAX_UDP_WIRE_LENGTH};
use rand::RngCore;
use std::{io, sync::Arc};
use xray_routing::{Network, Target};
use zeroize::Zeroizing;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Native UDP packets: `salt || seal(address || payload)` with a fresh salt
/// and the zero nonce per packet (Xray-core `EncodeUDPPacket`). The format
/// carries no session or packet identifier, so, like the reference client,
/// replies are authenticated but not replay-filtered.
pub struct UdpSession {
    method: Arc<Method>,
}

impl UdpSession {
    pub fn new(method: Arc<Method>) -> Self {
        Self { method }
    }

    pub fn encode(&mut self, target: &Target, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut salt = [0; 32];
        let salt = &mut salt[..self.method.cipher.key_len()];
        rand::rngs::OsRng
            .try_fill_bytes(salt)
            .map_err(|_| invalid("Shadowsocks random source failed"))?;
        self.encode_with_salt(target, payload, salt)
    }

    fn encode_with_salt(
        &self,
        target: &Target,
        payload: &[u8],
        salt: &[u8],
    ) -> io::Result<Vec<u8>> {
        let address = address::encode(target)?;
        if target.network != Network::Udp
            || salt.len() + address.len() + payload.len() + TAG_LENGTH > MAX_UDP_WIRE_LENGTH
        {
            return Err(invalid("invalid Shadowsocks AEAD datagram size or network"));
        }
        let mut wire = Vec::with_capacity(salt.len() + address.len() + payload.len() + TAG_LENGTH);
        wire.extend_from_slice(salt);
        wire.extend_from_slice(&address);
        wire.extend_from_slice(payload);
        Records::new(&self.method, salt).seal_from(&mut wire, salt.len())?;
        Ok(wire)
    }

    /// Authenticate before parsing. As in Xray-core `DecodeUDPPacket`, the
    /// address type's high nibble is ignored.
    pub fn decode(&mut self, wire: &[u8]) -> io::Result<(Target, Vec<u8>)> {
        let salt_len = self.method.cipher.key_len();
        if wire.len() < salt_len + TAG_LENGTH || wire.len() > MAX_UDP_WIRE_LENGTH {
            return Err(invalid("invalid Shadowsocks AEAD packet length"));
        }
        let (salt, sealed) = wire.split_at(salt_len);
        let mut body = Zeroizing::new(sealed.to_vec());
        let len = Records::new(&self.method, salt).open(&mut body)?;
        let body = &mut body[..len];
        if let Some(kind) = body.first_mut() {
            *kind &= 0x0f;
        }
        let (source, used) = address::decode(body)?;
        Ok((source, body[used..].to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixtures, method, unhex};
    use super::*;
    use xray_routing::TargetAddr;

    #[test]
    fn packets_match_pinned_go_including_masked_reply_types() {
        for case in fixtures() {
            let mut session = UdpSession::new(method(&case));
            let wire = unhex(case["udpWire"].as_str().unwrap());
            let salt = &wire[..case["saltLength"].as_u64().unwrap() as usize];
            let target = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Udp);
            let payload = unhex(case["udpPayload"].as_str().unwrap());
            assert_eq!(
                session.encode_with_salt(&target, &payload, salt).unwrap(),
                wire,
                "{}",
                case["method"]
            );
            assert_eq!(session.decode(&wire).unwrap(), (target, payload));
            let (source, reply) = session
                .decode(&unhex(case["udpMaskedReply"].as_str().unwrap()))
                .unwrap();
            assert_eq!(
                source,
                Target::new(
                    TargetAddr::Ip("192.0.2.8".parse().unwrap()),
                    53,
                    Network::Udp
                )
            );
            assert_eq!(reply, b"reply");
        }
    }

    #[test]
    fn packets_fail_closed_on_any_modification_size_or_network() {
        for case in fixtures() {
            let mut session = UdpSession::new(method(&case));
            let target = Target::new(
                TargetAddr::Ip("192.0.2.8".parse().unwrap()),
                53,
                Network::Udp,
            );
            let wire = session.encode(&target, b"payload").unwrap();
            assert_ne!(session.encode(&target, b"payload").unwrap(), wire);
            for i in 0..wire.len() {
                let mut bad = wire.clone();
                bad[i] ^= 1;
                assert!(session.decode(&bad).is_err());
            }
            for len in 0..wire.len() {
                assert!(session.decode(&wire[..len]).is_err());
            }
            let salt_len = session.method.cipher.key_len();
            let max = MAX_UDP_WIRE_LENGTH - salt_len - 7 - TAG_LENGTH;
            assert_eq!(
                session.encode(&target, &vec![0; max]).unwrap().len(),
                MAX_UDP_WIRE_LENGTH
            );
            assert!(session.encode(&target, &vec![0; max + 1]).is_err());
            let tcp = Target::new(target.addr.clone(), 53, Network::Tcp);
            assert!(session.encode(&tcp, b"payload").is_err());
        }
    }
}
