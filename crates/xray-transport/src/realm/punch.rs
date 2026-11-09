//! Punch packets as Xray-core's realm writes and reads them: an eight-byte
//! salt, then the magic, the type, the attempt's nonce and up to 1024
//! random bytes, XORed with SHA-256 of the attempt's key and the salt.
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};

pub(super) const NONCE_LEN: usize = 16;
pub(super) const OBFS_KEY_LEN: usize = 32;
pub(super) const MAX_PADDING: usize = 1024;
const SALT_LEN: usize = 8;
const MAGIC: [u8; 8] = *b"HYRLMv1\0";
/// Magic, type and nonce.
const HEADER_LEN: usize = 25;
const MIN_WIRE_LEN: usize = SALT_LEN + HEADER_LEN;
/// The longest punch packet, and the buffer Xray-core reads into while it
/// punches.
pub(super) const MAX_WIRE_LEN: usize = MIN_WIRE_LEN + MAX_PADDING;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PacketType {
    Hello = 0x01,
    Ack = 0x02,
}

/// One attempt's nonce and key, which the client draws and the rendezvous
/// hands to the server.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PunchMetadata {
    pub nonce: [u8; NONCE_LEN],
    pub obfs: [u8; OBFS_KEY_LEN],
}

impl std::fmt::Debug for PunchMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchMetadata")
            .field("nonce", &hex(&self.nonce))
            .finish_non_exhaustive()
    }
}

impl PunchMetadata {
    /// `NewPunchMetadata`.
    pub(super) fn random() -> Self {
        let mut meta = Self {
            nonce: [0; NONCE_LEN],
            obfs: [0; OBFS_KEY_LEN],
        };
        rand::rngs::OsRng.fill_bytes(&mut meta.nonce);
        rand::rngs::OsRng.fill_bytes(&mut meta.obfs);
        meta
    }

    /// Both values in lower-case hex, as `randHex` writes them.
    pub(super) fn nonce_hex(&self) -> String {
        hex(&self.nonce)
    }

    pub(super) fn obfs_hex(&self) -> String {
        hex(&self.obfs)
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// `EncodePunchPacket` with a random salt and padding.
pub(super) fn encode(kind: PacketType, meta: &PunchMetadata) -> Vec<u8> {
    let mut rng = rand::rngs::OsRng;
    let padding = rng.gen_range(0..=MAX_PADDING);
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut padding_bytes = vec![0u8; padding];
    rng.fill_bytes(&mut padding_bytes);
    encode_with(kind, meta, salt, &padding_bytes)
}

/// The packet for a given salt and padding.
pub(super) fn encode_with(
    kind: PacketType,
    meta: &PunchMetadata,
    salt: [u8; SALT_LEN],
    padding: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(MIN_WIRE_LEN + padding.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&MAGIC);
    packet.push(kind as u8);
    packet.extend_from_slice(&meta.nonce);
    packet.extend_from_slice(padding);
    xor(&mut packet[SALT_LEN..], &meta.obfs, &salt);
    packet
}

/// `DecodePunchPacket`: the packet's type and padding length when it
/// belongs to this attempt.
pub(super) fn decode(packet: &[u8], meta: &PunchMetadata) -> Option<(PacketType, usize)> {
    if !(MIN_WIRE_LEN..=MAX_WIRE_LEN).contains(&packet.len()) {
        return None;
    }
    let (salt, body) = packet.split_at(SALT_LEN);
    let mut plain = body.to_vec();
    xor(&mut plain, &meta.obfs, salt);
    if plain[..MAGIC.len()] != MAGIC {
        return None;
    }
    let kind = match plain[MAGIC.len()] {
        0x01 => PacketType::Hello,
        0x02 => PacketType::Ack,
        _ => return None,
    };
    if plain[MAGIC.len() + 1..HEADER_LEN] != meta.nonce {
        return None;
    }
    Some((kind, plain.len() - HEADER_LEN))
}

/// `xorPunchPacket`: SHA-256 of the key and the salt, repeated.
fn xor(packet: &mut [u8], key: &[u8], salt: &[u8]) {
    let mask = Sha256::new()
        .chain_update(key)
        .chain_update(salt)
        .finalize();
    for (i, byte) in packet.iter_mut().enumerate() {
        *byte ^= mask[i % mask.len()];
    }
}

#[cfg(test)]
mod tests;
