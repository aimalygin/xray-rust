//! mKCP's `finalmask.udp` masks as Xray-core v26.10.31 applies them: the
//! `mkcp-legacy`, noise and `header-custom` masks.
//!
//! Xray applies masks in array order on the way out, so the last one is
//! outermost on the wire. Consecutive legacy masks share one
//! `headerManagerConn`, which drops a datagram over 4096 bytes. Noise sends
//! its packets through the masks after it. Noise and custom headers split
//! the legacy masks into separate groups.
use std::{collections::VecDeque, io, net::SocketAddr, ops::Range, time::Duration};

use aes_gcm::{
    aead::{AeadInOut, KeyInit},
    Aes128Gcm, Nonce, Tag,
};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use super::{KcpHeader, KcpMask};
use crate::{
    header_custom::udp::{UdpHeader, Write},
    sudoku::datagram::DatagramMask,
    udp_noise::UdpNoiseConfig,
};

/// Xray's `finalmask.UDPSize`.
const UDP_SIZE: usize = 4096;
const NONCE: usize = 12;
const TAG: usize = 16;
/// The checksum and length the original mask puts first.
const ORIGINAL: usize = 6;

/// One `mkcp-legacy` mask.
enum Legacy {
    Original,
    Aes(Box<Aes128Gcm>),
    /// The DNS query; its transaction ID is redrawn for every datagram.
    Dns(Vec<u8>),
    Dtls {
        epoch: u16,
        length: u16,
        sequence: u32,
    },
    Srtp {
        number: u16,
    },
    Utp,
    Wechat {
        sn: u32,
    },
    Wireguard,
}

impl Legacy {
    fn new(mask: &KcpMask) -> io::Result<Option<Self>> {
        Ok(Some(match mask {
            KcpMask::Noise | KcpMask::HeaderCustom(_) | KcpMask::Sudoku(_) => return Ok(None),
            KcpMask::Original => Self::Original,
            KcpMask::Aes128Gcm(password) => {
                let key = Sha256::digest(password.as_bytes());
                Self::Aes(Box::new(Aes128Gcm::new_from_slice(&key[..16]).map_err(
                    |_| io::Error::new(io::ErrorKind::InvalidInput, "AES-128 key length"),
                )?))
            }
            KcpMask::Header(KcpHeader::Dns(domain)) => Self::Dns(dns_header(domain)?),
            KcpMask::Header(KcpHeader::Dtls) => Self::Dtls {
                epoch: 0,
                length: 0,
                sequence: 0,
            },
            KcpMask::Header(KcpHeader::Srtp) => Self::Srtp { number: 0 },
            KcpMask::Header(KcpHeader::Utp) => Self::Utp,
            KcpMask::Header(KcpHeader::Wechat) => Self::Wechat { sn: 0 },
            KcpMask::Header(KcpHeader::Wireguard) => Self::Wireguard,
        }))
    }

    /// Bytes reserved ahead of what this mask wraps.
    fn size(&self) -> usize {
        match self {
            Self::Original => ORIGINAL,
            Self::Aes(_) => NONCE,
            Self::Dns(header) => header.len(),
            Self::Dtls { .. } | Self::Wechat { .. } => 13,
            Self::Srtp { .. } | Self::Utp | Self::Wireguard => 4,
        }
    }

    /// Wraps `buf[start..]`, whose first `size()` bytes are this mask's.
    fn seal(&mut self, buf: &mut Vec<u8>, start: usize) {
        let size = self.size();
        match self {
            Self::Original => {
                let region = &mut buf[start..];
                let length = (region.len() - ORIGINAL) as u16;
                region[4..6].copy_from_slice(&length.to_be_bytes());
                let hash = fnv1a(&region[4..]);
                region[..4].copy_from_slice(&hash.to_be_bytes());
                for i in 4..region.len() {
                    region[i] ^= region[i - 4];
                }
            }
            Self::Aes(cipher) => {
                let mut nonce = [0; NONCE];
                rand::thread_rng().fill_bytes(&mut nonce);
                buf[start..start + NONCE].copy_from_slice(&nonce);
                // Encrypting a datagram-sized buffer cannot fail.
                if let Ok(tag) = cipher.encrypt_inout_detached(
                    (&nonce).into(),
                    b"",
                    (&mut buf[start + NONCE..]).into(),
                ) {
                    buf.extend_from_slice(&tag);
                }
            }
            Self::Dns(header) => {
                buf[start..start + size].copy_from_slice(header);
                let id: u16 = rand::thread_rng().gen();
                buf[start..start + 2].copy_from_slice(&id.to_be_bytes());
            }
            Self::Dtls {
                epoch,
                length,
                sequence,
            } => {
                let b = &mut buf[start..start + size];
                b[..3].copy_from_slice(&[23, 254, 253]);
                b[3..5].copy_from_slice(&epoch.to_be_bytes());
                b[5..7].copy_from_slice(&[0, 0]);
                b[7..11].copy_from_slice(&sequence.to_be_bytes());
                *sequence = sequence.wrapping_add(1);
                b[11..13].copy_from_slice(&length.to_be_bytes());
                *length = length.wrapping_add(17);
                if *length > 100 {
                    *length -= 50;
                }
            }
            Self::Srtp { number } => {
                *number = number.wrapping_add(1);
                let b = &mut buf[start..start + size];
                b[..2].copy_from_slice(&[0, 0]);
                b[2..4].copy_from_slice(&number.to_be_bytes());
            }
            Self::Utp => buf[start..start + size].copy_from_slice(&[0, 0, 0, 0]),
            Self::Wechat { sn } => {
                *sn = sn.wrapping_add(1);
                let b = &mut buf[start..start + size];
                b[..2].copy_from_slice(&[0xa1, 0x08]);
                b[2..6].copy_from_slice(&sn.to_be_bytes());
                b[6..].copy_from_slice(&[0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]);
            }
            Self::Wireguard => buf[start..start + size].copy_from_slice(&[4, 0, 0, 0]),
        }
    }

    /// Unwraps `region` in place: what this mask wrapped, relative to it, or
    /// `None` to drop the datagram. Only the original and AES masks check.
    fn open(&self, region: &mut [u8]) -> Option<Range<usize>> {
        match self {
            Self::Original => {
                for i in (4..region.len()).rev() {
                    region[i] ^= region[i - 4];
                }
                let hash = u32::from_be_bytes([region[0], region[1], region[2], region[3]]);
                if hash != fnv1a(&region[4..]) {
                    return None;
                }
                let length = usize::from(u16::from_be_bytes([region[4], region[5]]));
                (region.len() - ORIGINAL == length).then_some(ORIGINAL..region.len())
            }
            Self::Aes(cipher) => {
                if region.len() < NONCE + TAG {
                    return None;
                }
                let (nonce, rest) = region.split_at_mut(NONCE);
                let (text, tag) = rest.split_at_mut(rest.len() - TAG);
                let nonce = <&Nonce<_>>::try_from(&*nonce).ok()?;
                let tag = <&Tag>::try_from(&*tag).ok()?;
                cipher
                    .decrypt_inout_detached(nonce, b"", text.into(), tag)
                    .ok()?;
                Some(NONCE..region.len() - TAG)
            }
            _ => Some(self.size()..region.len()),
        }
    }
}

/// Consecutive legacy masks in array order, as one `headerManagerConn`.
#[derive(Default)]
struct Group(Vec<Legacy>);

impl Group {
    fn size(&self) -> usize {
        self.0.iter().map(Legacy::size).sum()
    }

    /// `payload` wrapped by every mask, the first innermost; `None` when it
    /// is too large, which Xray drops.
    fn seal(&mut self, payload: Vec<u8>) -> Option<Vec<u8>> {
        if self.0.is_empty() {
            return Some(payload);
        }
        let size = self.size();
        if size + payload.len() > UDP_SIZE {
            return None;
        }
        let mut buf = Vec::with_capacity(size + payload.len() + TAG * self.0.len());
        buf.resize(size, 0);
        buf.extend_from_slice(&payload);
        let mut start = size;
        for mask in &mut self.0 {
            start -= mask.size();
            mask.seal(&mut buf, start);
        }
        (buf.len() <= UDP_SIZE).then_some(buf)
    }

    /// Unwraps `range` of `buf`, the outermost mask first.
    fn open(&self, buf: &mut [u8], mut range: Range<usize>) -> Option<Range<usize>> {
        if self.0.is_empty() {
            return Some(range);
        }
        if range.len() < self.size() {
            return None;
        }
        for mask in self.0.iter().rev() {
            let inner = mask.open(&mut buf[range.clone()])?;
            range = range.start + inner.start..range.start + inner.end;
        }
        Some(range)
    }
}

/// The noise mask: its packets go out before the first datagram and again
/// after the connection idles past its reset interval.
struct Noise {
    config: UdpNoiseConfig,
    /// When the next datagram sends noise again; `None` before the first.
    reset_at: Option<Instant>,
}

/// Consecutive legacy masks share a size limit; other masks split groups.
enum Layer {
    Legacy(Group),
    Noise(Noise),
    Header(Box<UdpHeader>),
    Sudoku(DatagramMask),
}

enum Pending {
    Packet(Vec<u8>, usize),
    Pause(Duration),
    NoiseSent(usize),
    Handshake(Vec<u8>, usize),
}

pub(super) enum Action {
    Send(Vec<u8>),
    Pause(Duration),
    Wait,
}

/// Writes resume after each wire operation, so a standalone handshake can
/// receive its answer before the original packet advances to the next mask.
pub(super) struct Masks {
    layers: Vec<Layer>,
    pending: VecDeque<Pending>,
}

impl Masks {
    pub(super) fn new(masks: &[KcpMask], noise: Option<&UdpNoiseConfig>) -> io::Result<Self> {
        let mut layers = Vec::new();
        let mut seen_noise = false;
        let mut seen_header = false;
        for mask in masks {
            if let Some(legacy) = Legacy::new(mask)? {
                if let Some(Layer::Legacy(group)) = layers.last_mut() {
                    group.0.push(legacy);
                } else {
                    layers.push(Layer::Legacy(Group(vec![legacy])));
                }
                continue;
            }
            match mask {
                KcpMask::Noise => {
                    let Some(config) = noise else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "an mKCP noise mask without noise settings",
                        ));
                    };
                    if seen_noise {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "mKCP takes one noise mask",
                        ));
                    }
                    config.validate()?;
                    seen_noise = true;
                    layers.push(Layer::Noise(Noise {
                        config: config.clone(),
                        reset_at: None,
                    }));
                }
                KcpMask::HeaderCustom(config) => {
                    if seen_header {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "mKCP takes one header-custom mask",
                        ));
                    }
                    seen_header = true;
                    layers.push(Layer::Header(Box::new(UdpHeader::new(config.clone())?)));
                }
                KcpMask::Sudoku(config) => layers.push(Layer::Sudoku(DatagramMask::new(config)?)),
                _ => unreachable!("legacy masks handled above"),
            }
        }
        Ok(Self {
            layers,
            pending: VecDeque::new(),
        })
    }

    pub(super) fn start(&mut self, datagram: Vec<u8>) {
        self.pending.push_back(Pending::Packet(datagram, 0));
    }

    /// The awaited standalone reply has not come: the datagram goes back to
    /// the custom header, which sends its request again.
    pub(super) fn resend(&mut self) {
        let index = match self.pending.pop_front() {
            Some(Pending::Handshake(data, index) | Pending::Packet(data, index)) => {
                self.pending.push_front(Pending::Packet(data, index));
                index
            }
            Some(other) => {
                self.pending.push_front(other);
                return;
            }
            None => return,
        };
        if let Some(Layer::Header(header)) = self.layers.get_mut(index) {
            header.abandon();
        }
    }

    pub(super) fn next(
        &mut self,
        now: Instant,
        local: Option<SocketAddr>,
        peer: SocketAddr,
    ) -> Option<Action> {
        while let Some(pending) = self.pending.pop_front() {
            match pending {
                Pending::Pause(pause) => return Some(Action::Pause(pause)),
                Pending::NoiseSent(index) => {
                    if let Layer::Noise(noise) = &mut self.layers[index] {
                        noise.reset_at = Some(
                            now + Duration::from_secs(noise.config.reset_secs.sample().into()),
                        );
                    }
                }
                Pending::Handshake(data, index) => {
                    if let Layer::Header(header) = &self.layers[index] {
                        if header.waiting() {
                            self.pending.push_front(Pending::Handshake(data, index));
                            return Some(Action::Wait);
                        }
                    }
                    self.pending.push_front(Pending::Packet(data, index + 1));
                }
                Pending::Packet(data, index) => {
                    let Some(layer) = self.layers.get_mut(index) else {
                        return Some(Action::Send(data));
                    };
                    match layer {
                        Layer::Legacy(group) => {
                            if let Some(data) = group.seal(data) {
                                self.pending.push_front(Pending::Packet(data, index + 1));
                            }
                        }
                        Layer::Noise(noise) => {
                            self.pending.push_front(Pending::Packet(data, index + 1));
                            self.pending.push_front(Pending::NoiseSent(index));
                            if noise
                                .reset_at
                                .is_none_or(|reset| noise.config.reset_secs.to > 0 && now > reset)
                            {
                                // Expand in reverse to send items in configuration order.
                                for item in noise.config.items.iter().rev() {
                                    let pause =
                                        Duration::from_millis(item.delay_ms.sample().into());
                                    self.pending.push_front(Pending::Pause(pause));
                                    self.pending
                                        .push_front(Pending::Packet(item.build(), index + 1));
                                }
                            }
                        }
                        Layer::Sudoku(sudoku) => {
                            let data = sudoku.encode(&data);
                            self.pending.push_front(Pending::Packet(data, index + 1));
                        }
                        Layer::Header(header) => match header.write(&data, local, peer, now) {
                            Write::Packet(data) => {
                                self.pending.push_front(Pending::Packet(data, index + 1))
                            }
                            Write::Handshake(request) => {
                                self.pending.push_front(Pending::Handshake(data, index));
                                self.pending.push_front(Pending::Packet(request, index + 1));
                            }
                            Write::Waiting => {
                                self.pending.push_front(Pending::Packet(data, index));
                                return Some(Action::Wait);
                            }
                            Write::Drop => {}
                        },
                    }
                }
            }
        }
        None
    }

    pub(super) fn open(
        &mut self,
        buf: &mut [u8],
        peer: SocketAddr,
        now: Instant,
    ) -> Option<Range<usize>> {
        let mut range = 0..buf.len();
        for layer in self.layers.iter_mut().rev() {
            match layer {
                Layer::Legacy(group) => range = group.open(buf, range)?,
                Layer::Noise(_) => {}
                Layer::Sudoku(sudoku) => range = sudoku.decode(buf, range)?,
                Layer::Header(header) => {
                    range.end = range
                        .end
                        .min(range.start.saturating_add(header.receive_limit()));
                    range.start += header.read(&buf[range.clone()], peer, now)?;
                }
            }
        }
        Some(range)
    }
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5, |hash: u32, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

/// A DNS query for `domain`, as `NewHeaderDNS` builds it.
fn dns_header(domain: &str) -> io::Result<Vec<u8>> {
    let mut header = vec![0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    let mut name = [0; 256];
    let length = pack_domain_name(format!("{domain}.").as_bytes(), &mut name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    header.extend_from_slice(&name[..length]);
    header.extend_from_slice(&[0, 1, 0, 1]);
    Ok(header)
}

/// miekg/dns's `packDomainName` as Xray copies it: dots end labels, a
/// backslash escapes the next byte, and a label is at most 63 bytes.
fn pack_domain_name(name: &[u8], msg: &mut [u8]) -> Result<usize, &'static str> {
    let mut name = name.to_vec();
    let mut end = name.len();
    let mut offset = 0;
    let mut begin = 0;
    let mut i = 0;
    while i < end {
        match name[i] {
            b'\\' => {
                if offset + 1 > msg.len() {
                    return Err("buffer size too small");
                }
                name.copy_within(i + 1..end, i);
                end -= 1;
            }
            b'.' => {
                let label = i - begin;
                if label >= 64 {
                    return Err("bad rdata");
                }
                if offset + 1 + label > msg.len() {
                    return Err("buffer size too small");
                }
                msg[offset] = label as u8;
                msg[offset + 1..offset + 1 + label].copy_from_slice(&name[begin..i]);
                offset += 1 + label;
                begin = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    // Xray slices one byte past its buffer here, and panics.
    if offset >= msg.len() {
        return Err("buffer size too small");
    }
    msg[offset] = 0;
    Ok(offset + 1)
}

#[cfg(test)]
mod tests;
