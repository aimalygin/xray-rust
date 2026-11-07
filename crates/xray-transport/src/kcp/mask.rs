//! mKCP's `finalmask.udp` masks as Xray-core v26.10.31 applies them: the
//! `mkcp-legacy` header, original and AES-128-GCM masks, and noise.
//!
//! Xray applies masks in array order on the way out, so the last one is
//! outermost on the wire. Consecutive legacy masks share one
//! `headerManagerConn`, which drops a datagram over 4096 bytes. Noise sends
//! its packets through the masks after it, and splits the legacy masks into
//! the group before it and the group after it.
use std::{io, ops::Range, time::Duration};

use aes_gcm::{
    aead::{AeadInOut, KeyInit},
    Aes128Gcm, Nonce, Tag,
};
use rand::{Rng, RngCore};
use sha2::{Digest, Sha256};
use tokio::time::Instant;

use super::{KcpHeader, KcpMask};
use crate::udp_noise::UdpNoiseConfig;

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
            KcpMask::Noise => return Ok(None),
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

/// One datagram on the wire.
pub(super) struct Wrapped {
    /// Noise packets due first, each with the pause after it; `None` for
    /// one the masks after noise dropped.
    pub(super) noise: Vec<(Option<Vec<u8>>, Duration)>,
    /// The datagram, unless the masks after noise dropped it.
    pub(super) datagram: Option<Vec<u8>>,
}

/// The masks of one mKCP connection, in Xray's order.
pub(super) struct Masks {
    inner: Group,
    noise: Option<Noise>,
    outer: Group,
}

impl Masks {
    /// The masks `masks` lists. A noise entry takes `noise`.
    pub(super) fn new(masks: &[KcpMask], noise: Option<&UdpNoiseConfig>) -> io::Result<Self> {
        let mut inner = Group::default();
        let mut outer = Group::default();
        let mut seen_noise = None;
        for mask in masks {
            match Legacy::new(mask)? {
                Some(legacy) if seen_noise.is_some() => outer.0.push(legacy),
                Some(legacy) => inner.0.push(legacy),
                None => {
                    let Some(config) = noise else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "an mKCP noise mask without noise settings",
                        ));
                    };
                    if seen_noise.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "mKCP takes one noise mask",
                        ));
                    }
                    config.validate()?;
                    seen_noise = Some(Noise {
                        config: config.clone(),
                        reset_at: None,
                    });
                }
            }
        }
        Ok(Self {
            inner,
            noise: seen_noise,
            outer,
        })
    }

    /// What goes on the wire for `datagram` at `now`; `None` when the masks
    /// before noise drop it.
    pub(super) fn wrap(&mut self, datagram: Vec<u8>, now: Instant) -> Option<Wrapped> {
        let datagram = self.inner.seal(datagram)?;
        let noise = match &self.noise {
            Some(noise)
                if noise
                    .reset_at
                    .is_none_or(|reset_at| noise.config.reset_secs.to > 0 && now > reset_at) =>
            {
                noise
                    .config
                    .items
                    .iter()
                    .map(|item| {
                        let pause = Duration::from_millis(item.delay_ms.sample().into());
                        (self.outer.seal(item.build()), pause)
                    })
                    .collect()
            }
            _ => Vec::new(),
        };
        Some(Wrapped {
            noise,
            datagram: self.outer.seal(datagram),
        })
    }

    /// The noise mask saw a datagram at `now`: noise is due again once the
    /// connection idles past a reset interval drawn afresh.
    pub(super) fn sent(&mut self, now: Instant) {
        if let Some(noise) = &mut self.noise {
            noise.reset_at =
                Some(now + Duration::from_secs(noise.config.reset_secs.sample().into()));
        }
    }

    /// Unwraps a received datagram in place, returning the segments' range.
    pub(super) fn open(&self, buf: &mut [u8]) -> Option<Range<usize>> {
        let range = self.outer.open(buf, 0..buf.len())?;
        self.inner.open(buf, range)
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
