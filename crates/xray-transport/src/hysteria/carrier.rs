//! Optional Hysteria UDP carrier transforms. The ordinary carrier never enters
//! this wrapper. Port changes use Quinn's bounded current/previous socket pair.
use std::{
    fmt,
    io::{self, IoSliceMut},
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use blake2::{digest::consts::U32, Blake2b, Digest};
#[cfg(not(target_os = "macos"))]
use quinn::Runtime;
use quinn::{udp, AsyncUdpSocket, UdpPoller};
use rand::{Rng, RngCore};
use zeroize::{Zeroize, Zeroizing};

use super::HysteriaError;
use crate::stream::H3UdpHopConfig;

pub(crate) const SALT_LEN: usize = 8;

/// Xray Salamander and UDP-hop options. Empty options preserve the native path.
#[derive(Clone, Default)]
pub struct HysteriaCarrierConfig {
    pub salamander_password: Option<Arc<Zeroizing<String>>>,
    pub udp_hop: H3UdpHopConfig,
}

impl fmt::Debug for HysteriaCarrierConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaCarrierConfig")
            .field("salamander", &self.salamander_password.is_some())
            .field("udp_hop", &self.udp_hop)
            .finish()
    }
}

impl HysteriaCarrierConfig {
    pub(crate) fn validate(&self) -> Result<(), HysteriaError> {
        if self
            .salamander_password
            .as_ref()
            .is_some_and(|p| !(4..=4096).contains(&p.len()))
            || self.udp_hop.ports.len() > 65_535
            || self.udp_hop.ports.contains(&0)
        {
            return Err(HysteriaError::Configuration);
        }
        if !self.udp_hop.ports.is_empty() {
            let (min, max) = self.intervals();
            if min < Duration::from_secs(5)
                || max < min
                || max > Duration::from_secs(i32::MAX as u64)
            {
                return Err(HysteriaError::Configuration);
            }
        }
        Ok(())
    }

    fn intervals(&self) -> (Duration, Duration) {
        let default = |v: Duration| {
            if v.is_zero() {
                Duration::from_secs(30)
            } else {
                v
            }
        };
        (
            default(self.udp_hop.interval_min),
            default(self.udp_hop.interval_max),
        )
    }

    pub(crate) fn enabled(&self) -> bool {
        self.salamander_password.is_some() || !self.udp_hop.ports.is_empty()
    }

    pub(crate) fn next_peer(&self, mut peer: SocketAddr) -> SocketAddr {
        if !self.udp_hop.ports.is_empty() {
            peer.set_port(
                self.udp_hop.ports[rand::thread_rng().gen_range(0..self.udp_hop.ports.len())],
            );
        }
        peer
    }

    pub(crate) fn next_interval(&self) -> Option<Duration> {
        if self.udp_hop.ports.is_empty() {
            return None;
        }
        let (min, max) = self.intervals();
        Some(Duration::from_nanos(
            rand::thread_rng().gen_range(min.as_nanos() as u64..=max.as_nanos() as u64),
        ))
    }
}

pub(crate) fn wrap(
    socket: UdpSocket,
    logical_peer: SocketAddr,
    wire_peer: SocketAddr,
    config: &HysteriaCarrierConfig,
) -> io::Result<Arc<dyn AsyncUdpSocket>> {
    // Socket protection has already happened, before connect or any send.
    #[cfg(target_os = "macos")]
    let inner = crate::connected_quic::wrap(socket, wire_peer)?;
    #[cfg(not(target_os = "macos"))]
    let inner = quinn::TokioRuntime.wrap_udp_socket(socket)?;
    Ok(Arc::new(CarrierSocket {
        inner,
        logical_peer,
        wire_peer,
        password: config.salamander_password.clone(),
        send_buffer: Mutex::new(Vec::with_capacity(1500)),
        receive_buffer: config
            .salamander_password
            .as_ref()
            .map(|_| Mutex::new(vec![0; 65_536].into_boxed_slice())),
    }))
}

struct CarrierSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    logical_peer: SocketAddr,
    wire_peer: SocketAddr,
    password: Option<Arc<Zeroizing<String>>>,
    send_buffer: Mutex<Vec<u8>>,
    receive_buffer: Option<Mutex<Box<[u8]>>>,
}

impl fmt::Debug for CarrierSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaCarrierSocket")
            .field("logical_peer", &self.logical_peer)
            .field("wire_peer", &self.wire_peer)
            .field("salamander", &self.password.is_some())
            .finish_non_exhaustive()
    }
}

fn key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

fn encode(password: &str, salt: [u8; SALT_LEN], input: &[u8], output: &mut [u8]) {
    let mut mask = key(password, &salt);
    output[..SALT_LEN].copy_from_slice(&salt);
    for (i, byte) in input.iter().enumerate() {
        output[SALT_LEN + i] = byte ^ mask[i % mask.len()];
    }
    mask.zeroize();
}

// Compact each GRO segment separately. Removing only the first salt would
// corrupt coalesced datagrams on Linux/Android.
fn decode(password: &str, buffer: &mut [u8], meta: &mut udp::RecvMeta) {
    if meta.stride <= SALT_LEN
        || meta.len > buffer.len()
        || !meta.len.is_multiple_of(meta.stride) && meta.len % meta.stride <= SALT_LEN
    {
        meta.len = 0;
        meta.stride = 1;
        return;
    }
    let mut written = 0;
    for offset in (0..meta.len).step_by(meta.stride) {
        let end = (offset + meta.stride).min(meta.len);
        let mut mask = key(password, &buffer[offset..offset + SALT_LEN]);
        for i in 0..end - offset - SALT_LEN {
            buffer[written + i] = buffer[offset + SALT_LEN + i] ^ mask[i % mask.len()];
        }
        written += end - offset - SALT_LEN;
        mask.zeroize();
    }
    meta.len = written;
    meta.stride -= SALT_LEN;
}

impl AsyncUdpSocket for CarrierSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &udp::Transmit) -> io::Result<()> {
        if transmit.destination != self.logical_peer {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unexpected Hysteria peer",
            ));
        }
        let mut rewritten = udp::Transmit {
            destination: self.wire_peer,
            ..*transmit
        };
        let Some(password) = &self.password else {
            return self.inner.try_send(&rewritten);
        };
        if transmit.contents.len() > 65_507 - SALT_LEN
            || transmit
                .segment_size
                .is_some_and(|size| size == 0 || transmit.contents.len() > size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Salamander requires one bounded datagram",
            ));
        }
        let mut buffer = self.send_buffer.lock().unwrap_or_else(|e| e.into_inner());
        buffer.resize(transmit.contents.len() + SALT_LEN, 0);
        let mut salt = [0; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        encode(password, salt, transmit.contents, &mut buffer);
        rewritten.contents = &buffer;
        rewritten.segment_size = None;
        self.inner.try_send(&rewritten)
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if let (Some(password), Some(scratch)) = (&self.password, &self.receive_buffer) {
            // Quinn allocates receive buffers from its advertised QUIC payload
            // limit, which excludes the salt. Reserve wire overhead separately,
            // including for GRO aggregates, before copying decoded bytes back.
            let mut scratch = scratch.lock().unwrap_or_else(|e| e.into_inner());
            let mut wire = [IoSliceMut::new(&mut scratch)];
            let count = std::task::ready!(self.inner.poll_recv(cx, &mut wire, &mut meta[..1]))?;
            if count == 0 {
                return Poll::Ready(Ok(0));
            }
            if meta[0].addr == self.wire_peer {
                decode(password, &mut scratch, &mut meta[0]);
                meta[0].addr = self.logical_peer;
                if meta[0].len <= bufs[0].len() {
                    bufs[0][..meta[0].len].copy_from_slice(&scratch[..meta[0].len]);
                } else {
                    meta[0].len = 0;
                    meta[0].stride = 1;
                }
            } else {
                meta[0].len = 0;
                meta[0].stride = 1;
            }
            return Poll::Ready(Ok(1));
        }
        let count = std::task::ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (buffer, meta) in bufs.iter_mut().zip(meta).take(count) {
            if meta.addr != self.wire_peer {
                meta.len = 0;
                meta.stride = 1;
                continue;
            }
            meta.addr = self.logical_peer;
            if let Some(password) = &self.password {
                decode(password, buffer, meta);
            }
        }
        Poll::Ready(Ok(count))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
    fn max_transmit_segments(&self) -> usize {
        if self.password.is_some() {
            1
        } else {
            self.inner.max_transmit_segments()
        }
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_blake2b_256_vector_and_gro_boundaries() {
        // Independently generated with Python hashlib.blake2b(digest_size=32).
        // BLAKE2b-512 truncated to 256 bits would NOT match this vector.
        let input = b"Salamander independent wire vector";
        let expected =
            "000102030405060777443fb63daf49e241c27041583d9a8f9c675ee1f82d2a91937784a0f67f81414b57";
        let mut wire = vec![0; input.len() + SALT_LEN];
        encode(
            "synthetic-password",
            [0, 1, 2, 3, 4, 5, 6, 7],
            input,
            &mut wire,
        );
        assert_eq!(
            wire.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            expected
        );
        let stride = wire.len();
        let mut aggregate = wire.clone();
        aggregate.extend_from_slice(&wire);
        let mut short = vec![0; 11];
        encode("synthetic-password", [0xff; 8], b"end", &mut short);
        aggregate.extend_from_slice(&short);
        let mut meta = udp::RecvMeta {
            len: aggregate.len(),
            stride,
            ..Default::default()
        };
        decode("synthetic-password", &mut aggregate, &mut meta);
        assert_eq!(meta.stride, input.len());
        assert_eq!(
            &aggregate[..meta.len],
            [input.as_slice(), input.as_slice(), b"end"].concat()
        );
        for length in 0..=8 {
            let mut invalid = vec![0; stride + length];
            let mut meta = udp::RecvMeta {
                len: invalid.len(),
                stride: if length == 0 { 0 } else { stride },
                ..Default::default()
            };
            decode("synthetic-password", &mut invalid, &mut meta);
            assert_eq!(meta.len, 0);
            assert_eq!(meta.stride, 1);
        }
    }

    #[test]
    fn hop_bounds_defaults_and_secret_redaction() {
        let mut config = HysteriaCarrierConfig::default();
        assert!(!config.enabled());
        assert_eq!(config.next_interval(), None);
        config.salamander_password = Some(Arc::new(Zeroizing::new("secret-synthetic".into())));
        assert!(!format!("{config:?}").contains("secret-synthetic"));
        config.udp_hop.ports = vec![443, 8443];
        config.validate().unwrap();
        assert_eq!(config.next_interval(), Some(Duration::from_secs(30)));
        config.udp_hop.interval_min = Duration::from_secs(4);
        assert!(config.validate().is_err());
        config.udp_hop.interval_min = Duration::from_secs(31);
        assert!(config.validate().is_err());
        config.udp_hop.interval_max = Duration::from_secs(60);
        config.validate().unwrap();
        for _ in 0..100 {
            assert!((Duration::from_secs(31)..=Duration::from_secs(60))
                .contains(&config.next_interval().unwrap()));
            assert!(config
                .udp_hop
                .ports
                .contains(&config.next_peer("127.0.0.1:1000".parse().unwrap()).port()));
        }
        config.udp_hop.ports.push(0);
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn wire_overhead_receive_capacity_and_wrong_peer() {
        use std::future::poll_fn;
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wire_peer = peer.local_addr().unwrap();
        let local = UdpSocket::bind("127.0.0.1:0").unwrap();
        local.set_nonblocking(true).unwrap();
        let logical = "127.0.0.1:1".parse().unwrap();
        let config = HysteriaCarrierConfig {
            salamander_password: Some(Arc::new(Zeroizing::new("synthetic-password".into()))),
            ..Default::default()
        };
        let client = wrap(local, logical, wire_peer, &config).unwrap();
        assert_eq!(client.max_transmit_segments(), 1);
        let input = vec![0xa5; 1472];
        let mut wire = vec![0; input.len() + SALT_LEN];
        encode("synthetic-password", [7; 8], &input, &mut wire);
        let mut destination = client.local_addr().unwrap();
        destination.set_ip(wire_peer.ip());
        peer.send_to(&wire, destination).await.unwrap();
        let mut output = vec![0; input.len()];
        let mut bufs = [IoSliceMut::new(&mut output)];
        let mut meta = [udp::RecvMeta::default()];
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| client.poll_recv(cx, &mut bufs, &mut meta)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(meta[0].addr, logical);
        assert_eq!(meta[0].len, input.len());
        assert_eq!(output, input);
    }
}
