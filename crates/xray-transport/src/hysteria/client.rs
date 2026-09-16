use std::fmt;
use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use h3::client::SendRequest;
use http::{HeaderValue, Method, Request};
use quinn::{Connection, Endpoint, VarInt};
use rand::{distributions::Alphanumeric, Rng};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::stream::{
    connect_quic_transport_with_datagrams, H3ConnectConfig, H3Error, H3QuicConfig,
};
use crate::{TlsClientConfig, TlsConnector, TransportError};

use super::udp::Registry;

const AUTH_HEADER_LIMIT: u64 = 8192;
const MAX_AUTH_BYTES: usize = 4096;
const QUIC_DATAGRAM_BUFFER: usize = 256 * 1024;
// Match pinned Xray without shrinking Quinn's aggregate receive queue.
const QUIC_DATAGRAM_FRAME_SIZE: u16 = 1200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HysteriaLimits {
    pub max_tcp_streams: usize,
    pub max_udp_sessions: usize,
    pub udp_queue_packets: usize,
    pub udp_queue_bytes: usize,
    pub udp_payload_bytes: usize,
    pub fragment_timeout: Duration,
    pub operation_timeout: Duration,
}

impl Default for HysteriaLimits {
    fn default() -> Self {
        Self {
            max_tcp_streams: 64,
            max_udp_sessions: 32,
            udp_queue_packets: 4,
            udp_queue_bytes: 1024 * 1024,
            udp_payload_bytes: 65535,
            fragment_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(10),
        }
    }
}

impl HysteriaLimits {
    fn validate(&self) -> Result<(), HysteriaError> {
        if !(1..=256).contains(&self.max_tcp_streams)
            || !(1..=128).contains(&self.max_udp_sessions)
            || !(1..=16).contains(&self.udp_queue_packets)
            || !(1..=4 * 1024 * 1024).contains(&self.udp_queue_bytes)
            || !(1..=65535).contains(&self.udp_payload_bytes)
            || self.fragment_timeout.is_zero()
            || self.fragment_timeout > Duration::from_secs(30)
            || self.operation_timeout.is_zero()
            || self.operation_timeout > Duration::from_secs(60)
        {
            return Err(HysteriaError::Configuration);
        }
        Ok(())
    }
}

/// One resolved server candidate. Endpoint resolution belongs to the core DNS
/// policy; the socket protector is taken from the supplied TLS connector.
pub struct HysteriaConfig {
    pub remote_addr: SocketAddr,
    pub tls: TlsClientConfig,
    pub auth: Zeroizing<String>,
    pub quic: H3QuicConfig,
    pub limits: HysteriaLimits,
}

impl HysteriaConfig {
    pub fn new(remote_addr: SocketAddr, tls: TlsClientConfig, auth: String) -> Self {
        Self {
            remote_addr,
            tls,
            auth: Zeroizing::new(auth),
            limits: HysteriaLimits::default(),
            quic: H3QuicConfig {
                max_idle_timeout: Duration::from_secs(30),
                ..H3QuicConfig::default()
            },
        }
    }
}

impl fmt::Debug for HysteriaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaConfig")
            .field("remote_addr", &self.remote_addr)
            .field("auth", &"<redacted>")
            .field("quic", &self.quic)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Stage-specific errors deliberately omit untrusted server messages, HTTP
/// headers, credentials and QUIC application-close reason bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HysteriaError {
    #[error("invalid or unsupported Hysteria configuration")]
    Configuration,
    #[error("could not build Hysteria TLS policy")]
    TlsConfiguration,
    #[error("Hysteria UDP socket protection failed")]
    SocketProtection,
    #[error("Hysteria QUIC connection failed")]
    Connect,
    #[error("Hysteria operation timed out")]
    Timeout,
    #[error("Hysteria HTTP/3 authentication failed")]
    Authentication,
    #[error("invalid Hysteria authentication response headers")]
    AuthenticationHeaders,
    #[error("Hysteria connection is closed")]
    Closed,
    #[error("Hysteria session limit reached")]
    SessionLimit,
    #[error("invalid Hysteria target")]
    Target,
    #[error("Hysteria TCP request was rejected")]
    TcpRejected,
    #[error("invalid Hysteria TCP response")]
    TcpResponse,
    #[error("Hysteria stream failed")]
    Stream,
    #[error("Hysteria server does not support UDP")]
    UdpUnsupported,
    #[error("Hysteria UDP message exceeds the supported size")]
    DatagramSize,
    #[error("Hysteria UDP send failed")]
    DatagramSend,
}

type AuthSender = SendRequest<h3_quinn::OpenStreams, Bytes>;

// Owns the connection as soon as it exists, including authentication errors
// and cancellation before a usable client can be returned.
struct Connecting {
    endpoint: Option<Endpoint>,
    connection: Connection,
    driver: Option<JoinHandle<()>>,
}

impl Drop for Connecting {
    fn drop(&mut self) {
        if let Some(endpoint) = &self.endpoint {
            self.connection.close(VarInt::from_u32(0x100), b"");
            endpoint.close(VarInt::from_u32(0x100), b"");
        }
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}

#[derive(Default)]
struct RebindRequest {
    pending: AtomicBool,
    wake: Notify,
}

pub(super) struct Shared {
    connection: Mutex<Option<Connection>>,
    endpoint: Mutex<Option<Endpoint>>,
    // Last h3 SendRequest drop closes its connection. Retain it after auth.
    auth_sender: Mutex<Option<AuthSender>>,
    h3_driver: JoinHandle<()>,
    pub udp_driver: Mutex<Option<JoinHandle<()>>>,
    closed: AtomicBool,
    rebind: Arc<RebindRequest>,
    rebind_driver: Mutex<Option<JoinHandle<()>>>,
    bind_addr: SocketAddr,
    protector: Option<Arc<dyn crate::SocketProtector>>,
    pub limits: HysteriaLimits,
    pub tcp_slots: Arc<Semaphore>,
    pub udp: Arc<Registry>,
    pub udp_enabled: bool,
}

impl Shared {
    pub fn is_live(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self
                .connection
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .as_ref()
                .is_some_and(|connection| connection.close_reason().is_none())
            && !self.h3_driver.is_finished()
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Some(connection) = self
            .connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            connection.close(VarInt::from_u32(0x100), b"");
        }
        self.auth_sender
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(endpoint) = self
            .endpoint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            endpoint.close(VarInt::from_u32(0x100), b"");
        }
        if let Some(task) = self
            .rebind_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
        self.tcp_slots.close();
        self.h3_driver.abort();
        if let Some(task) = self
            .udp_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
        self.udp.close();
    }

    fn rebind_socket(&self) -> Result<(), HysteriaError> {
        if !self.is_live() {
            return Err(HysteriaError::Closed);
        }
        let socket = UdpSocket::bind(self.bind_addr).map_err(|_| HysteriaError::Connect)?;
        crate::protect_std_udp_socket(&socket, self.protector.as_deref())
            .map_err(|_| HysteriaError::SocketProtection)?;
        socket
            .set_nonblocking(true)
            .map_err(|_| HysteriaError::Connect)?;
        let endpoint = self.endpoint.lock().unwrap_or_else(|e| e.into_inner());
        if self.closed.load(Ordering::Acquire) {
            return Err(HysteriaError::Closed);
        }
        // Runs on the captured Tokio runtime, never on the host/FFI thread.
        // Quinn retains the live QUIC connection and validates the new path.
        endpoint
            .as_ref()
            .ok_or(HysteriaError::Closed)?
            .rebind(socket)
            .map_err(|_| HysteriaError::Connect)
    }

    pub fn connection(&self) -> Result<Connection, HysteriaError> {
        self.connection
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(HysteriaError::Closed)
    }
}

impl Drop for Shared {
    fn drop(&mut self) {
        self.close();
    }
}

/// A single authenticated multiplexed QUIC connection. Clones and live TCP/UDP
/// leases share ownership. Dropping the last lease closes sockets and tasks.
/// Explicit `close` closes all leases; reconnect requires a fresh `connect`.
#[derive(Clone)]
pub struct HysteriaClient {
    pub(super) shared: Arc<Shared>,
}

impl fmt::Debug for HysteriaClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HysteriaClient")
            .field("live", &self.is_live())
            .field("udp_enabled", &self.shared.udp_enabled)
            .finish_non_exhaustive()
    }
}

impl HysteriaClient {
    pub async fn connect(
        config: HysteriaConfig,
        tls: &TlsConnector,
    ) -> Result<Self, HysteriaError> {
        config.limits.validate()?;
        if config.remote_addr.port() == 0
            || config.auth.is_empty()
            || config.auth.len() > MAX_AUTH_BYTES
            || config.tls.fingerprint.is_some()
            || (!config.tls.alpn.is_empty() && config.tls.alpn != ["h3"])
        {
            return Err(HysteriaError::Configuration);
        }
        config
            .quic
            .diagnostics()
            .map_err(|_| HysteriaError::Configuration)?;
        let mut auth = HeaderValue::from_bytes(config.auth.as_bytes())
            .map_err(|_| HysteriaError::Configuration)?;
        auth.set_sensitive(true);
        let deadline = config.limits.operation_timeout;
        timeout(deadline, Self::connect_inner(config, tls, auth))
            .await
            .map_err(|_| HysteriaError::Timeout)?
    }

    async fn connect_inner(
        config: HysteriaConfig,
        tls: &TlsConnector,
        auth: HeaderValue,
    ) -> Result<Self, HysteriaError> {
        let tls_config = tls
            .quic_client_config_for(&config.tls, b"h3")
            .map_err(|_| HysteriaError::TlsConfiguration)?;
        let (endpoint, connection, _) = connect_quic_transport_with_datagrams(
            H3ConnectConfig {
                remote_addr: config.remote_addr,
                server_name: config.tls.server_name.clone(),
                tls_config,
                socket_protector: tls.socket_protector_arc(),
                quic: config.quic.clone(),
            },
            b"h3",
            Some((
                QUIC_DATAGRAM_BUFFER,
                QUIC_DATAGRAM_BUFFER,
                QUIC_DATAGRAM_FRAME_SIZE,
            )),
        )
        .await
        .map_err(|error| match error {
            H3Error::Transport(TransportError::SocketProtection(_)) => {
                HysteriaError::SocketProtection
            }
            _ => HysteriaError::Connect,
        })?;
        let mut pending = Connecting {
            endpoint: Some(endpoint),
            connection,
            driver: None,
        };
        let (mut driver, mut sender) = h3::client::builder()
            .max_field_section_size(AUTH_HEADER_LIMIT)
            .build(h3_quinn::Connection::new(pending.connection.clone()))
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        let driver_connection = pending.connection.clone();
        pending.driver = Some(tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
            driver_connection.close(VarInt::from_u32(0x100), b"");
        }));
        let padding = random_padding(256, 2048);
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://hysteria/auth")
            .header("hysteria-auth", auth)
            .header("hysteria-cc-rx", "0")
            .header("hysteria-padding", padding)
            .body(())
            .map_err(|_| HysteriaError::Configuration)?;
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        stream
            .finish()
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        let response = stream
            .recv_response()
            .await
            .map_err(|_| HysteriaError::Authentication)?;
        if response.status().as_u16() != 233 {
            return Err(HysteriaError::Authentication);
        }
        let udp_enabled = parse_auth_headers(response.headers())?;
        stream.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        drop(stream);
        let registry = Arc::new(Registry::new(config.limits));
        let bind_addr = match crate::canonicalize_socket_addr(config.remote_addr).ip() {
            IpAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            IpAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
        };
        let rebind = Arc::new(RebindRequest::default());
        let shared = Arc::new(Shared {
            connection: Mutex::new(Some(pending.connection.clone())),
            endpoint: Mutex::new(pending.endpoint.take()),
            auth_sender: Mutex::new(Some(sender)),
            h3_driver: pending.driver.take().expect("started H3 driver"),
            udp_driver: Mutex::new(None),
            closed: AtomicBool::new(false),
            rebind: rebind.clone(),
            rebind_driver: Mutex::new(None),
            bind_addr,
            protector: tls.socket_protector_arc(),
            limits: config.limits,
            tcp_slots: Arc::new(Semaphore::new(config.limits.max_tcp_streams)),
            udp: registry,
            udp_enabled,
        });
        let owner = Arc::downgrade(&shared);
        let task = tokio::spawn(async move {
            loop {
                rebind.wake.notified().await;
                rebind.pending.store(false, Ordering::Release);
                let Some(shared) = owner.upgrade() else { break };
                if shared.rebind_socket().is_err() {
                    // Do not retain a stale carrier after failed protection/bind.
                    shared.close();
                    break;
                }
            }
        });
        *shared
            .rebind_driver
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(task);
        if udp_enabled {
            let task = super::udp::spawn_receiver(shared.connection()?, Arc::clone(&shared.udp));
            *shared.udp_driver.lock().unwrap_or_else(|e| e.into_inner()) = Some(task);
        }
        Ok(Self { shared })
    }

    pub fn is_live(&self) -> bool {
        self.shared.is_live()
    }
    /// Queue a fresh protected carrier socket on the connection's runtime.
    /// Preserves QUIC/TCP/UDP state and the remote address. A replacement
    /// failure closes the client; true means accepted, not path validation.
    pub fn rebind(&self) -> bool {
        if !self.is_live() {
            return false;
        }
        if !self.shared.rebind.pending.swap(true, Ordering::AcqRel) {
            self.shared.rebind.wake.notify_one();
        }
        true
    }
    pub fn udp_enabled(&self) -> bool {
        self.shared.udp_enabled
    }
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.shared
            .endpoint
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "Hysteria connection closed",
                )
            })?
            .local_addr()
    }
    pub fn close(&self) {
        self.shared.close();
    }
    pub fn active_udp_sessions(&self) -> usize {
        self.shared.udp.len()
    }
}

pub(super) fn random_padding(min: usize, max: usize) -> String {
    let mut rng = rand::thread_rng();
    let length = rng.gen_range(min..max);
    (&mut rng)
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn parse_auth_headers(headers: &http::HeaderMap) -> Result<bool, HysteriaError> {
    let one = |name| {
        let mut values = headers.get_all(name).iter();
        let value = values.next().ok_or(HysteriaError::AuthenticationHeaders)?;
        if values.next().is_some() {
            return Err(HysteriaError::AuthenticationHeaders);
        }
        value
            .to_str()
            .map_err(|_| HysteriaError::AuthenticationHeaders)
    };
    let udp = match one("hysteria-udp")? {
        "true" | "True" | "TRUE" | "t" | "T" | "1" => true,
        "false" | "False" | "FALSE" | "f" | "F" | "0" => false,
        _ => return Err(HysteriaError::AuthenticationHeaders),
    };
    let rate = one("hysteria-cc-rx")?;
    if rate != "auto"
        && (rate.is_empty()
            || !rate.bytes().all(|b| b.is_ascii_digit())
            || rate.parse::<u64>().is_err())
    {
        return Err(HysteriaError::AuthenticationHeaders);
    }
    // Only adaptive BBR/Reno modes are exposed. As with Xray's explicit BBR/Reno
    // modes, the advertised Brutal rate does not select fixed-rate congestion.
    Ok(udp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_response_requires_single_valid_udp_and_rate_headers() {
        let mut headers = http::HeaderMap::new();
        headers.insert("hysteria-udp", HeaderValue::from_static("True"));
        headers.insert(
            "hysteria-cc-rx",
            HeaderValue::from_static("18446744073709551615"),
        );
        assert_eq!(parse_auth_headers(&headers), Ok(true));
        for value in ["", "+1", "-1", "18446744073709551616", "AUTO", "1,2"] {
            headers.insert("hysteria-cc-rx", HeaderValue::from_str(value).unwrap());
            assert_eq!(
                parse_auth_headers(&headers),
                Err(HysteriaError::AuthenticationHeaders)
            );
        }
        headers.insert("hysteria-cc-rx", HeaderValue::from_static("auto"));
        headers.append("hysteria-udp", HeaderValue::from_static("false"));
        assert_eq!(
            parse_auth_headers(&headers),
            Err(HysteriaError::AuthenticationHeaders)
        );
        headers.remove("hysteria-udp");
        assert_eq!(
            parse_auth_headers(&headers),
            Err(HysteriaError::AuthenticationHeaders)
        );
        headers.insert("hysteria-udp", HeaderValue::from_static("0"));
        assert_eq!(parse_auth_headers(&headers), Ok(false));
        headers.append("hysteria-cc-rx", HeaderValue::from_static("0"));
        assert_eq!(
            parse_auth_headers(&headers),
            Err(HysteriaError::AuthenticationHeaders)
        );
    }
}
