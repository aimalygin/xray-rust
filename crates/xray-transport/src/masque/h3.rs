//! CONNECT-IP over HTTP/3, as Xray-core v26.10.31's `masque.Dial` opens it:
//! one QUIC connection per tunnel, extended CONNECT and RFC 9297 datagrams.
use std::future::poll_fn;

use bytes::Bytes;
use http::{Method, Request};

use super::request::{ascii_authority, request_fields, MasqueRequest, QUIC_GO_USER_AGENT};
use super::session::{
    self, quic_max_packet, Addressing, Datagrams, HttpConnection, MasqueError, MasqueTunnel,
    RequestRecv, RequestSend,
};
use super::warp::MasqueWarp;
use super::MIN_PACKET_SIZE;
use crate::stream::H3QuicConfig;
use crate::stream::{
    connect_quic_transport_with_datagrams, move_udp_carrier, CarrierSocket, H3ConnectConfig,
    H3Error,
};
use crate::{SocketProtector, TlsClientConfig, TlsConnector, TransportError};
use std::net::SocketAddr;
use std::sync::Arc;

/// quic-go's `http3` client limit on response headers, which it announces.
const QUIC_GO_MAX_FIELD_SECTION_SIZE: u64 = 10 << 20;
/// quic-go's `wire.MaxDatagramSize`, the frame size it advertises.
const DATAGRAM_FRAME_SIZE: u16 = 16383;
/// Datagram bytes Quinn holds each way; quic-go queues 128 incoming and 32
/// outgoing datagrams.
const DATAGRAM_RECEIVE_BUFFER: usize = 256 * 1024;
const DATAGRAM_SEND_BUFFER: usize = 64 * 1024;

/// One CONNECT-IP dial over HTTP/3.
#[derive(Clone)]
pub struct MasqueH3Config {
    pub remote_addr: SocketAddr,
    /// Server name and verification; the ALPN is always `h3`.
    pub tls: TlsClientConfig,
    pub socket_protector: Option<Arc<dyn SocketProtector>>,
    pub quic: H3QuicConfig,
    /// The request authority, from [`super::authority`].
    pub authority: String,
    pub request: MasqueRequest,
    /// Cloudflare WARP instead of a CONNECT-IP proxy.
    pub warp: Option<MasqueWarp>,
    /// What a `realm` mask in `quic` takes from the dial, as XHTTP H3's.
    pub realm: Option<crate::realm::RealmEnv>,
    /// The tunnel takes a fresh socket whenever these report that the OS
    /// network changed.
    pub network_changes: Option<crate::NetworkChanges>,
}

impl std::fmt::Debug for MasqueH3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasqueH3Config")
            .field("remote_addr", &self.remote_addr)
            .field("server_name", &self.tls.server_name)
            .field("authority", &self.authority)
            .field("path", &self.request.path)
            .field("quic", &self.quic)
            .field("realm", &self.realm.is_some())
            .finish_non_exhaustive()
    }
}

/// Opens a tunnel. The caller bounds the whole establishment with Xray's
/// ten-second deadline; dropping the future closes what it opened.
pub async fn dial_h3(
    config: MasqueH3Config,
    tls: &TlsConnector,
) -> Result<MasqueTunnel, MasqueError> {
    let warp = config.warp.as_ref();
    let tls_config = match warp {
        Some(warp) => warp
            .tls()
            .and_then(|warp| tls.warp_quic_client_config(&config.tls, b"h3", &warp)),
        None => tls.quic_client_config_for(&config.tls, b"h3"),
    }
    .map_err(|error| MasqueError::Dial(error.to_string()))?;
    let connect = H3ConnectConfig {
        remote_addr: config.remote_addr,
        server_name: config.tls.server_name.clone(),
        tls_config,
        socket_protector: config.socket_protector.clone(),
        quic: config.quic.clone(),
        realm: config.realm.clone(),
        network_changes: None,
    };
    let carrier = connect.quic.hop_carrier();
    let protector = connect.socket_protector.clone();
    let (endpoint, connection, _, wire_peer) = connect_quic_transport_with_datagrams(
        connect,
        b"h3",
        Some((
            DATAGRAM_RECEIVE_BUFFER,
            DATAGRAM_SEND_BUFFER,
            DATAGRAM_FRAME_SIZE,
        )),
        None,
        Default::default(),
        None,
    )
    .await
    .map_err(dial_error)?;
    let mut tasks = Vec::new();
    tasks.extend(move_udp_carrier(
        &endpoint,
        &connection,
        carrier,
        protector,
        wire_peer,
        CarrierSocket::Datagrams,
        config.network_changes.as_ref(),
    ));
    let close = |connection: &quinn::Connection| {
        connection.close(quinn::VarInt::from_u32(0x100), b"");
    };
    let (mut driver, mut send_request) = match h3::client::builder()
        .max_field_section_size(QUIC_GO_MAX_FIELD_SECTION_SIZE)
        .send_grease(false)
        .enable_datagram(true)
        // Xray's WARP dial announces the draft-00 datagram setting too.
        .enable_datagram_draft00(warp.is_some())
        .build::<_, _, Bytes>(h3_quinn::Connection::new(connection.clone()))
        .await
    {
        Ok(client) => client,
        Err(error) => {
            close(&connection);
            return Err(MasqueError::Request(error.to_string()));
        }
    };
    tasks.push(tokio::spawn(async move {
        let _ = poll_fn(|cx| driver.poll_close(cx)).await;
    }));
    let fail = |tasks: &[tokio::task::JoinHandle<()>], error: MasqueError| {
        close(&connection);
        for task in tasks {
            task.abort();
        }
        Err(error)
    };

    // Xray's `ClientConn.Dial`: the server's SETTINGS must allow extended
    // CONNECT and datagrams before the request goes out.
    let Some(settings) = send_request.peer_settings().await else {
        return fail(
            &tasks,
            MasqueError::Request("the connection closed before the server's SETTINGS".into()),
        );
    };
    // Cloudflare needs neither extended CONNECT nor RFC 9297 datagrams:
    // its draft-00 datagrams carry the same frames.
    if !settings.enable_extended_connect() && warp.is_none() {
        return fail(&tasks, MasqueError::NoExtendedConnect);
    }
    let draft = warp.is_some() && settings.enable_datagram_draft00();
    if !settings.enable_datagram() && !draft {
        return fail(&tasks, MasqueError::NoDatagrams);
    }

    let Some(authority) = ascii_authority(&config.authority) else {
        return fail(
            &tasks,
            MasqueError::Request("connect-ip: invalid request authority".into()),
        );
    };
    let mut builder = Request::builder()
        .method(Method::CONNECT)
        .uri(format!("https://{authority}{}", config.request.path))
        .extension(match warp {
            Some(_) => h3::ext::Protocol::CF_CONNECT_IP,
            None => h3::ext::Protocol::CONNECT_IP,
        });
    for (name, value) in request_fields(&config.request, true, Some(QUIC_GO_USER_AGENT)) {
        builder = builder.header(name, value);
    }
    let request = match builder.body(()) {
        Ok(request) => request,
        Err(error) => {
            return fail(
                &tasks,
                MasqueError::Request(format!("connect-ip: failed to create request: {error}")),
            )
        }
    };
    let mut stream = match send_request.send_request(request).await {
        Ok(stream) => stream,
        Err(error) => {
            return fail(
                &tasks,
                MasqueError::Request(format!("connect-ip: failed to send request: {error}")),
            )
        }
    };
    let response = match stream.recv_response().await {
        Ok(response) => response,
        Err(error) => {
            return fail(
                &tasks,
                MasqueError::Request(format!("connect-ip: failed to read response: {error}")),
            )
        }
    };
    let status = response.status().as_u16();
    if !(200..=299).contains(&status) {
        return fail(&tasks, MasqueError::Status(status));
    }
    let quarter_stream_id = stream.id().index();
    let max = quic_max_packet(&connection, quarter_stream_id);
    if max < MIN_PACKET_SIZE {
        return fail(&tasks, MasqueError::PacketSize(max));
    }
    let (send, recv) = stream.split();
    session::start(
        RequestSend::H3(Box::new(send)),
        RequestRecv::H3(recv),
        Datagrams::Quic {
            connection: connection.clone(),
            quarter_stream_id,
        },
        HttpConnection::Quic {
            endpoint,
            connection,
            _send_request: send_request,
            tasks,
        },
        match warp {
            Some(warp) => Addressing::Fixed(warp.addresses.clone()),
            None => Addressing::Request,
        },
    )
    .await
}

fn dial_error(error: H3Error) -> MasqueError {
    match error {
        H3Error::Transport(TransportError::SocketProtection(error)) => {
            MasqueError::SocketProtection(error.to_string())
        }
        error => MasqueError::Dial(error.to_string()),
    }
}
