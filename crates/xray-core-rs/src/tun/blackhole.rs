//! TUN TCP and UDP handling of a selected `blackhole` outbound.

use super::*;
use crate::outbound::{absorb_udp_datagrams, BlackholeOutbound, BLACKHOLE_RESPONSE_GRACE};

/// The routing and lifecycle state of a TUN TCP flow answered by a blackhole.
pub(super) struct BlackholedTcpFlow<'a> {
    pub(super) handle: SocketHandle,
    pub(super) generation: u64,
    pub(super) blackhole: BlackholeOutbound,
    pub(super) outbound_tag: Option<String>,
    pub(super) client_target: &'a Target,
    pub(super) routing_inbound_tag: Option<&'a str>,
    /// Whether sniffing already handed client upload to the bridge.
    pub(super) client_already_opened: bool,
}

/// Answers a TUN TCP flow routed to a blackhole without dialing anything.
///
/// As with Xray's TUN inbound, the client handshake has already completed in
/// the userspace stack. Without a response the flow is closed with FIN at
/// once. With one, the response is queued ahead of the FIN, and client upload
/// is then discarded for at most Xray's one-second response grace, so the
/// client is not reset while it reads the response. Client upload is handed
/// to this task first, so upload that arrives after the task has ended resets
/// the flow, as Xray interrupts the link, instead of filling a receive window
/// that nothing reads.
pub(super) async fn finish_blackholed_tcp_flow(
    flow: BlackholedTcpFlow<'_>,
    context: &TunRuntimeContext,
    mut from_stack: mpsc::Receiver<StackToRemoteData>,
    mut shutdown: watch::Receiver<bool>,
    mut close_guard: TcpBridgeCloseGuard,
) {
    let connection = context.connection_registry.register(
        context.inbound_tag.clone(),
        flow.outbound_tag.clone(),
        flow.client_target.clone(),
    );
    let mut connection_close = connection.close_receiver();
    if context.runtime_logger.is_enabled() {
        let outbound_label = flow.outbound_tag.as_deref().unwrap_or("blackhole");
        crate::debug_log::log_route_decision(
            &context.runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: flow.routing_inbound_tag,
                network: flow.client_target.network,
                original_target: flow.client_target,
                sniffed_protocol: None,
                route_target: flow.client_target,
                dial_target: flow.client_target,
                selected_outbound: outbound_label,
            },
        );
        crate::debug_log::log_access_accepted(
            &context.runtime_logger,
            "tun",
            flow.client_target,
            outbound_label,
        );
    }

    // Hand client upload to this task unless sniffing already did.
    if !flow.client_already_opened {
        let opened = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(&mut shutdown) => false,
            () = wait_for_connection_close(&mut connection_close) => false,
            result = context.stack_tx.send(StackEvent::RemoteOpened {
                handle: flow.handle,
                generation: flow.generation,
                upload_queue_packets: None,
            }) => result.is_ok(),
        };
        if !opened {
            // Dropping the armed guard resets the flow, as for host close.
            connection.finish();
            return;
        }
    }

    let response = flow.blackhole.response_bytes();
    if response.is_empty() {
        close_guard.close().await;
        connection.finish();
        return;
    }
    let serial = Arc::new(tokio::sync::Mutex::new(()));
    let delivered = tokio::select! {
        biased;
        () = wait_for_tun_shutdown(&mut shutdown) => false,
        () = wait_for_connection_close(&mut connection_close) => false,
        result = send_remote_data(
            &context.stack_tx,
            &serial,
            flow.handle,
            flow.generation,
            Bytes::from_static(response),
        ) => result.is_ok(),
    };
    if !delivered {
        // Dropping the armed guard resets the flow, as for host close.
        connection.finish();
        return;
    }
    close_guard.close().await;
    let _ = tokio::time::timeout(BLACKHOLE_RESPONSE_GRACE, async {
        loop {
            tokio::select! {
                biased;
                () = wait_for_tun_shutdown(&mut shutdown) => break,
                () = wait_for_connection_close(&mut connection_close) => break,
                upload = from_stack.recv() => if upload.is_none() {
                    break;
                },
            }
        }
    })
    .await;
    connection.finish();
}

/// Absorbs a TUN UDP flow routed to a blackhole without opening a socket.
///
/// Xray dispatches the flow once. Its TUN inbound returns an `http` response
/// as one datagram from the original destination, and the blackhole then
/// discards later datagrams until the flow is idle, so they are not routed
/// again. Nothing answers with ICMP. The flow stays registered as one
/// connection until it has been idle for [`UDP_IDLE_TIMEOUT`].
pub(super) async fn absorb_blackholed_udp_flow(
    key: UdpFlowKey,
    generation: u64,
    blackhole: BlackholeOutbound,
    context: &TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    connection: ConnectionLease,
) {
    let mut connection_close = connection.close_receiver();
    connection.mark_active();
    let response = blackhole.response_bytes();
    if !response.is_empty() {
        tokio::select! {
            biased;
            () = wait_for_tun_shutdown(&mut shutdown) => {}
            () = wait_for_connection_close(&mut connection_close) => {}
            _ = context.stack_tx.send(StackEvent::UdpDatagram {
                client: key.client.into_endpoint(),
                source: key.target.into_endpoint(),
                payload: Bytes::from_static(response),
            }) => {}
        }
    }
    absorb_udp_datagrams(
        &mut from_stack,
        &mut shutdown,
        &mut connection_close,
        UDP_IDLE_TIMEOUT,
    )
    .await;
    let _ = context
        .stack_tx
        .send(StackEvent::UdpClosed { key, generation })
        .await;
    connection.finish();
}
