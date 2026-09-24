use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "SOCKS flow owns admission, client address, routing and shutdown"
)]
pub(super) async fn bridge(
    target: Target,
    client_visible_target: Option<Target>,
    outbound: UdpOutbound,
    context: SocksUdpFlowContext,
    from_client: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
    pending_open_permit: OwnedSemaphorePermit,
    connection: ConnectionLease,
    mut connection_close: watch::Receiver<bool>,
) {
    let traffic = connection.traffic();
    let flow = async {
        let session = crate::outbound::datagram::open(
            &outbound,
            &target,
            context.dns_resolvers.destination.as_ref(),
            context.dns_resolvers.bootstrap.as_ref(),
            context.transport_dialer.as_ref(),
        )
        .await?;
        drop(pending_open_permit);
        connection.mark_active();
        crate::debug_log::log_access_accepted(
            &context.runtime_logger,
            &context.client_addr.to_string(),
            &target,
            crate::debug_log::udp_outbound_label(&outbound),
        );
        crate::outbound::datagram::relay_udp(
            session,
            &target,
            from_client,
            first_payload,
            &traffic,
            SOCKS_UDP_FLOW_IDLE_TIMEOUT,
            None,
            |source, payload| {
                let source = client_visible_target.clone().unwrap_or(source);
                let socket = &context.client_socket;
                let addr = context.client_addr;
                async move {
                    let packet = encode_socks5_udp_datagram(&source, &payload)
                        .map_err(std::io::Error::other)?;
                    socket.send_to(&packet, addr).await.map(|_| ())
                }
            },
        )
        .await
    };
    if *shutdown.borrow() || *connection_close.borrow() {
        return;
    }
    tokio::select! {
        biased;
        () = wait_for_connection_close(&mut connection_close) => {},
        _ = shutdown.changed() => {},
        result = flow => { let _ = result; },
    }
    connection.finish();
}
