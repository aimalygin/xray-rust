use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "TUN flow owns stack identity, routing, queues and shutdown"
)]
pub(super) async fn bridge(
    key: UdpFlowKey,
    generation: u64,
    target: Target,
    outbound: UdpOutbound,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
    connection: ConnectionLease,
    mut connection_close: watch::Receiver<bool>,
) {
    let traffic = connection.traffic();
    {
        let flow = async {
            let session = crate::outbound::datagram::open(
                &outbound,
                &target,
                context.dns_resolver.as_ref(),
                context.bootstrap_dns_resolver(),
                &context.transport_dialer,
            )
            .await
            .inspect_err(|_| context.tun.record_udp_open_error())?;
            connection.mark_active();
            context.tun.record_udp_remote_open(target.port == 443);
            crate::debug_log::log_access_accepted(
                &context.runtime_logger,
                "tun",
                &target,
                crate::debug_log::udp_outbound_label(&outbound),
            );
            crate::outbound::datagram::relay_udp(
                session,
                &target,
                from_stack,
                first_payload,
                &traffic,
                UDP_IDLE_TIMEOUT,
                Some(&context.tun),
                |_source, payload| {
                    let stack = &context.stack_tx;
                    async move {
                        stack
                            .send(StackEvent::UdpDatagram {
                                client: key.client.into_endpoint(),
                                source: key.target.into_endpoint(),
                                payload,
                            })
                            .await
                            .map_err(|_| std::io::Error::other("TUN stack closed"))
                    }
                },
            )
            .await
        };
        if !*shutdown.borrow() && !*connection_close.borrow() {
            tokio::select! {
                biased;
                () = wait_for_connection_close(&mut connection_close) => {},
                _ = shutdown.changed() => {},
                result = flow => {
                    let _ = result;
                },
            }
        }
    }
    let _ = context
        .stack_tx
        .send(StackEvent::UdpClosed { key, generation })
        .await;
    connection.finish();
}
