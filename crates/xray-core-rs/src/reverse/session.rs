//! A session the portal opened, routed as if an inbound tagged
//! `reverse.tag` had accepted it: the client is the portal's, the user the
//! outbound's email, sniffing the reverse settings'. TCP relays here; UDP
//! takes the SOCKS UDP relays, each destination a flow of its own.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use xray_config::RouteContext;
use xray_routing::{Network, Target};

use super::mux::NewSession;
use super::{client_label, BridgeContext};
use crate::connection::wait_for_connection_close;
use crate::dns_outbound_runtime::FakeIpTargetProvenance;
use crate::outbound::{
    final_rules, open_tcp_stream_with_resolvers_and_dialer, InboundSource, TcpSessionOutbound,
};
use crate::policy::{copy_bidirectional_with_idle_timeout_and_traffic, EffectivePolicy};
use xray_transport::BoxedTransportStream;

/// Serves one session to its end.
pub(super) async fn serve(
    context: Arc<BridgeContext>,
    new: NewSession,
    shutdown: watch::Receiver<bool>,
) {
    let NewSession {
        target,
        source,
        local,
        session,
    } = new;
    // A session needs a destination; the control session alone goes to
    // port 0.
    if target.port == 0 {
        session.finish(true);
        return;
    }
    match target.network {
        Network::Tcp => {
            let failed = serve_tcp(&context, session.clone(), target, source, local).await;
            session.finish(failed);
        }
        Network::Udp => {
            crate::socks::relay_reverse_udp_session(
                &context,
                session.clone(),
                target,
                source,
                local,
                shutdown,
            )
            .await;
            session.finish(false);
        }
    }
}

/// The inbound side's policy for a session: the outbound user's level for
/// its handshake and buffer, and no timer of its own, as Xray-core's Mux
/// worker keeps none; the outbound's timers alone apply.
fn session_policy(context: &BridgeContext) -> EffectivePolicy {
    EffectivePolicy {
        conn_idle: Duration::MAX,
        uplink_only: Duration::MAX,
        downlink_only: Duration::MAX,
        ..context.policy
    }
}

/// Routes and relays one TCP session. Returns whether it failed, which the
/// End's error flag tells the portal.
async fn serve_tcp(
    context: &BridgeContext,
    mut session: super::Session,
    target: Target,
    source: Option<std::net::SocketAddr>,
    local: Option<std::net::SocketAddr>,
) -> bool {
    let logger = &context.logger;
    let label = logger.is_enabled().then(|| client_label(source));
    let sniffing = context.reverse.sniffing.as_ref();
    let restored = context.dns.outbound.restore_client_target(&target);
    let provenance = restored.provenance;
    let sniffed_routing = context.router.sniffed_routing();
    let sniff = (crate::socks::fake_ip_allows_content_sniffing(provenance)
        || sniffed_routing.tcp())
        && crate::sniffing::should_sniff_tcp(sniffing, sniffed_routing.tcp());
    let mut route_target = restored.target.clone();
    let mut dial_target = restored.target;
    let mut initial_payload = Bytes::new();
    let mut sniffed_protocol = None;
    let mut protocol = None;
    let mut attributes = None;
    if let (true, Some(config)) = (sniff, sniffing) {
        let (payload, sniffed) = crate::socks::read_tcp_sniff_payload(
            &mut session,
            config,
            &dial_target,
            sniffed_routing.attributes,
        )
        .await;
        initial_payload = payload;
        attributes = sniffed.attributes;
        if let Some(sniffed) = sniffed.sniffed {
            protocol = Some(sniffed.protocol);
            if let Some(sniffed) = sniffed
                .target
                .filter(|_| crate::socks::fake_ip_allows_content_sniffing(provenance))
            {
                let sniffed =
                    crate::socks::apply_fake_ip_sniffed_dial_precedence(provenance, sniffed);
                sniffed_protocol = Some(sniffed.protocol);
                route_target = sniffed.route_target;
                dial_target = sniffed.dial_target;
            }
        }
    }
    let protocol = crate::sniffing::routing_protocol(
        protocol,
        provenance == FakeIpTargetProvenance::Mapped,
        sniffing,
    );
    let route = RouteContext {
        inbound_tag: Some(context.reverse.tag.as_str()),
        source,
        local,
        user: context.user(),
        protocol: protocol.map(crate::sniffing::SniffedProtocol::name),
        attributes: attributes.as_ref(),
    };
    let selected = match context
        .router
        .select_tcp_session_outbound_with_tag_and_resolver(
            &route,
            &route_target,
            &dial_target,
            true,
            context.dns.destination.as_ref(),
        )
        .await
    {
        Ok(selected) => selected,
        Err(error) => {
            if let Some(label) = label.as_deref() {
                crate::debug_log::log_access_rejected(logger, label, &route_target, error);
            }
            return true;
        }
    };
    let connection = context.registry.register(
        Some(context.reverse.tag.clone()),
        selected.tag.clone(),
        dial_target.clone(),
    );
    let mut connection_close = connection.close_receiver();
    let traffic = connection.traffic();
    if logger.is_enabled() {
        let selected_outbound = match &selected.outbound {
            TcpSessionOutbound::Transport(outbound) => {
                crate::debug_log::tcp_outbound_label(outbound)
            }
            TcpSessionOutbound::Dns(_) => "dns",
            TcpSessionOutbound::Blackhole(_) => "blackhole",
        };
        crate::debug_log::log_route_decision(
            logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: Some(context.reverse.tag.as_str()),
                network: target.network,
                original_target: &target,
                sniffed_protocol,
                route_target: &route_target,
                dial_target: &dial_target,
                selected_outbound,
            },
        );
    }

    let inbound_policy = session_policy(context);
    let outbound = match selected.outbound {
        TcpSessionOutbound::Transport(outbound) => outbound.for_reverse(),
        TcpSessionOutbound::Dns(outbound) => {
            if let Some(label) = label.as_deref() {
                crate::debug_log::log_access_accepted(logger, label, &dial_target, "dns");
            }
            connection.mark_active();
            let served = tokio::select! {
                result = context.dns.outbound.serve_tcp_stream(
                    &mut session,
                    initial_payload,
                    &outbound,
                    &dial_target,
                    inbound_policy.conn_idle,
                ) => result.is_err(),
                () = wait_for_connection_close(&mut connection_close) => true,
            };
            connection.finish();
            return served;
        }
        TcpSessionOutbound::Blackhole(blackhole) => {
            if let Some(label) = label.as_deref() {
                crate::debug_log::log_access_accepted(logger, label, &dial_target, "blackhole");
            }
            tokio::select! {
                () = blackhole.finish_stream(&mut session) => {}
                () = wait_for_connection_close(&mut connection_close) => {}
            }
            connection.finish();
            return false;
        }
    };

    let (open_timeout, relay_timeouts, relay_buffer_size) =
        crate::socks::tcp_relay_policy(&context.config, &inbound_policy, &outbound);
    let client = outbound
        .names_the_client()
        .then(|| source.map(InboundSource::tcp))
        .flatten();
    // Refused before anything is dialed where the chain shares connections
    // (`TcpOutbound::reverse_refusal`); held as a blocked connection is.
    let refusal = tokio::select! {
        result = outbound.reverse_refusal(context.dns.bootstrap.as_ref(), context.dialer.as_ref()) => Some(result),
        () = wait_for_connection_close(&mut connection_close) => None,
    };
    let opened = match refusal {
        None => None,
        Some(Err(error)) => Some(Ok(Err(error))),
        Some(Ok(Some(delay))) => Some(Ok(Ok(
            Box::new(final_rules::BlockedStream::new(delay)) as BoxedTransportStream
        ))),
        Some(Ok(None)) => tokio::select! {
            result = tokio::time::timeout(
                open_timeout,
                open_tcp_stream_with_resolvers_and_dialer(
                    &outbound,
                    &dial_target,
                    context.dns.destination.as_ref(),
                    context.dns.bootstrap.as_ref(),
                    context.dialer.as_ref(),
                    client.as_ref(),
                ),
            ) => Some(result),
            () = wait_for_connection_close(&mut connection_close) => None,
        },
    };
    let mut outbound_stream = match opened {
        None => return true,
        Some(Ok(Ok(stream))) => stream,
        Some(Ok(Err(error))) => {
            if let Some(label) = label.as_deref() {
                crate::debug_log::log_access_rejected(logger, label, &dial_target, error);
            }
            return true;
        }
        Some(Err(_)) => {
            if let Some(label) = label.as_deref() {
                crate::debug_log::log_access_rejected(
                    logger,
                    label,
                    &dial_target,
                    "outbound tcp open timed out",
                );
            }
            return true;
        }
    };
    if let Some(label) = label.as_deref() {
        crate::debug_log::log_access_accepted(
            logger,
            label,
            &dial_target,
            crate::debug_log::tcp_outbound_label(&outbound),
        );
    }
    if !initial_payload.is_empty() {
        if outbound_stream.write_all(&initial_payload).await.is_err() {
            return true;
        }
        traffic.record_uplink(initial_payload.len() as u64);
    }
    connection.mark_active();
    let copied = tokio::select! {
        result = copy_bidirectional_with_idle_timeout_and_traffic(
            &mut session,
            &mut outbound_stream,
            relay_timeouts,
            relay_buffer_size,
            traffic.as_ref(),
        ) => result.is_err(),
        () = wait_for_connection_close(&mut connection_close) => true,
    };
    connection.finish();
    copied
}
