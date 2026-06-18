use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant as StdInstant;

use bytes::{Bytes, BytesMut};
use smoltcp::iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpEndpoint};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Duration};
use xray_config::{CoreConfig, DnsFakeIpConfig};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{protect_udp_socket, DnsResolver, TransportDialer};
use xray_tun::{
    TunEndpoint, TunError, TunTcpFlowSummaryEvent, TunTcpOpenErrorEvent,
    TunTcpRemoteWriteSlowEvent, TunTcpSlowFlowEvent, TunTcpSlowFlowKind, TunUdpResponseGapEvent,
    TunUdpSlowFlowEvent,
};

use crate::outbound::{
    open_tcp_stream_with_resolver_and_dialer,
    open_vless_udp_stream_with_resolver_dialer_and_options, select_tcp_outbound_for_session,
    select_tcp_outbound_for_session_with_tag, select_udp_outbound_for_session, UdpOutbound,
    VlessTcpOutbound, VlessUdpFraming, VlessUdpOpenOptions,
};
use crate::{TunRuntimeOptions, TunRuntimeProfile};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, encode_xudp_new_packet, read_udp_packet,
    read_xudp_packet,
};

const DEFAULT_RANDOM_SEED: u64 = 0x7872_6179_7275_7374;
const ICMPV4_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const DNS_PORT: u16 = 53;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;
const TCP_BUFFER_SIZE: usize = 32 * 1024;
const STACK_EVENT_CHANNEL_DEPTH: usize = 64;
const TCP_BRIDGE_CHANNEL_DEPTH: usize = 256;
// Burst-heavy UDP (DNS fan-out, QUIC fallback retries) overflows a 64-deep
// channel and surfaces as udp_channel_dropped_packets.
const UDP_BRIDGE_CHANNEL_DEPTH: usize = 256;
const BRIDGE_READ_BUFFER_SIZE: usize = 16 * 1024;
const TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES: usize = TCP_BRIDGE_CHANNEL_DEPTH + 1;
const TCP_BRIDGE_WRITE_BATCH_MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_TUN_INBOUND_DRAIN_PER_TICK: usize = 256;
const TCP_REMOTE_DRAIN_MAX_PASSES_PER_TICK: usize = 4;
const TCP_REMOTE_DRAIN_MAX_BYTES_PER_TICK: usize = 4 * 1024 * 1024;
const TCP_SLOW_FLOW_THRESHOLD_MS: u64 = 500;
const TCP_REMOTE_WRITE_SLOW_THRESHOLD_MS: u64 = 500;
const TCP_FLOW_SUMMARY_64KIB_BYTES: u64 = 64 * 1024;
const TCP_FLOW_SUMMARY_128KIB_BYTES: u64 = 128 * 1024;
const TCP_FLOW_SUMMARY_256KIB_BYTES: u64 = 256 * 1024;
const TCP_FLOW_SUMMARY_MIN_BYTES: u64 = 512 * 1024;
const TCP_FLOW_SUMMARY_MILESTONE_BYTES: u64 = 1024 * 1024;
const UDP_SLOW_FLOW_THRESHOLD_MS: u64 = 500;
const UDP_RESPONSE_GAP_THRESHOLD_MS: u64 = 500;
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpRemoteBufferPolicy {
    normal_per_flow_bytes: usize,
    pressure_per_flow_bytes: usize,
    pressure_start_total_bytes: usize,
    pressure_release_total_bytes: usize,
    hard_total_bytes: usize,
}

const MOBILE_TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = TcpRemoteBufferPolicy {
    // Per-flow ceiling matches desktop so a single bulk stream (speedtest) is
    // not capped early; totals stay inside NetworkExtension memory limits.
    normal_per_flow_bytes: 4 * 1024 * 1024,
    pressure_per_flow_bytes: 2 * 1024 * 1024,
    pressure_start_total_bytes: 24 * 1024 * 1024,
    pressure_release_total_bytes: 16 * 1024 * 1024,
    hard_total_bytes: 40 * 1024 * 1024,
};

const DESKTOP_TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = TcpRemoteBufferPolicy {
    normal_per_flow_bytes: 4 * 1024 * 1024,
    pressure_per_flow_bytes: 2 * 1024 * 1024,
    pressure_start_total_bytes: 96 * 1024 * 1024,
    pressure_release_total_bytes: 64 * 1024 * 1024,
    hard_total_bytes: 160 * 1024 * 1024,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpFlowBudgetPolicy {
    max_active_flows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowBudgetPolicy {
    tcp_remote: TcpRemoteBufferPolicy,
    udp: UdpFlowBudgetPolicy,
}

const MOBILE_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: MOBILE_TCP_REMOTE_BUFFER_POLICY,
    udp: UdpFlowBudgetPolicy {
        // Speedtests and DNS-heavy bursts easily exceed 256 concurrent UDP
        // flows; dropping fresh flows shows up as failed probes.
        max_active_flows: 512,
    },
};

const MOBILE_PLUS_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: DESKTOP_TCP_REMOTE_BUFFER_POLICY,
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 512,
    },
};

const DESKTOP_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: DESKTOP_TCP_REMOTE_BUFFER_POLICY,
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 1024,
    },
};

const LOW_MEMORY_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: TcpRemoteBufferPolicy {
        normal_per_flow_bytes: 1024 * 1024,
        pressure_per_flow_bytes: 512 * 1024,
        pressure_start_total_bytes: 12 * 1024 * 1024,
        pressure_release_total_bytes: 8 * 1024 * 1024,
        hard_total_bytes: 20 * 1024 * 1024,
    },
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 128,
    },
};

const THROUGHPUT_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: DESKTOP_TCP_REMOTE_BUFFER_POLICY,
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 2048,
    },
};

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
const FLOW_BUDGET_POLICY: FlowBudgetPolicy = MOBILE_FLOW_BUDGET_POLICY;

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
const FLOW_BUDGET_POLICY: FlowBudgetPolicy = DESKTOP_FLOW_BUDGET_POLICY;

fn flow_budget_policy_for_runtime_options(options: TunRuntimeOptions) -> FlowBudgetPolicy {
    match options.profile {
        TunRuntimeProfile::Default => FLOW_BUDGET_POLICY,
        TunRuntimeProfile::Mobile => MOBILE_FLOW_BUDGET_POLICY,
        TunRuntimeProfile::MobilePlus => MOBILE_PLUS_FLOW_BUDGET_POLICY,
        TunRuntimeProfile::Desktop => DESKTOP_FLOW_BUDGET_POLICY,
        TunRuntimeProfile::LowMemory => LOW_MEMORY_FLOW_BUDGET_POLICY,
        TunRuntimeProfile::Throughput => THROUGHPUT_FLOW_BUDGET_POLICY,
    }
}

#[derive(Debug)]
struct TcpRemoteBufferState {
    policy: TcpRemoteBufferPolicy,
    pending_total_bytes: usize,
    pending_flow_count: usize,
    pressure_active: bool,
}

impl TcpRemoteBufferState {
    fn new(policy: TcpRemoteBufferPolicy) -> Self {
        Self {
            policy,
            pending_total_bytes: 0,
            pending_flow_count: 0,
            pressure_active: false,
        }
    }

    fn can_enqueue_remote_data(&self, flow_pending_bytes: usize, data_len: usize) -> bool {
        let next_total_bytes = self.pending_total_bytes.saturating_add(data_len);
        if next_total_bytes > self.policy.hard_total_bytes {
            return false;
        }

        flow_pending_bytes.saturating_add(data_len) <= self.per_flow_limit()
    }

    fn record_pending_remote_enqueue(&mut self, flow_pending_bytes: usize, data_len: usize) {
        if data_len == 0 {
            return;
        }

        self.pending_total_bytes = self.pending_total_bytes.saturating_add(data_len);
        if flow_pending_bytes == 0 {
            self.pending_flow_count = self.pending_flow_count.saturating_add(1);
        }
        self.refresh_pressure_state();
    }

    fn record_pending_remote_dequeue(&mut self, flow_pending_bytes: usize, data_len: usize) {
        let removed_bytes = data_len.min(flow_pending_bytes);
        if removed_bytes == 0 {
            return;
        }

        self.pending_total_bytes = self.pending_total_bytes.saturating_sub(removed_bytes);
        if removed_bytes == flow_pending_bytes {
            self.pending_flow_count = self.pending_flow_count.saturating_sub(1);
        }
        self.refresh_pressure_state();
    }

    fn record_pending_remote_remove_flow(&mut self, flow_pending_bytes: usize) {
        if flow_pending_bytes == 0 {
            return;
        }

        self.pending_total_bytes = self.pending_total_bytes.saturating_sub(flow_pending_bytes);
        self.pending_flow_count = self.pending_flow_count.saturating_sub(1);
        self.refresh_pressure_state();
    }

    fn pending_total_bytes(&self) -> usize {
        self.pending_total_bytes
    }

    fn pending_flow_count(&self) -> usize {
        self.pending_flow_count
    }

    fn per_flow_limit(&self) -> usize {
        if self.pressure_active {
            self.policy.pressure_per_flow_bytes
        } else {
            self.policy.normal_per_flow_bytes
        }
    }

    fn pressure_active(&self) -> bool {
        self.pressure_active
    }

    fn refresh_pressure_state(&mut self) {
        if self.pressure_active {
            if self.pending_total_bytes <= self.policy.pressure_release_total_bytes {
                self.pressure_active = false;
            }
        } else if self.pending_total_bytes >= self.policy.pressure_start_total_bytes {
            self.pressure_active = true;
        }
    }
}

#[derive(Debug)]
struct FlowBudgetState {
    policy: FlowBudgetPolicy,
    tcp_remote: TcpRemoteBufferState,
    udp_sequence: u64,
    udp_budget_drops: u64,
    udp_evicted_flows: u64,
    udp_channel_dropped_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FakeIpRuntimeConfig {
    ipv4_network: Ipv4Addr,
    ipv4_prefix: u8,
    ttl: u32,
}

impl FakeIpRuntimeConfig {
    fn from_config(config: &DnsFakeIpConfig) -> Option<Self> {
        let IpAddr::V4(ipv4_network) = config.ipv4_pool.network() else {
            return None;
        };
        Some(Self {
            ipv4_network,
            ipv4_prefix: config.ipv4_pool.prefix(),
            ttl: config.ttl,
        })
    }
}

#[derive(Debug)]
struct FakeIpMapper {
    config: FakeIpRuntimeConfig,
    network_base: u32,
    first_offset: u64,
    usable_addresses: u64,
    next_offset: u64,
    by_domain: HashMap<String, Ipv4Addr>,
    by_ipv4: HashMap<Ipv4Addr, String>,
}

impl FakeIpMapper {
    fn new(config: FakeIpRuntimeConfig) -> Option<Self> {
        if config.ipv4_prefix > 32 {
            return None;
        }

        let address_count = 1_u64 << u32::from(32 - config.ipv4_prefix);
        let first_offset = if address_count > 2 { 1 } else { 0 };
        let usable_addresses = if address_count > 2 {
            address_count - 2
        } else {
            address_count
        };
        if usable_addresses == 0 {
            return None;
        }

        let mask = if config.ipv4_prefix == 0 {
            0
        } else {
            u32::MAX << u32::from(32 - config.ipv4_prefix)
        };
        let network_base = u32::from(config.ipv4_network) & mask;

        Some(Self {
            config,
            network_base,
            first_offset,
            usable_addresses,
            next_offset: 0,
            by_domain: HashMap::new(),
            by_ipv4: HashMap::new(),
        })
    }

    fn fake_ipv4_for_domain(&mut self, domain: &str) -> Option<Ipv4Addr> {
        let domain = normalize_dns_domain(domain)?;
        if let Some(ip) = self.by_domain.get(&domain) {
            return Some(*ip);
        }
        if self.by_domain.len() as u64 >= self.usable_addresses {
            return None;
        }

        for _ in 0..self.usable_addresses {
            let offset = self.first_offset + (self.next_offset % self.usable_addresses);
            self.next_offset = self.next_offset.saturating_add(1);
            let Some(raw_ip) = self.network_base.checked_add(u32::try_from(offset).ok()?) else {
                continue;
            };
            let ip = Ipv4Addr::from(raw_ip);
            if self.by_ipv4.contains_key(&ip) {
                continue;
            }

            self.by_domain.insert(domain.clone(), ip);
            self.by_ipv4.insert(ip, domain);
            return Some(ip);
        }

        None
    }

    fn domain_for_ipv4(&self, ip: Ipv4Addr) -> Option<&str> {
        self.by_ipv4.get(&ip).map(String::as_str)
    }

    fn target_for_endpoint(&self, endpoint: IpEndpoint, network: RoutingNetwork) -> Option<Target> {
        let IpAddress::Ipv4(ip) = endpoint.addr else {
            return target_from_endpoint_with_network(endpoint, network);
        };
        let Some(domain) = self.domain_for_ipv4(ip) else {
            return target_from_endpoint_with_network(endpoint, network);
        };
        Some(Target::new(
            RoutingTargetAddr::Domain(domain.to_owned()),
            endpoint.port,
            network,
        ))
    }

    fn fake_dns_response(&mut self, query: &[u8]) -> Option<Bytes> {
        let question = parse_dns_question(query)?;
        match question.qtype {
            DNS_TYPE_A => {
                let ip = self.fake_ipv4_for_domain(&question.domain)?;
                Some(build_dns_response(
                    query,
                    &question,
                    Some(ip),
                    self.config.ttl,
                ))
            }
            DNS_TYPE_AAAA => Some(build_dns_response(query, &question, None, self.config.ttl)),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsQuestion {
    domain: String,
    question_end: usize,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpFlowAdmission {
    Existing,
    Admit { sequence: u64 },
    Drop,
}

impl FlowBudgetState {
    fn new(policy: FlowBudgetPolicy) -> Self {
        Self {
            policy,
            tcp_remote: TcpRemoteBufferState::new(policy.tcp_remote),
            udp_sequence: 0,
            udp_budget_drops: 0,
            udp_evicted_flows: 0,
            udp_channel_dropped_packets: 0,
        }
    }

    fn can_enqueue_remote_data(&self, flow_pending_bytes: usize, data_len: usize) -> bool {
        self.tcp_remote
            .can_enqueue_remote_data(flow_pending_bytes, data_len)
    }

    fn record_pending_remote_enqueue(&mut self, flow_pending_bytes: usize, data_len: usize) {
        self.tcp_remote
            .record_pending_remote_enqueue(flow_pending_bytes, data_len);
    }

    fn record_pending_remote_dequeue(&mut self, flow_pending_bytes: usize, data_len: usize) {
        self.tcp_remote
            .record_pending_remote_dequeue(flow_pending_bytes, data_len);
    }

    fn record_pending_remote_remove_flow(&mut self, flow_pending_bytes: usize) {
        self.tcp_remote
            .record_pending_remote_remove_flow(flow_pending_bytes);
    }

    fn pending_total_bytes(&self) -> usize {
        self.tcp_remote.pending_total_bytes()
    }

    fn pending_flow_count(&self) -> usize {
        self.tcp_remote.pending_flow_count()
    }

    fn per_flow_limit(&self) -> usize {
        self.tcp_remote.per_flow_limit()
    }

    fn pressure_active(&self) -> bool {
        self.tcp_remote.pressure_active()
    }

    fn udp_flow_limit(&self) -> usize {
        self.policy.udp.max_active_flows
    }

    fn udp_budget_drops(&self) -> u64 {
        self.udp_budget_drops
    }

    fn udp_evicted_flows(&self) -> u64 {
        self.udp_evicted_flows
    }

    fn udp_channel_dropped_packets(&self) -> u64 {
        self.udp_channel_dropped_packets
    }

    fn admit_udp_flow(
        &mut self,
        flows: &mut HashMap<UdpFlowKey, UdpFlow>,
        key: UdpFlowKey,
    ) -> UdpFlowAdmission {
        let sequence = self.next_udp_sequence();
        if let Some(flow) = flows.get_mut(&key) {
            flow.last_used_sequence = sequence;
            return UdpFlowAdmission::Existing;
        }

        let limit = self.policy.udp.max_active_flows;
        if limit == 0 {
            self.udp_budget_drops = self.udp_budget_drops.saturating_add(1);
            return UdpFlowAdmission::Drop;
        }

        if flows.len() >= limit {
            if let Some(oldest_key) = flows
                .iter()
                .min_by_key(|(_, flow)| flow.last_used_sequence)
                .map(|(key, _)| *key)
            {
                flows.remove(&oldest_key);
                self.udp_evicted_flows = self.udp_evicted_flows.saturating_add(1);
            }
        }

        if flows.len() >= limit {
            self.udp_budget_drops = self.udp_budget_drops.saturating_add(1);
            return UdpFlowAdmission::Drop;
        }

        UdpFlowAdmission::Admit { sequence }
    }

    fn record_udp_channel_drop(&mut self) {
        self.udp_channel_dropped_packets = self.udp_channel_dropped_packets.saturating_add(1);
    }

    fn next_udp_sequence(&mut self) -> u64 {
        self.udp_sequence = self.udp_sequence.saturating_add(1);
        self.udp_sequence
    }
}

pub(crate) async fn serve_tun_endpoint(
    tun: Arc<TunEndpoint>,
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    tun_runtime_options: TunRuntimeOptions,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut device = PacketDevice::new(1500);
    let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
    iface_config.random_seed = DEFAULT_RANDOM_SEED;
    let mut iface = Interface::new(iface_config, &mut device, Instant::now());
    iface.set_any_ip(true);
    let mut sockets = SocketSet::new(Vec::new());
    let mut tcp_listeners = HashMap::new();
    let mut tcp_flows = HashMap::new();
    let mut flow_budget_state =
        FlowBudgetState::new(flow_budget_policy_for_runtime_options(tun_runtime_options));
    let mut udp_flows = HashMap::new();
    let mut delayed_stack_events = VecDeque::new();
    let (stack_tx, mut stack_rx) = mpsc::channel(STACK_EVENT_CHANNEL_DEPTH);
    let fake_ip_mapper = config
        .dns
        .fake_ip
        .as_ref()
        .and_then(FakeIpRuntimeConfig::from_config)
        .and_then(FakeIpMapper::new)
        .map(|mapper| Arc::new(Mutex::new(mapper)));
    let runtime_context = TunRuntimeContext {
        inbound_tag,
        config,
        dns_resolver,
        transport_dialer,
        stack_tx,
        tun: Arc::clone(&tun),
        tun_runtime_options,
        fake_ip_mapper,
    };

    'runtime: loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            packet = tun.poll_inbound() => {
                match packet {
                    Ok(packet) => {
                        if !process_tun_packet(
                            packet,
                            &tun,
                            &mut sockets,
                            &mut tcp_listeners,
                            &mut udp_flows,
                            &mut flow_budget_state,
                            &runtime_context,
                            shutdown.clone(),
                            &mut device,
                        )
                        .await
                        {
                            break;
                        }
                    }
                    Err(TunError::QueueClosed) => break,
                    Err(_) => {}
                }
            }
            event = stack_rx.recv(), if delayed_stack_events.is_empty() => {
                if let Some(event) = event {
                    apply_or_delay_stack_event(
                        event,
                        &mut delayed_stack_events,
                        &mut tcp_flows,
                        &mut flow_budget_state,
                        &mut udp_flows,
                        &mut device,
                        Some(tun.as_ref()),
                    );
                }
            }
            () = sleep(Duration::from_millis(25)) => {}
        }

        for _ in 0..MAX_TUN_INBOUND_DRAIN_PER_TICK {
            match tun.try_poll_inbound().await {
                Ok(Some(packet)) => {
                    if !process_tun_packet(
                        packet,
                        &tun,
                        &mut sockets,
                        &mut tcp_listeners,
                        &mut udp_flows,
                        &mut flow_budget_state,
                        &runtime_context,
                        shutdown.clone(),
                        &mut device,
                    )
                    .await
                    {
                        break 'runtime;
                    }
                }
                Ok(None) => break,
                Err(TunError::QueueClosed) => break 'runtime,
                Err(_) => {}
            }
        }

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            Some(tun.as_ref()),
        );
        drain_tcp_remote_data_to_sockets(
            &mut iface,
            &mut device,
            &mut sockets,
            &mut tcp_flows,
            &mut flow_budget_state,
        );
        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            Some(tun.as_ref()),
        );
        drain_tcp_remote_data_to_sockets(
            &mut iface,
            &mut device,
            &mut sockets,
            &mut tcp_flows,
            &mut flow_budget_state,
        );
        record_flow_budget_stats(tun.as_ref(), &flow_budget_state, &tcp_flows, &udp_flows);
        iface.poll(Instant::now(), &mut device, &mut sockets);
        open_ready_tcp_flows(
            &mut sockets,
            &mut tcp_listeners,
            &mut tcp_flows,
            &runtime_context,
            shutdown.clone(),
        );
        read_socket_data_to_remote(&tun, &mut sockets, &mut tcp_flows);
        cleanup_closed_tcp_flows(&mut sockets, &mut tcp_flows, &mut flow_budget_state);
        drain_tcp_remote_data_to_sockets(
            &mut iface,
            &mut device,
            &mut sockets,
            &mut tcp_flows,
            &mut flow_budget_state,
        );
        iface.poll(Instant::now(), &mut device, &mut sockets);
        while let Some(packet) = device.pop_outbound() {
            if tun.push_outbound(packet).await.is_err() {
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_tun_packet(
    packet: Bytes,
    tun: &TunEndpoint,
    sockets: &mut SocketSet<'static>,
    tcp_listeners: &mut HashMap<IpEndpoint, SocketHandle>,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
    device: &mut PacketDevice,
) -> bool {
    if let Some(reply) = icmp_echo_reply(&packet) {
        return !matches!(tun.push_outbound(reply).await, Err(TunError::QueueClosed));
    }
    if let Some(reply) = reject_vision_udp443_packet(tun, &packet, context) {
        return !matches!(tun.push_outbound(reply).await, Err(TunError::QueueClosed));
    }
    if let Some(packet) = parse_udp_packet(&packet) {
        if let Some(reply) = context.fake_dns_reply_packet(&packet) {
            return !matches!(tun.push_outbound(reply).await, Err(TunError::QueueClosed));
        }
        handle_udp_packet(packet, udp_flows, flow_budget_state, context, shutdown);
        return true;
    }
    if let Some(endpoint) = tcp_syn_destination(&packet) {
        ensure_tcp_listener(sockets, tcp_listeners, endpoint);
    }
    device.push_inbound(packet);
    true
}

#[derive(Clone)]
struct TunRuntimeContext {
    inbound_tag: Option<String>,
    config: Arc<CoreConfig>,
    dns_resolver: Arc<dyn DnsResolver>,
    transport_dialer: Arc<TransportDialer>,
    stack_tx: mpsc::Sender<StackEvent>,
    tun: Arc<TunEndpoint>,
    tun_runtime_options: TunRuntimeOptions,
    fake_ip_mapper: Option<Arc<Mutex<FakeIpMapper>>>,
}

impl TunRuntimeContext {
    fn target_from_endpoint(
        &self,
        endpoint: IpEndpoint,
        network: RoutingNetwork,
    ) -> Option<Target> {
        let Some(mapper) = &self.fake_ip_mapper else {
            return target_from_endpoint_with_network(endpoint, network);
        };
        mapper.lock().ok()?.target_for_endpoint(endpoint, network)
    }

    fn fake_dns_reply_packet(&self, packet: &UdpTunPacket) -> Option<Bytes> {
        if packet.target.port != DNS_PORT {
            return None;
        }
        let mapper = self.fake_ip_mapper.as_ref()?;
        let response = mapper.lock().ok()?.fake_dns_response(&packet.payload)?;
        build_udp_packet(packet.target, packet.client, &response)
    }
}

#[derive(Debug)]
struct TcpFlow {
    to_remote: mpsc::Sender<Bytes>,
    pending_remote: VecDeque<Bytes>,
    pending_remote_bytes: usize,
    remote_closed: bool,
}

#[derive(Debug)]
struct UdpFlow {
    to_remote: mpsc::Sender<Bytes>,
    last_used_sequence: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpFlowKey {
    client: EndpointKey,
    target: EndpointKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct EndpointKey {
    addr: IpAddr,
    port: u16,
}

impl UdpFlowKey {
    fn new(client: IpEndpoint, target: IpEndpoint) -> Self {
        Self {
            client: EndpointKey::from_endpoint(client),
            target: EndpointKey::from_endpoint(target),
        }
    }
}

impl EndpointKey {
    fn from_endpoint(endpoint: IpEndpoint) -> Self {
        Self {
            addr: match endpoint.addr {
                IpAddress::Ipv4(ip) => IpAddr::V4(ip),
                IpAddress::Ipv6(ip) => IpAddr::V6(ip),
            },
            port: endpoint.port,
        }
    }

    fn into_endpoint(self) -> IpEndpoint {
        IpEndpoint::new(IpAddress::from(self.addr), self.port)
    }
}

#[derive(Debug)]
struct UdpTunPacket {
    client: IpEndpoint,
    target: IpEndpoint,
    payload: Bytes,
}

#[derive(Debug)]
enum StackEvent {
    RemoteData {
        handle: SocketHandle,
        data: Bytes,
    },
    RemoteClosed {
        handle: SocketHandle,
    },
    UdpDatagram {
        client: IpEndpoint,
        source: IpEndpoint,
        payload: Bytes,
    },
    UdpClosed {
        key: UdpFlowKey,
    },
}

fn open_ready_tcp_flows(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<IpEndpoint, SocketHandle>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
) {
    let ready = listeners
        .iter()
        .filter_map(|(endpoint, handle)| {
            let socket = sockets.get::<tcp::Socket>(*handle);
            if socket.is_listening() || flows.contains_key(handle) {
                return None;
            }
            let local_endpoint = socket.local_endpoint()?;
            Some((
                *endpoint,
                *handle,
                context.target_from_endpoint(local_endpoint, RoutingNetwork::Tcp)?,
            ))
        })
        .collect::<Vec<_>>();

    for (endpoint, handle, target) in ready {
        listeners.remove(&endpoint);
        let (to_remote, from_stack) = mpsc::channel(TCP_BRIDGE_CHANNEL_DEPTH);
        flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
            },
        );
        tokio::spawn(bridge_tcp_flow(
            handle,
            target,
            context.clone(),
            from_stack,
            shutdown.clone(),
        ));
    }
}

fn target_from_endpoint_with_network(
    endpoint: IpEndpoint,
    network: RoutingNetwork,
) -> Option<Target> {
    let ip = match endpoint.addr {
        IpAddress::Ipv4(ip) => IpAddr::V4(ip),
        IpAddress::Ipv6(ip) => IpAddr::V6(ip),
    };
    Some(Target::new(
        RoutingTargetAddr::Ip(ip),
        endpoint.port,
        network,
    ))
}

fn normalize_dns_domain(domain: &str) -> Option<String> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

fn parse_dns_question(packet: &[u8]) -> Option<DnsQuestion> {
    if packet.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let question_count = u16::from_be_bytes([packet[4], packet[5]]);
    if question_count != 1 {
        return None;
    }

    let mut offset = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*packet.get(offset)?);
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        let label_end = offset.checked_add(len)?;
        let label = std::str::from_utf8(packet.get(offset..label_end)?).ok()?;
        labels.push(label.to_owned());
        offset = label_end;
    }

    let qtype = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
    let qclass = u16::from_be_bytes([*packet.get(offset + 2)?, *packet.get(offset + 3)?]);
    let domain = normalize_dns_domain(&labels.join("."))?;

    Some(DnsQuestion {
        domain,
        question_end: offset + 4,
        qtype,
        qclass,
    })
}

fn build_dns_response(
    query: &[u8],
    question: &DnsQuestion,
    answer: Option<Ipv4Addr>,
    ttl: u32,
) -> Bytes {
    let has_answer = answer.is_some() && question.qclass == DNS_CLASS_IN;
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let response_flags = 0x8000 | (request_flags & 0x0100) | 0x0080;
    let mut response = Vec::with_capacity(question.question_end + 16);
    response.extend_from_slice(&query[0..2]);
    response.extend_from_slice(&response_flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&(has_answer as u16).to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question.question_end]);

    if let Some(ip) = answer.filter(|_| has_answer) {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&4_u16.to_be_bytes());
        response.extend_from_slice(&ip.octets());
    }

    Bytes::from(response)
}

fn drain_stack_events(
    stack_rx: &mut mpsc::Receiver<StackEvent>,
    delayed_stack_events: &mut VecDeque<StackEvent>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut PacketDevice,
    tun: Option<&TunEndpoint>,
) {
    while let Some(event) = delayed_stack_events.pop_front() {
        if !apply_or_delay_stack_event(
            event,
            delayed_stack_events,
            tcp_flows,
            flow_budget_state,
            udp_flows,
            device,
            tun,
        ) {
            return;
        }
    }

    while let Ok(event) = stack_rx.try_recv() {
        if !apply_or_delay_stack_event(
            event,
            delayed_stack_events,
            tcp_flows,
            flow_budget_state,
            udp_flows,
            device,
            tun,
        ) {
            return;
        }
    }
}

fn apply_or_delay_stack_event(
    event: StackEvent,
    delayed_stack_events: &mut VecDeque<StackEvent>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut PacketDevice,
    tun: Option<&TunEndpoint>,
) -> bool {
    match try_apply_stack_event(event, tcp_flows, flow_budget_state, udp_flows, device) {
        Ok(()) => true,
        Err(event) => {
            if let Some(tun) = tun {
                tun.record_tcp_remote_to_stack_backpressure();
            }
            delayed_stack_events.push_front(event);
            false
        }
    }
}

fn try_apply_stack_event(
    event: StackEvent,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut PacketDevice,
) -> Result<(), StackEvent> {
    match event {
        StackEvent::RemoteData { handle, data } => {
            let Some(flow) = tcp_flows.get_mut(&handle) else {
                return Ok(());
            };
            if !flow_budget_state.can_enqueue_remote_data(flow.pending_remote_bytes, data.len()) {
                return Err(StackEvent::RemoteData { handle, data });
            }
            let pending_before = flow.pending_remote_bytes;
            let next_pending_bytes = pending_before.saturating_add(data.len());
            flow.pending_remote_bytes = next_pending_bytes;
            flow_budget_state.record_pending_remote_enqueue(pending_before, data.len());
            flow.pending_remote.push_back(data);
        }
        StackEvent::RemoteClosed { handle } => {
            if let Some(flow) = tcp_flows.get_mut(&handle) {
                flow.remote_closed = true;
            }
        }
        StackEvent::UdpDatagram {
            client,
            source,
            payload,
        } => {
            if let Some(packet) = build_udp_packet(source, client, &payload) {
                device.push_outbound(packet);
            }
        }
        StackEvent::UdpClosed { key } => {
            udp_flows.remove(&key);
        }
    }
    Ok(())
}

fn record_flow_budget_stats(
    tun: &TunEndpoint,
    flow_budget_state: &FlowBudgetState,
    flows: &HashMap<SocketHandle, TcpFlow>,
    udp_flows: &HashMap<UdpFlowKey, UdpFlow>,
) {
    let mut max_pending_bytes = 0usize;

    for flow in flows.values() {
        if flow.pending_remote_bytes > 0 {
            max_pending_bytes = max_pending_bytes.max(flow.pending_remote_bytes);
        }
    }

    tun.record_tcp_pending_remote(
        flow_budget_state.pending_total_bytes(),
        flow_budget_state.pending_flow_count(),
        max_pending_bytes,
        flow_budget_state.per_flow_limit(),
        flow_budget_state.pressure_active(),
    );
    tun.record_flow_budget(
        flows.len(),
        udp_flows.len(),
        flow_budget_state.udp_flow_limit(),
        flow_budget_state.udp_budget_drops(),
        flow_budget_state.udp_evicted_flows(),
        flow_budget_state.udp_channel_dropped_packets(),
    );
}

fn drain_tcp_remote_data_to_sockets(
    iface: &mut Interface,
    device: &mut PacketDevice,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
) {
    let mut drained_bytes = 0usize;
    let mut polled_after_stall = false;

    for _ in 0..TCP_REMOTE_DRAIN_MAX_PASSES_PER_TICK {
        let written = write_remote_data_to_sockets(sockets, flows, flow_budget_state);
        drained_bytes = drained_bytes.saturating_add(written);

        let has_pending_remote_data = flow_budget_state.pending_total_bytes() > 0;
        if written == 0 && !has_pending_remote_data {
            break;
        }
        if written == 0 && polled_after_stall {
            break;
        }

        iface.poll(Instant::now(), device, sockets);

        if drained_bytes >= TCP_REMOTE_DRAIN_MAX_BYTES_PER_TICK {
            break;
        }
        polled_after_stall = written == 0;
    }
}

fn write_remote_data_to_sockets(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
) -> usize {
    let mut written_bytes = 0usize;

    for (handle, flow) in flows {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        while socket.can_send() {
            let Some(front) = flow.pending_remote.front_mut() else {
                break;
            };
            let written = match socket.send_slice(front) {
                Ok(written) => written,
                Err(_) => {
                    socket.abort();
                    break;
                }
            };
            if written == 0 {
                break;
            }
            written_bytes = written_bytes.saturating_add(written);
            let pending_before = flow.pending_remote_bytes;
            if written == front.len() {
                flow.pending_remote_bytes = flow.pending_remote_bytes.saturating_sub(front.len());
                flow_budget_state.record_pending_remote_dequeue(pending_before, front.len());
                flow.pending_remote.pop_front();
            } else {
                *front = front.slice(written..);
                flow.pending_remote_bytes = flow.pending_remote_bytes.saturating_sub(written);
                flow_budget_state.record_pending_remote_dequeue(pending_before, written);
                break;
            }
        }
        if flow.remote_closed && flow.pending_remote.is_empty() && socket.may_send() {
            socket.close();
        }
    }

    written_bytes
}

fn read_socket_data_to_remote(
    tun: &TunEndpoint,
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
) {
    for (handle, flow) in flows {
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        while socket.can_recv() {
            let permit = match flow.to_remote.try_reserve() {
                Ok(permit) => permit,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    tun.record_tcp_stack_to_remote_backpressure();
                    break;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    socket.abort();
                    break;
                }
            };
            let data = match socket.recv(|data| {
                let len = data.len();
                (len, Bytes::copy_from_slice(data))
            }) {
                Ok(data) => data,
                Err(_) => {
                    socket.abort();
                    break;
                }
            };
            if data.is_empty() {
                break;
            }
            tun.record_tcp_stack_to_remote(data.len());
            permit.send(data);
        }
    }
}

fn cleanup_closed_tcp_flows(
    sockets: &mut SocketSet<'static>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
) {
    let closed = flows
        .keys()
        .copied()
        .filter(|handle| !sockets.get::<tcp::Socket>(*handle).is_open())
        .collect::<Vec<_>>();

    for handle in closed {
        if let Some(flow) = flows.remove(&handle) {
            flow_budget_state.record_pending_remote_remove_flow(flow.pending_remote_bytes);
        }
        sockets.remove(handle);
    }
}

fn elapsed_ms_since(start: &StdInstant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn bridge_tcp_flow(
    handle: SocketHandle,
    target: Target,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
) {
    let collect_tcp_timings = context.tun_runtime_options.collect_tcp_timings;
    let tcp_timing_start = collect_tcp_timings.then(StdInstant::now);
    let is_tcp443 = target.port == 443;
    let outbound_result = if collect_tcp_timings {
        select_tcp_outbound_for_session_with_tag(
            &context.config,
            context.inbound_tag.as_deref(),
            &target,
            true,
        )
        .map(|selection| (selection.outbound, selection.tag))
    } else {
        select_tcp_outbound_for_session(&context.config, context.inbound_tag.as_deref(), &target)
            .map(|outbound| (outbound, None))
    };
    let (outbound, outbound_tag) = match outbound_result {
        Ok(selection) => selection,
        Err(error) => {
            context.tun.record_tcp_open_error();
            record_tcp_open_error_event(context.tun.as_ref(), &target, None, error);
            let _ = context
                .stack_tx
                .send(StackEvent::RemoteClosed { handle })
                .await;
            return;
        }
    };
    let stream = match open_tcp_stream_with_resolver_and_dialer(
        &outbound,
        &target,
        context.dns_resolver.as_ref(),
        &context.transport_dialer,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            context.tun.record_tcp_open_error();
            record_tcp_open_error_event(
                context.tun.as_ref(),
                &target,
                outbound_tag.as_deref(),
                error,
            );
            let _ = context
                .stack_tx
                .send(StackEvent::RemoteClosed { handle })
                .await;
            return;
        }
    };
    let tcp_open_duration_ms = if let Some(start) = tcp_timing_start.as_ref() {
        let duration_ms = elapsed_ms_since(start);
        context.tun.record_tcp_open_timing(duration_ms, is_tcp443);
        record_tcp_slow_flow_event(
            context.tun.as_ref(),
            &target,
            TunTcpSlowFlowKind::Open,
            duration_ms,
            0,
        );
        Some(duration_ms)
    } else {
        None
    };

    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    if let (Some(start), Some(open_duration_ms)) = (tcp_timing_start, tcp_open_duration_ms) {
        let mut timing = TcpFirstByteTimingEnabled::new(
            start,
            is_tcp443,
            open_duration_ms,
            outbound_tag.clone(),
        );
        bridge_tcp_flow_loop(
            handle,
            &target,
            context,
            from_stack,
            shutdown,
            &mut remote_reader,
            &mut remote_writer,
            outbound_tag.as_deref(),
            &mut timing,
        )
        .await;
    } else {
        let mut timing = TcpFirstByteTimingDisabled;
        bridge_tcp_flow_loop(
            handle,
            &target,
            context,
            from_stack,
            shutdown,
            &mut remote_reader,
            &mut remote_writer,
            outbound_tag.as_deref(),
            &mut timing,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_tcp_flow_loop<R, W, T>(
    handle: SocketHandle,
    target: &Target,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    remote_reader: &mut R,
    remote_writer: &mut W,
    outbound_tag: Option<&str>,
    timing: &mut T,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: TcpFirstByteTiming,
{
    let mut read_buffer = vec![0; BRIDGE_READ_BUFFER_SIZE];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            data = from_stack.recv() => {
                let Some(data) = data else {
                    break;
                };
                if write_stack_batch_to_remote(
                    remote_writer,
                    target,
                    outbound_tag,
                    data,
                    &mut from_stack,
                    context.tun.as_ref(),
                )
                .await
                .is_err()
                {
                    context.tun.record_tcp_remote_write_error();
                    break;
                }
            }
            read = remote_reader.read(&mut read_buffer) => {
                let read = match read {
                    Ok(read) => read,
                    Err(_) => {
                        context.tun.record_tcp_remote_read_error();
                        break;
                    }
                };
                if read == 0 {
                    context.tun.record_tcp_remote_closed();
                    break;
                }
                timing.record_first_byte(context.tun.as_ref(), target);
                context.tun.record_tcp_remote_read(read);
                timing.record_remote_read(context.tun.as_ref(), target, read);
                if context
                    .stack_tx
                    .send(StackEvent::RemoteData {
                        handle,
                        data: Bytes::copy_from_slice(&read_buffer[..read]),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    let _ = context
        .stack_tx
        .send(StackEvent::RemoteClosed { handle })
        .await;
    timing.record_flow_summary(context.tun.as_ref(), target, true);
}

fn record_tcp_open_error_event(
    tun: &TunEndpoint,
    target: &Target,
    outbound_tag: Option<&str>,
    error: impl std::fmt::Display,
) {
    tun.record_tcp_open_error_event(TunTcpOpenErrorEvent {
        target: slow_flow_target_label(target),
        outbound_tag: outbound_tag.map(ToOwned::to_owned),
        error: error.to_string(),
    });
}

fn record_tcp_slow_flow_event(
    tun: &TunEndpoint,
    target: &Target,
    kind: TunTcpSlowFlowKind,
    open_duration_ms: u64,
    first_byte_duration_ms: u64,
) {
    if target.port != 443 {
        return;
    }
    let measured_duration_ms = match kind {
        TunTcpSlowFlowKind::Open => open_duration_ms,
        TunTcpSlowFlowKind::FirstByte => first_byte_duration_ms,
    };
    if measured_duration_ms <= TCP_SLOW_FLOW_THRESHOLD_MS {
        return;
    }

    tun.record_tcp_slow_flow_event(TunTcpSlowFlowEvent {
        kind,
        target: slow_flow_target_label(target),
        open_duration_ms,
        first_byte_duration_ms,
    });
}

fn record_tcp_remote_write_slow_event(
    tun: &TunEndpoint,
    target: &Target,
    outbound_tag: Option<&str>,
    duration_ms: u64,
    bytes: usize,
    messages: usize,
) {
    if target.port != 443 {
        return;
    }
    if duration_ms <= TCP_REMOTE_WRITE_SLOW_THRESHOLD_MS {
        return;
    }

    tun.record_tcp_remote_write_slow_event(TunTcpRemoteWriteSlowEvent {
        target: slow_flow_target_label(target),
        outbound_tag: outbound_tag.map(ToOwned::to_owned),
        duration_ms,
        bytes: bytes as u64,
        messages: messages as u64,
    });
}

#[allow(clippy::too_many_arguments)]
fn record_tcp_flow_summary_event(
    tun: &TunEndpoint,
    target: &Target,
    outbound_tag: Option<&str>,
    closed: bool,
    duration_ms: u64,
    open_duration_ms: u64,
    first_byte_duration_ms: u64,
    remote_read_bytes: u64,
    ms_to_64kib: u64,
    ms_to_128kib: u64,
    ms_to_256kib: u64,
    ms_to_512kib: u64,
    ms_to_1mib: u64,
) {
    if target.port != 443 {
        return;
    }
    if remote_read_bytes < TCP_FLOW_SUMMARY_MIN_BYTES {
        return;
    }

    tun.record_tcp_flow_summary_event(TunTcpFlowSummaryEvent {
        target: slow_flow_target_label(target),
        outbound_tag: outbound_tag.map(ToOwned::to_owned),
        closed,
        duration_ms,
        open_duration_ms,
        first_byte_duration_ms,
        remote_read_bytes,
        ms_to_64kib,
        ms_to_128kib,
        ms_to_256kib,
        ms_to_512kib,
        ms_to_1mib,
    });
}

fn record_udp_slow_flow_event(
    tun: &TunEndpoint,
    target: &Target,
    first_response_duration_ms: u64,
    written_bytes: u64,
    read_bytes: u64,
) {
    if target.port != 443 {
        return;
    }
    if first_response_duration_ms <= UDP_SLOW_FLOW_THRESHOLD_MS {
        return;
    }

    tun.record_udp_slow_flow_event(TunUdpSlowFlowEvent {
        target: slow_flow_target_label(target),
        first_response_duration_ms,
        written_bytes,
        read_bytes,
    });
}

fn record_udp_response_gap_event(
    tun: &TunEndpoint,
    target: &Target,
    response_gap_duration_ms: u64,
    written_bytes: u64,
    read_bytes: u64,
) {
    if target.port != 443 {
        return;
    }
    if response_gap_duration_ms <= UDP_RESPONSE_GAP_THRESHOLD_MS {
        return;
    }

    tun.record_udp_response_gap_event(TunUdpResponseGapEvent {
        target: slow_flow_target_label(target),
        response_gap_duration_ms,
        written_bytes,
        read_bytes,
    });
}

fn slow_flow_target_label(target: &Target) -> String {
    match &target.addr {
        RoutingTargetAddr::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
        RoutingTargetAddr::Ip(ip) => format!("{ip}:{}", target.port),
        RoutingTargetAddr::Domain(domain) => format!("{domain}:{}", target.port),
    }
}

trait TcpFirstByteTiming {
    fn record_first_byte(&mut self, tun: &TunEndpoint, target: &Target);
    fn record_remote_read(&mut self, tun: &TunEndpoint, target: &Target, bytes: usize);
    fn record_flow_summary(&mut self, tun: &TunEndpoint, target: &Target, closed: bool);
}

struct TcpFirstByteTimingDisabled;

impl TcpFirstByteTiming for TcpFirstByteTimingDisabled {
    #[inline]
    fn record_first_byte(&mut self, _tun: &TunEndpoint, _target: &Target) {}

    #[inline]
    fn record_remote_read(&mut self, _tun: &TunEndpoint, _target: &Target, _bytes: usize) {}

    #[inline]
    fn record_flow_summary(&mut self, _tun: &TunEndpoint, _target: &Target, _closed: bool) {}
}

struct TcpFirstByteTimingEnabled {
    start: StdInstant,
    is_tcp443: bool,
    outbound_tag: Option<String>,
    open_duration_ms: u64,
    first_byte_duration_ms: u64,
    remote_read_bytes: u64,
    ms_to_64kib: u64,
    ms_to_128kib: u64,
    ms_to_256kib: u64,
    ms_to_512kib: u64,
    ms_to_1mib: u64,
    recorded: bool,
    milestone_512kib_recorded: bool,
    milestone_1mib_recorded: bool,
}

impl TcpFirstByteTimingEnabled {
    fn new(
        start: StdInstant,
        is_tcp443: bool,
        open_duration_ms: u64,
        outbound_tag: Option<String>,
    ) -> Self {
        Self {
            start,
            is_tcp443,
            outbound_tag,
            open_duration_ms,
            first_byte_duration_ms: 0,
            remote_read_bytes: 0,
            ms_to_64kib: 0,
            ms_to_128kib: 0,
            ms_to_256kib: 0,
            ms_to_512kib: 0,
            ms_to_1mib: 0,
            recorded: false,
            milestone_512kib_recorded: false,
            milestone_1mib_recorded: false,
        }
    }
}

impl TcpFirstByteTiming for TcpFirstByteTimingEnabled {
    #[inline]
    fn record_first_byte(&mut self, tun: &TunEndpoint, target: &Target) {
        if self.recorded {
            return;
        }
        let first_byte_duration_ms = elapsed_ms_since(&self.start);
        self.first_byte_duration_ms = first_byte_duration_ms;
        tun.record_tcp_first_byte_timing(first_byte_duration_ms, self.is_tcp443);
        record_tcp_slow_flow_event(
            tun,
            target,
            TunTcpSlowFlowKind::FirstByte,
            self.open_duration_ms,
            first_byte_duration_ms,
        );
        self.recorded = true;
    }

    #[inline]
    fn record_remote_read(&mut self, tun: &TunEndpoint, target: &Target, bytes: usize) {
        let previous_read_bytes = self.remote_read_bytes;
        let read_bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.remote_read_bytes = self.remote_read_bytes.saturating_add(read_bytes);

        if self.ms_to_64kib == 0
            && previous_read_bytes < TCP_FLOW_SUMMARY_64KIB_BYTES
            && self.remote_read_bytes >= TCP_FLOW_SUMMARY_64KIB_BYTES
        {
            self.ms_to_64kib = elapsed_ms_since(&self.start);
        }
        if self.ms_to_128kib == 0
            && previous_read_bytes < TCP_FLOW_SUMMARY_128KIB_BYTES
            && self.remote_read_bytes >= TCP_FLOW_SUMMARY_128KIB_BYTES
        {
            self.ms_to_128kib = elapsed_ms_since(&self.start);
        }
        if self.ms_to_256kib == 0
            && previous_read_bytes < TCP_FLOW_SUMMARY_256KIB_BYTES
            && self.remote_read_bytes >= TCP_FLOW_SUMMARY_256KIB_BYTES
        {
            self.ms_to_256kib = elapsed_ms_since(&self.start);
        }
        if self.ms_to_512kib == 0
            && previous_read_bytes < TCP_FLOW_SUMMARY_MIN_BYTES
            && self.remote_read_bytes >= TCP_FLOW_SUMMARY_MIN_BYTES
        {
            self.ms_to_512kib = elapsed_ms_since(&self.start);
        }
        if self.ms_to_1mib == 0
            && previous_read_bytes < TCP_FLOW_SUMMARY_MILESTONE_BYTES
            && self.remote_read_bytes >= TCP_FLOW_SUMMARY_MILESTONE_BYTES
        {
            self.ms_to_1mib = elapsed_ms_since(&self.start);
        }

        if !self.milestone_512kib_recorded && self.remote_read_bytes >= TCP_FLOW_SUMMARY_MIN_BYTES {
            self.milestone_512kib_recorded = true;
            self.record_flow_summary(tun, target, false);
        }
        if !self.milestone_1mib_recorded
            && self.remote_read_bytes >= TCP_FLOW_SUMMARY_MILESTONE_BYTES
        {
            self.milestone_1mib_recorded = true;
            self.record_flow_summary(tun, target, false);
        }
    }

    #[inline]
    fn record_flow_summary(&mut self, tun: &TunEndpoint, target: &Target, closed: bool) {
        record_tcp_flow_summary_event(
            tun,
            target,
            self.outbound_tag.as_deref(),
            closed,
            elapsed_ms_since(&self.start),
            self.open_duration_ms,
            self.first_byte_duration_ms,
            self.remote_read_bytes,
            self.ms_to_64kib,
            self.ms_to_128kib,
            self.ms_to_256kib,
            self.ms_to_512kib,
            self.ms_to_1mib,
        );
    }
}

trait UdpFirstResponseTiming {
    fn record_written(&mut self, bytes: usize);
    fn record_first_response(&mut self, tun: &TunEndpoint, target: &Target, read_bytes: usize);
}

struct UdpFirstResponseTimingDisabled;

impl UdpFirstResponseTiming for UdpFirstResponseTimingDisabled {
    #[inline]
    fn record_written(&mut self, _bytes: usize) {}

    #[inline]
    fn record_first_response(&mut self, _tun: &TunEndpoint, _target: &Target, _read_bytes: usize) {}
}

struct UdpFirstResponseTimingEnabled {
    start: StdInstant,
    written_bytes: u64,
    pending_gap_start: Option<StdInstant>,
    pending_gap_written_bytes: u64,
    recorded: bool,
}

impl UdpFirstResponseTimingEnabled {
    fn new(start: StdInstant) -> Self {
        Self {
            start,
            written_bytes: 0,
            pending_gap_start: None,
            pending_gap_written_bytes: 0,
            recorded: false,
        }
    }
}

impl UdpFirstResponseTiming for UdpFirstResponseTimingEnabled {
    #[inline]
    fn record_written(&mut self, bytes: usize) {
        if !self.recorded {
            self.written_bytes = self.written_bytes.saturating_add(bytes as u64);
            return;
        }
        if self.pending_gap_start.is_none() {
            self.pending_gap_start = Some(StdInstant::now());
        }
        self.pending_gap_written_bytes =
            self.pending_gap_written_bytes.saturating_add(bytes as u64);
    }

    #[inline]
    fn record_first_response(&mut self, tun: &TunEndpoint, target: &Target, read_bytes: usize) {
        if !self.recorded {
            self.recorded = true;
            record_udp_slow_flow_event(
                tun,
                target,
                elapsed_ms_since(&self.start),
                self.written_bytes,
                read_bytes as u64,
            );
            return;
        }

        let Some(gap_start) = self.pending_gap_start.take() else {
            return;
        };
        let written_bytes = self.pending_gap_written_bytes;
        self.pending_gap_written_bytes = 0;
        record_udp_response_gap_event(
            tun,
            target,
            elapsed_ms_since(&gap_start),
            written_bytes,
            read_bytes as u64,
        );
    }
}

async fn write_stack_batch_to_remote<W>(
    remote_writer: &mut W,
    target: &Target,
    outbound_tag: Option<&str>,
    first: Bytes,
    from_stack: &mut mpsc::Receiver<Bytes>,
    tun: &TunEndpoint,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut batch_messages = 0usize;
    let mut batch_bytes = 0usize;
    let mut batch = BytesMut::with_capacity(first.len().min(TCP_BRIDGE_WRITE_BATCH_MAX_BYTES));
    let mut next = Some(first);

    while let Some(data) = next {
        let data_len = data.len();
        batch.extend_from_slice(&data);

        batch_messages += 1;
        batch_bytes = batch_bytes.saturating_add(data_len);
        if batch_messages >= TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES
            || batch_bytes >= TCP_BRIDGE_WRITE_BATCH_MAX_BYTES
        {
            break;
        }

        next = from_stack.try_recv().ok();
    }

    let write_start = StdInstant::now();
    let write_result = remote_writer.write_all(&batch).await;
    let write_duration_ms = elapsed_ms_since(&write_start);
    tun.record_tcp_remote_write_wait(write_duration_ms);
    record_tcp_remote_write_slow_event(
        tun,
        target,
        outbound_tag,
        write_duration_ms,
        batch_bytes,
        batch_messages,
    );
    write_result?;
    tun.record_tcp_remote_written(batch_bytes);
    let flush_start = StdInstant::now();
    let flush_result = remote_writer.flush().await;
    tun.record_tcp_remote_flush_wait(elapsed_ms_since(&flush_start));
    flush_result?;
    tun.record_tcp_remote_write_batch(batch_messages, batch_bytes);
    Ok(())
}

fn handle_udp_packet(
    packet: UdpTunPacket,
    flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
) {
    let key = UdpFlowKey::new(packet.client, packet.target);

    match flow_budget_state.admit_udp_flow(flows, key) {
        UdpFlowAdmission::Existing => {}
        UdpFlowAdmission::Admit { sequence } => {
            let Some(target) = context.target_from_endpoint(packet.target, RoutingNetwork::Udp)
            else {
                return;
            };
            let udp_timing_start = context
                .tun_runtime_options
                .collect_tcp_timings
                .then(StdInstant::now);
            let (to_remote, from_stack) = mpsc::channel(UDP_BRIDGE_CHANNEL_DEPTH);
            flows.insert(
                key,
                UdpFlow {
                    to_remote,
                    last_used_sequence: sequence,
                },
            );
            tokio::spawn(bridge_udp_flow(
                key,
                target,
                context.clone(),
                from_stack,
                shutdown,
                udp_timing_start,
            ));
        }
        UdpFlowAdmission::Drop => return,
    }

    if let Some(flow) = flows.get(&key) {
        if flow.to_remote.try_send(packet.payload).is_err() {
            flow_budget_state.record_udp_channel_drop();
            flows.remove(&key);
        }
    }
}

async fn bridge_udp_flow(
    key: UdpFlowKey,
    target: Target,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
    udp_timing_start: Option<StdInstant>,
) {
    let outbound = match select_udp_outbound_for_session(
        &context.config,
        context.inbound_tag.as_deref(),
        &target,
    ) {
        Ok(outbound) => outbound,
        Err(_) => {
            context.tun.record_udp_open_error();
            let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
            return;
        }
    };

    match outbound {
        UdpOutbound::Freedom => {
            bridge_udp_freedom_flow(key, target, context, from_stack, shutdown, udp_timing_start)
                .await;
        }
        UdpOutbound::Vless(outbound) => {
            bridge_udp_vless_flow(
                key,
                target,
                outbound,
                context,
                from_stack,
                shutdown,
                udp_timing_start,
            )
            .await;
        }
    }
}

async fn bridge_udp_freedom_flow(
    key: UdpFlowKey,
    target: Target,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
    udp_timing_start: Option<StdInstant>,
) {
    let bind_addr = match key.target.addr {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(_) => {
            context.tun.record_udp_open_error();
            let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
            return;
        }
    };
    if protect_udp_socket(&socket, context.transport_dialer.socket_protector()).is_err() {
        context.tun.record_udp_open_error();
        let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
        return;
    }
    let target_addr = match resolve_udp_freedom_target(&target, context.dns_resolver.as_ref()).await
    {
        Ok(target) => target,
        Err(_) => {
            context.tun.record_udp_open_error();
            let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
            return;
        }
    };
    context.tun.record_udp_remote_open(target.port == 443);
    if let Some(start) = udp_timing_start {
        let mut timing = UdpFirstResponseTimingEnabled::new(start);
        bridge_udp_freedom_flow_loop(
            key,
            target,
            target_addr,
            socket,
            context,
            from_stack,
            shutdown,
            &mut timing,
        )
        .await;
    } else {
        let mut timing = UdpFirstResponseTimingDisabled;
        bridge_udp_freedom_flow_loop(
            key,
            target,
            target_addr,
            socket,
            context,
            from_stack,
            shutdown,
            &mut timing,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_udp_freedom_flow_loop<T>(
    key: UdpFlowKey,
    target: Target,
    target_addr: SocketAddr,
    socket: UdpSocket,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    timing: &mut T,
) where
    T: UdpFirstResponseTiming,
{
    let client = key.client.into_endpoint();
    let response_source = key.target.into_endpoint();
    let mut read_buffer = vec![0; BRIDGE_READ_BUFFER_SIZE];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = sleep(UDP_IDLE_TIMEOUT) => {
                break;
            }
            payload = from_stack.recv() => {
                let Some(payload) = payload else {
                    break;
                };
                let payload_len = payload.len();
                if socket.send_to(&payload, target_addr).await.is_err() {
                    context.tun.record_udp_remote_write_error();
                    break;
                }
                context.tun.record_udp_remote_written(payload_len);
                timing.record_written(payload_len);
            }
            received = socket.recv_from(&mut read_buffer) => {
                let Ok((len, _source)) = received else {
                    context.tun.record_udp_remote_read_error();
                    break;
                };
                timing.record_first_response(context.tun.as_ref(), &target, len);
                context.tun.record_udp_remote_read(len);
                if context
                    .stack_tx
                    .send(StackEvent::UdpDatagram {
                        client,
                        source: response_source,
                        payload: Bytes::copy_from_slice(&read_buffer[..len]),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
}

async fn resolve_udp_freedom_target(
    target: &Target,
    dns_resolver: &dyn DnsResolver,
) -> Result<SocketAddr, crate::CoreError> {
    match &target.addr {
        RoutingTargetAddr::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        RoutingTargetAddr::Domain(domain) => Ok(dns_resolver.resolve(domain, target.port).await?),
    }
}

async fn bridge_udp_vless_flow(
    key: UdpFlowKey,
    target: Target,
    outbound: Box<VlessTcpOutbound>,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
    udp_timing_start: Option<StdInstant>,
) {
    // Regular xtls-rprx-vision cannot carry UDP/443 (QUIC); reject it
    // unconditionally as upstream xray-core does. xtls-rprx-vision-udp443 still
    // allows it. (The packet layer also ICMP-rejects UDP/443 to vision for fast
    // fallback; this is the backstop for any packet that reaches the bridge.)
    let options = VlessUdpOpenOptions::default();
    let (stream, framing) = match open_vless_udp_stream_with_resolver_dialer_and_options(
        &outbound,
        &target,
        context.dns_resolver.as_ref(),
        &context.transport_dialer,
        options,
    )
    .await
    {
        Ok(opened) => opened,
        Err(error) => {
            context.tun.record_udp_open_error();
            if matches!(error, crate::CoreError::VisionUdp443Rejected) {
                context.tun.record_udp_vision_udp443_rejection();
            }
            let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
            return;
        }
    };
    context.tun.record_udp_remote_open(target.port == 443);

    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    if let Some(start) = udp_timing_start {
        let mut timing = UdpFirstResponseTimingEnabled::new(start);
        bridge_udp_vless_flow_loop(
            key,
            target,
            context,
            from_stack,
            shutdown,
            framing,
            &mut remote_reader,
            &mut remote_writer,
            &mut timing,
        )
        .await;
    } else {
        let mut timing = UdpFirstResponseTimingDisabled;
        bridge_udp_vless_flow_loop(
            key,
            target,
            context,
            from_stack,
            shutdown,
            framing,
            &mut remote_reader,
            &mut remote_writer,
            &mut timing,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_udp_vless_flow_loop<R, W, T>(
    key: UdpFlowKey,
    target: Target,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    framing: VlessUdpFraming,
    remote_reader: &mut R,
    remote_writer: &mut W,
    timing: &mut T,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: UdpFirstResponseTiming,
{
    let fallback_source = key.target.into_endpoint();
    let client = key.client.into_endpoint();
    let global_id = udp_flow_global_id(key);
    let mut sent_xudp_new = false;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = sleep(UDP_IDLE_TIMEOUT) => {
                break;
            }
            payload = from_stack.recv() => {
                let Some(payload) = payload else {
                    break;
                };
                let payload_len = payload.len();
                let frame = match framing {
                    VlessUdpFraming::LengthPrefixed => encode_udp_packet(&payload),
                    VlessUdpFraming::Xudp => {
                        if sent_xudp_new {
                            encode_xudp_keep_packet(Some(&target), &payload)
                        } else {
                            sent_xudp_new = true;
                            encode_xudp_new_packet(&target, &payload, global_id)
                        }
                    }
                };
                let Ok(frame) = frame else {
                    break;
                };
                if remote_writer.write_all(&frame).await.is_err() {
                    context.tun.record_udp_remote_write_error();
                    break;
                }
                if remote_writer.flush().await.is_err() {
                    context.tun.record_udp_remote_write_error();
                    break;
                }
                context.tun.record_udp_remote_written(payload_len);
                timing.record_written(payload_len);
            }
            packet = read_vless_udp_response(remote_reader, framing, fallback_source) => {
                let (source, payload) = match packet {
                    Ok(packet) => packet,
                    Err(error) => {
                        if error.kind() == std::io::ErrorKind::UnexpectedEof {
                            context.tun.record_udp_remote_closed();
                        } else {
                            context.tun.record_udp_remote_read_error();
                        }
                        break;
                    }
                };
                timing.record_first_response(context.tun.as_ref(), &target, payload.len());
                context.tun.record_udp_remote_read(payload.len());
                if context
                    .stack_tx
                    .send(StackEvent::UdpDatagram {
                        client,
                        source,
                        payload,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }

    let _ = context.stack_tx.send(StackEvent::UdpClosed { key }).await;
}

fn ensure_tcp_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<IpEndpoint, SocketHandle>,
    endpoint: IpEndpoint,
) {
    if listeners.contains_key(&endpoint) {
        return;
    }

    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
    );
    socket.set_nagle_enabled(false);
    if socket.listen(endpoint).is_ok() {
        listeners.insert(endpoint, sockets.add(socket));
    }
}

/// Replies with ICMP port-unreachable for a UDP/443 datagram that routes to a
/// regular `xtls-rprx-vision` outbound, which cannot carry QUIC. This makes
/// QUIC-preferring apps (YouTube, Chrome) fall back to TCP immediately instead
/// of stalling on a half-open QUIC handshake. Direct/freedom and
/// `xtls-rprx-vision-udp443` outbounds are left untouched, so their UDP/443
/// (including QUIC) keeps flowing.
fn reject_vision_udp443_packet(
    tun: &TunEndpoint,
    packet: &[u8],
    context: &TunRuntimeContext,
) -> Option<Bytes> {
    let view = udp_packet_view_for_destination(packet, 443)?;
    let target = context.target_from_endpoint(view.target, RoutingNetwork::Udp)?;
    let UdpOutbound::Vless(outbound) =
        select_udp_outbound_for_session(&context.config, context.inbound_tag.as_deref(), &target)
            .ok()?
    else {
        return None;
    };
    if !outbound.blocks_udp443() {
        return None;
    }

    let reply = icmp_port_unreachable_reply(packet)?;
    tun.record_udp_vision_udp443_rejection();
    Some(reply)
}

#[derive(Debug, Clone, Copy)]
struct UdpPacketView {
    target: IpEndpoint,
}

fn udp_packet_view_for_destination(packet: &[u8], destination_port: u16) -> Option<UdpPacketView> {
    match packet.first()? >> 4 {
        4 => ipv4_udp_packet_view_for_destination(packet, destination_port),
        6 => ipv6_udp_packet_view_for_destination(packet, destination_port),
        _ => None,
    }
}

fn ipv4_udp_packet_view_for_destination(
    packet: &[u8],
    destination_port: u16,
) -> Option<UdpPacketView> {
    if packet.len() < 28 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 || packet[9] != UDP_PROTOCOL {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }

    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    if u16::from_be_bytes([udp[2], udp[3]]) != destination_port {
        return None;
    }

    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some(UdpPacketView {
        target: IpEndpoint::new(IpAddress::Ipv4(destination), destination_port),
    })
}

#[cfg(test)]
fn ipv4_udp_payload_for_destination(packet: &[u8], destination_port: u16) -> Option<Bytes> {
    let parsed = parse_ipv4_udp_packet(packet)?;
    (parsed.target.port == destination_port).then_some(parsed.payload)
}

fn ipv6_udp_packet_view_for_destination(
    packet: &[u8],
    destination_port: u16,
) -> Option<UdpPacketView> {
    if packet.len() < 48 || packet[6] != UDP_PROTOCOL {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len < 8 || packet.len() < 40 + payload_len {
        return None;
    }

    let udp = &packet[40..40 + payload_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    if u16::from_be_bytes([udp[2], udp[3]]) != destination_port {
        return None;
    }

    let destination = <[u8; 16]>::try_from(&packet[24..40]).ok()?;
    Some(UdpPacketView {
        target: IpEndpoint::new(
            IpAddress::Ipv6(Ipv6Addr::from(destination)),
            destination_port,
        ),
    })
}

fn parse_udp_packet(packet: &[u8]) -> Option<UdpTunPacket> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_udp_packet(packet),
        6 => parse_ipv6_udp_packet(packet),
        _ => None,
    }
}

fn parse_ipv4_udp_packet(packet: &[u8]) -> Option<UdpTunPacket> {
    if packet.len() < 28 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 || packet[9] != UDP_PROTOCOL {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }

    let udp = &packet[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if checksum != 0 && ipv4_udp_checksum(source, destination, &udp[..udp_len]) != 0 {
        return None;
    }

    Some(UdpTunPacket {
        client: IpEndpoint::new(
            IpAddress::Ipv4(source),
            u16::from_be_bytes([udp[0], udp[1]]),
        ),
        target: IpEndpoint::new(
            IpAddress::Ipv4(destination),
            u16::from_be_bytes([udp[2], udp[3]]),
        ),
        payload: Bytes::copy_from_slice(&udp[8..udp_len]),
    })
}

fn parse_ipv6_udp_packet(packet: &[u8]) -> Option<UdpTunPacket> {
    if packet.len() < 48 || packet[6] != UDP_PROTOCOL {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len < 8 || packet.len() < 40 + payload_len {
        return None;
    }

    let source = <[u8; 16]>::try_from(&packet[8..24]).ok()?;
    let destination = <[u8; 16]>::try_from(&packet[24..40]).ok()?;
    let udp = &packet[40..40 + payload_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }
    if ipv6_transport_checksum(source, destination, UDP_PROTOCOL, &udp[..udp_len]) != 0 {
        return None;
    }

    Some(UdpTunPacket {
        client: IpEndpoint::new(
            IpAddress::Ipv6(Ipv6Addr::from(source)),
            u16::from_be_bytes([udp[0], udp[1]]),
        ),
        target: IpEndpoint::new(
            IpAddress::Ipv6(Ipv6Addr::from(destination)),
            u16::from_be_bytes([udp[2], udp[3]]),
        ),
        payload: Bytes::copy_from_slice(&udp[8..udp_len]),
    })
}

fn build_udp_packet(source: IpEndpoint, destination: IpEndpoint, payload: &[u8]) -> Option<Bytes> {
    match (source.addr, destination.addr) {
        (IpAddress::Ipv4(source_addr), IpAddress::Ipv4(destination_addr)) => {
            Some(Bytes::from(build_ipv4_udp_packet(
                source_addr,
                source.port,
                destination_addr,
                destination.port,
                payload,
            )?))
        }
        (IpAddress::Ipv6(source_addr), IpAddress::Ipv6(destination_addr)) => {
            Some(Bytes::from(build_ipv6_udp_packet(
                source_addr,
                source.port,
                destination_addr,
                destination.port,
                payload,
            )?))
        }
        _ => None,
    }
}

async fn read_vless_udp_response<R>(
    reader: &mut R,
    framing: VlessUdpFraming,
    fallback_source: IpEndpoint,
) -> std::io::Result<(IpEndpoint, Bytes)>
where
    R: AsyncRead + Unpin,
{
    match framing {
        VlessUdpFraming::LengthPrefixed => {
            let payload = read_udp_packet(reader).await?;
            Ok((fallback_source, payload))
        }
        VlessUdpFraming::Xudp => {
            let packet = read_xudp_packet(reader).await?;
            let source = packet
                .source
                .as_ref()
                .and_then(target_to_endpoint)
                .unwrap_or(fallback_source);
            Ok((source, packet.payload))
        }
    }
}

fn target_to_endpoint(target: &Target) -> Option<IpEndpoint> {
    let addr = match &target.addr {
        RoutingTargetAddr::Ip(ip) => IpAddress::from(*ip),
        RoutingTargetAddr::Domain(_) => return None,
    };
    Some(IpEndpoint::new(addr, target.port))
}

fn build_ipv4_udp_packet(
    source: Ipv4Addr,
    source_port: u16,
    destination: Ipv4Addr,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let total_len = 20usize.checked_add(udp_len)?;
    let total_len = u16::try_from(total_len).ok()?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;

    let mut packet = vec![0; usize::from(total_len)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = UDP_PROTOCOL;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = &mut packet[20..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum = nonzero_udp_checksum(ipv4_udp_checksum(source, destination, udp));
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    Some(packet)
}

fn build_ipv6_udp_packet(
    source: Ipv6Addr,
    source_port: u16,
    destination: Ipv6Addr,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = 8usize.checked_add(payload.len())?;
    let udp_len_u16 = u16::try_from(udp_len).ok()?;
    let mut packet = vec![0; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    packet[6] = UDP_PROTOCOL;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());

    let udp = &mut packet[40..];
    udp[0..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    udp[8..].copy_from_slice(payload);
    let checksum =
        ipv6_transport_checksum(source.octets(), destination.octets(), UDP_PROTOCOL, udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    Some(packet)
}

fn tcp_syn_destination(packet: &[u8]) -> Option<IpEndpoint> {
    match packet.first()? >> 4 {
        4 => ipv4_tcp_syn_destination(packet),
        6 => ipv6_tcp_syn_destination(packet),
        _ => None,
    }
}

fn ipv4_tcp_syn_destination(packet: &[u8]) -> Option<IpEndpoint> {
    if packet.len() < 40 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 20 {
        return None;
    }
    if packet[9] != TCP_PROTOCOL {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let tcp = &packet[header_len..];
    if !is_initial_tcp_syn(tcp) {
        return None;
    }

    let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Some(IpEndpoint::new(IpAddress::Ipv4(dst_addr), dst_port))
}

fn ipv6_tcp_syn_destination(packet: &[u8]) -> Option<IpEndpoint> {
    if packet.len() < 60 || packet[6] != TCP_PROTOCOL {
        return None;
    }

    let tcp = &packet[40..];
    if !is_initial_tcp_syn(tcp) {
        return None;
    }

    let dst_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Some(IpEndpoint::new(IpAddress::Ipv6(dst_addr), dst_port))
}

fn is_initial_tcp_syn(tcp: &[u8]) -> bool {
    if tcp.len() < 20 {
        return false;
    }
    let flags = tcp[13];
    flags & 0x02 != 0 && flags & 0x10 == 0
}

fn icmp_echo_reply(packet: &[u8]) -> Option<Bytes> {
    match packet.first()? >> 4 {
        4 => ipv4_icmp_echo_reply(packet),
        6 => ipv6_icmp_echo_reply(packet),
        _ => None,
    }
}

fn icmp_port_unreachable_reply(packet: &[u8]) -> Option<Bytes> {
    match packet.first()? >> 4 {
        4 => ipv4_icmp_port_unreachable_reply(packet),
        6 => ipv6_icmp_port_unreachable_reply(packet),
        _ => None,
    }
}

fn ipv4_icmp_echo_reply(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 28 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 {
        return None;
    }
    if packet[9] != ICMPV4_PROTOCOL {
        return None;
    }
    if internet_checksum(&packet[..header_len]) != 0 {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len + 8 || packet.len() < total_len {
        return None;
    }

    let icmp = &packet[header_len..total_len];
    if icmp[0] != 8 || icmp[1] != 0 || internet_checksum(icmp) != 0 {
        return None;
    }

    let icmp_len = icmp.len();
    let total_len = 20 + icmp_len;
    let mut reply = vec![0; total_len];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    reply[8] = 64;
    reply[9] = ICMPV4_PROTOCOL;
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);

    reply[20..].copy_from_slice(icmp);
    reply[20] = 0;
    reply[22] = 0;
    reply[23] = 0;
    let icmp_checksum = internet_checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    let ip_checksum = internet_checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    Some(Bytes::from(reply))
}

fn ipv6_icmp_echo_reply(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 48 || packet[6] != ICMPV6_PROTOCOL {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len < 8 || packet.len() < 40 + payload_len {
        return None;
    }

    let source = <[u8; 16]>::try_from(&packet[8..24]).ok()?;
    let destination = <[u8; 16]>::try_from(&packet[24..40]).ok()?;
    let icmp = &packet[40..40 + payload_len];
    if icmp[0] != 128
        || icmp[1] != 0
        || ipv6_transport_checksum(source, destination, ICMPV6_PROTOCOL, icmp) != 0
    {
        return None;
    }

    let total_len = 40 + payload_len;
    let mut reply = vec![0; total_len];
    reply[0] = 0x60;
    reply[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    reply[6] = ICMPV6_PROTOCOL;
    reply[7] = 64;
    reply[8..24].copy_from_slice(&destination);
    reply[24..40].copy_from_slice(&source);

    reply[40..].copy_from_slice(icmp);
    reply[40] = 129;
    reply[42] = 0;
    reply[43] = 0;
    let checksum = ipv6_transport_checksum(destination, source, ICMPV6_PROTOCOL, &reply[40..]);
    reply[42..44].copy_from_slice(&checksum.to_be_bytes());

    Some(Bytes::from(reply))
}

fn ipv4_icmp_port_unreachable_reply(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 28 {
        return None;
    }

    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len + 8 || packet[9] != UDP_PROTOCOL {
        return None;
    }

    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let original_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if original_len < header_len + 8 || packet.len() < original_len {
        return None;
    }

    let quote_len = (header_len + 8).min(original_len);
    let icmp_len = 8 + quote_len;
    let total_len = 20 + icmp_len;
    let mut reply = vec![0; total_len];
    reply[0] = 0x45;
    reply[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    reply[8] = 64;
    reply[9] = ICMPV4_PROTOCOL;
    reply[12..16].copy_from_slice(&packet[16..20]);
    reply[16..20].copy_from_slice(&packet[12..16]);

    {
        let icmp = &mut reply[20..];
        icmp[0] = 3;
        icmp[1] = 3;
        icmp[8..].copy_from_slice(&packet[..quote_len]);
        let checksum = internet_checksum(icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());
    }

    let ip_checksum = internet_checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    Some(Bytes::from(reply))
}

fn ipv6_icmp_port_unreachable_reply(packet: &[u8]) -> Option<Bytes> {
    if packet.len() < 48 || packet[6] != UDP_PROTOCOL {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if payload_len < 8 || packet.len() < 40 + payload_len {
        return None;
    }

    let source = <[u8; 16]>::try_from(&packet[8..24]).ok()?;
    let destination = <[u8; 16]>::try_from(&packet[24..40]).ok()?;
    let original_len = 40 + payload_len;
    let quote_len = original_len.min(1232);
    let icmp_len = 8 + quote_len;
    let total_len = 40 + icmp_len;
    let mut reply = vec![0; total_len];
    reply[0] = 0x60;
    reply[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    reply[6] = ICMPV6_PROTOCOL;
    reply[7] = 64;
    reply[8..24].copy_from_slice(&destination);
    reply[24..40].copy_from_slice(&source);

    {
        let icmp = &mut reply[40..];
        icmp[0] = 1;
        icmp[1] = 4;
        icmp[8..].copy_from_slice(&packet[..quote_len]);
    }

    let checksum = ipv6_transport_checksum(destination, source, ICMPV6_PROTOCOL, &reply[40..]);
    reply[42..44].copy_from_slice(&checksum.to_be_bytes());

    Some(Bytes::from(reply))
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&[0, UDP_PROTOCOL]);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    internet_checksum(&pseudo)
}

fn nonzero_udp_checksum(checksum: u16) -> u16 {
    if checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

fn udp_flow_global_id(key: UdpFlowKey) -> [u8; 8] {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    hash_endpoint(&mut hash, key.client);
    hash_endpoint(&mut hash, key.target);
    hash.to_be_bytes()
}

fn hash_endpoint(hash: &mut u64, endpoint: EndpointKey) {
    match endpoint.addr {
        IpAddr::V4(ip) => {
            for byte in ip.octets() {
                hash_byte(hash, byte);
            }
        }
        IpAddr::V6(ip) => {
            for byte in ip.octets() {
                hash_byte(hash, byte);
            }
        }
    }
    for byte in endpoint.port.to_be_bytes() {
        hash_byte(hash, byte);
    }
}

fn hash_byte(hash: &mut u64, byte: u8) {
    *hash ^= u64::from(byte);
    *hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
}

fn ipv6_transport_checksum(
    source: [u8; 16],
    destination: [u8; 16],
    next_header: u8,
    payload: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + payload.len());
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(payload);
    internet_checksum(&pseudo)
}

#[derive(Debug)]
pub(crate) struct PacketDevice {
    mtu: usize,
    inbound: VecDeque<Bytes>,
    outbound: VecDeque<Bytes>,
}

impl PacketDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            mtu,
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        }
    }

    pub(crate) fn push_inbound(&mut self, packet: Bytes) {
        self.inbound.push_back(packet);
    }

    pub(crate) fn push_outbound(&mut self, packet: Bytes) {
        self.outbound.push_back(packet);
    }

    pub(crate) fn pop_outbound(&mut self) -> Option<Bytes> {
        self.outbound.pop_front()
    }
}

impl Device for PacketDevice {
    type RxToken<'a>
        = PacketRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = PacketTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            PacketRxToken { packet },
            PacketTxToken {
                mtu: self.mtu,
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(PacketTxToken {
            mtu: self.mtu,
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = None;
        capabilities.checksum = ChecksumCapabilities::default();
        capabilities
    }
}

#[derive(Debug)]
pub(crate) struct PacketRxToken {
    packet: Bytes,
}

impl RxToken for PacketRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

#[derive(Debug)]
pub(crate) struct PacketTxToken<'a> {
    mtu: usize,
    outbound: &'a mut VecDeque<Bytes>,
}

impl TxToken for PacketTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len.min(self.mtu)];
        let result = f(&mut packet);
        self.outbound.push_back(Bytes::from(packet));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;

    const NORMAL_TCP_REMOTE_PENDING_LIMIT: usize = 4 * 1024 * 1024;
    const PRESSURE_TCP_REMOTE_PENDING_LIMIT: usize = 2 * 1024 * 1024;

    #[derive(Debug, Default)]
    struct CountingWrite {
        written: Vec<u8>,
        writes: usize,
        flushes: usize,
    }

    impl AsyncWrite for CountingWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            self.written.extend_from_slice(input);
            Poll::Ready(Ok(input.len()))
        }

        fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn mobile_tcp_flow_budget_state() -> TcpRemoteBufferState {
        TcpRemoteBufferState::new(MOBILE_TCP_REMOTE_BUFFER_POLICY)
    }

    fn test_tcp443_target() -> Target {
        Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        )
    }

    #[test]
    fn tcp_slow_flow_event_records_only_slow_tcp443_targets() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let tcp443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );
        let tcp8443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            8443,
            RoutingNetwork::Tcp,
        );

        record_tcp_slow_flow_event(
            &tun,
            &tcp443,
            TunTcpSlowFlowKind::Open,
            TCP_SLOW_FLOW_THRESHOLD_MS,
            0,
        );
        record_tcp_slow_flow_event(
            &tun,
            &tcp8443,
            TunTcpSlowFlowKind::Open,
            TCP_SLOW_FLOW_THRESHOLD_MS + 1,
            0,
        );
        record_tcp_slow_flow_event(
            &tun,
            &tcp443,
            TunTcpSlowFlowKind::FirstByte,
            450,
            TCP_SLOW_FLOW_THRESHOLD_MS + 1,
        );

        assert_eq!(
            tun.poll_tcp_slow_flow_event(),
            Some(TunTcpSlowFlowEvent {
                kind: TunTcpSlowFlowKind::FirstByte,
                target: "speedtest.example:443".to_owned(),
                open_duration_ms: 450,
                first_byte_duration_ms: TCP_SLOW_FLOW_THRESHOLD_MS + 1,
            })
        );
        assert_eq!(tun.poll_tcp_slow_flow_event(), None);
    }

    #[test]
    fn tcp_open_error_event_records_target_outbound_and_error() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = Target::new(
            RoutingTargetAddr::Domain("youtube.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );

        record_tcp_open_error_event(
            &tun,
            &target,
            Some("proxy"),
            "tcp connect failed: Network is unreachable",
        );

        assert_eq!(
            tun.poll_tcp_open_error_event(),
            Some(xray_tun::TunTcpOpenErrorEvent {
                target: "youtube.example:443".to_owned(),
                outbound_tag: Some("proxy".to_owned()),
                error: "tcp connect failed: Network is unreachable".to_owned(),
            })
        );
        assert_eq!(tun.poll_tcp_open_error_event(), None);
    }

    #[test]
    fn tcp_slow_flow_event_uses_500ms_threshold_for_tcp443_targets() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let tcp443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );

        record_tcp_slow_flow_event(&tun, &tcp443, TunTcpSlowFlowKind::Open, 500, 0);
        assert_eq!(tun.poll_tcp_slow_flow_event(), None);

        record_tcp_slow_flow_event(&tun, &tcp443, TunTcpSlowFlowKind::Open, 501, 0);
        assert_eq!(
            tun.poll_tcp_slow_flow_event(),
            Some(TunTcpSlowFlowEvent {
                kind: TunTcpSlowFlowKind::Open,
                target: "speedtest.example:443".to_owned(),
                open_duration_ms: 501,
                first_byte_duration_ms: 0,
            })
        );
        assert_eq!(tun.poll_tcp_slow_flow_event(), None);
    }

    #[test]
    fn tcp_remote_write_slow_event_uses_500ms_threshold_for_tcp443_targets() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let tcp443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );
        let tcp8443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            8443,
            RoutingNetwork::Tcp,
        );

        record_tcp_remote_write_slow_event(&tun, &tcp443, Some("proxy"), 500, 2_048, 2);
        record_tcp_remote_write_slow_event(&tun, &tcp8443, Some("proxy"), 501, 2_048, 2);
        assert_eq!(tun.poll_tcp_remote_write_slow_event(), None);

        record_tcp_remote_write_slow_event(&tun, &tcp443, Some("proxy"), 501, 2 * 1024 * 1024, 257);
        assert_eq!(
            tun.poll_tcp_remote_write_slow_event(),
            Some(TunTcpRemoteWriteSlowEvent {
                target: "speedtest.example:443".to_owned(),
                outbound_tag: Some("proxy".to_owned()),
                duration_ms: 501,
                bytes: 2 * 1024 * 1024,
                messages: 257,
            })
        );
        assert_eq!(tun.poll_tcp_remote_write_slow_event(), None);
    }

    #[test]
    fn tcp_flow_summary_event_records_only_large_tcp443_flows() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let tcp443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );
        let tcp8443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            8443,
            RoutingNetwork::Tcp,
        );

        record_tcp_flow_summary_event(
            &tun,
            &tcp8443,
            Some("proxy"),
            true,
            3_000,
            300,
            500,
            TCP_FLOW_SUMMARY_MIN_BYTES,
            700,
            750,
            800,
            900,
            0,
        );
        record_tcp_flow_summary_event(
            &tun,
            &tcp443,
            Some("proxy"),
            true,
            3_000,
            300,
            500,
            TCP_FLOW_SUMMARY_MIN_BYTES - 1,
            700,
            750,
            800,
            900,
            0,
        );
        record_tcp_flow_summary_event(
            &tun,
            &tcp443,
            Some("proxy"),
            true,
            3_288,
            320,
            650,
            TCP_FLOW_SUMMARY_MIN_BYTES,
            850,
            1_050,
            1_400,
            1_900,
            0,
        );

        assert_eq!(
            tun.poll_tcp_flow_summary_event(),
            Some(TunTcpFlowSummaryEvent {
                target: "speedtest.example:443".to_owned(),
                outbound_tag: Some("proxy".to_owned()),
                closed: true,
                duration_ms: 3_288,
                open_duration_ms: 320,
                first_byte_duration_ms: 650,
                remote_read_bytes: TCP_FLOW_SUMMARY_MIN_BYTES,
                ms_to_64kib: 850,
                ms_to_128kib: 1_050,
                ms_to_256kib: 1_400,
                ms_to_512kib: 1_900,
                ms_to_1mib: 0,
            })
        );
        assert_eq!(tun.poll_tcp_flow_summary_event(), None);
    }

    #[test]
    fn tcp_flow_summary_timing_records_early_thresholds_and_outbound_tag() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Tcp,
        );
        let start = StdInstant::now() - Duration::from_millis(100);
        let mut timing = TcpFirstByteTimingEnabled::new(start, true, 30, Some("proxy".to_owned()));

        timing.record_first_byte(&tun, &target);
        timing.record_remote_read(&tun, &target, TCP_FLOW_SUMMARY_64KIB_BYTES as usize);
        timing.record_remote_read(&tun, &target, TCP_FLOW_SUMMARY_64KIB_BYTES as usize);
        timing.record_remote_read(
            &tun,
            &target,
            (TCP_FLOW_SUMMARY_MIN_BYTES - TCP_FLOW_SUMMARY_128KIB_BYTES) as usize,
        );

        let Some(summary) = tun.poll_tcp_flow_summary_event() else {
            panic!("expected TCP flow summary after crossing 512KiB");
        };
        assert_eq!(summary.target, "speedtest.example:443");
        assert_eq!(summary.outbound_tag.as_deref(), Some("proxy"));
        assert!(!summary.closed);
        assert_eq!(summary.remote_read_bytes, TCP_FLOW_SUMMARY_MIN_BYTES);
        assert!(summary.ms_to_64kib >= 100);
        assert!(summary.ms_to_128kib >= 100);
        assert!(summary.ms_to_256kib >= 100);
        assert!(summary.ms_to_512kib >= 100);
        assert_eq!(summary.ms_to_1mib, 0);
        assert_eq!(tun.poll_tcp_flow_summary_event(), None);
    }

    #[test]
    fn udp_slow_flow_event_records_only_slow_udp443_targets() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let udp443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Udp,
        );
        let udp8443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            8443,
            RoutingNetwork::Udp,
        );

        record_udp_slow_flow_event(&tun, &udp443, UDP_SLOW_FLOW_THRESHOLD_MS, 1_200, 900);
        record_udp_slow_flow_event(&tun, &udp8443, UDP_SLOW_FLOW_THRESHOLD_MS + 1, 1_200, 900);
        record_udp_slow_flow_event(&tun, &udp443, UDP_SLOW_FLOW_THRESHOLD_MS + 1, 2_400, 1_400);

        assert_eq!(
            tun.poll_udp_slow_flow_event(),
            Some(TunUdpSlowFlowEvent {
                target: "speedtest.example:443".to_owned(),
                first_response_duration_ms: UDP_SLOW_FLOW_THRESHOLD_MS + 1,
                written_bytes: 2_400,
                read_bytes: 1_400,
            })
        );
        assert_eq!(tun.poll_udp_slow_flow_event(), None);
    }

    #[test]
    fn udp_response_gap_event_records_only_slow_udp443_targets() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let udp443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            443,
            RoutingNetwork::Udp,
        );
        let udp8443 = Target::new(
            RoutingTargetAddr::Domain("speedtest.example".to_owned()),
            8443,
            RoutingNetwork::Udp,
        );

        record_udp_response_gap_event(&tun, &udp443, UDP_RESPONSE_GAP_THRESHOLD_MS, 1_200, 900);
        record_udp_response_gap_event(
            &tun,
            &udp8443,
            UDP_RESPONSE_GAP_THRESHOLD_MS + 1,
            1_200,
            900,
        );
        record_udp_response_gap_event(
            &tun,
            &udp443,
            UDP_RESPONSE_GAP_THRESHOLD_MS + 1,
            2_400,
            1_400,
        );

        assert_eq!(
            tun.poll_udp_response_gap_event(),
            Some(TunUdpResponseGapEvent {
                target: "speedtest.example:443".to_owned(),
                response_gap_duration_ms: UDP_RESPONSE_GAP_THRESHOLD_MS + 1,
                written_bytes: 2_400,
                read_bytes: 1_400,
            })
        );
        assert_eq!(tun.poll_udp_response_gap_event(), None);
    }

    #[tokio::test]
    async fn stack_to_remote_write_batches_queued_chunks_before_flushing() {
        let (tx, mut rx) = mpsc::channel(TCP_BRIDGE_CHANNEL_DEPTH);
        tx.try_send(Bytes::from_static(b"two")).unwrap();
        tx.try_send(Bytes::from_static(b"three")).unwrap();
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            Bytes::from_static(b"one"),
            &mut rx,
            &tun,
        )
        .await
        .unwrap();

        assert_eq!(writer.written, b"onetwothree");
        assert_eq!(writer.writes, 1);
        assert_eq!(writer.flushes, 1);
        let stats = tun.stats().await;
        assert_eq!(stats.tcp_remote_written_bytes, b"onetwothree".len() as u64);
        assert_eq!(stats.tcp_remote_write_batches, 1);
        assert_eq!(stats.tcp_remote_write_batch_messages, 3);
        assert_eq!(stats.tcp_remote_write_batch_max_messages, 3);
        assert_eq!(
            stats.tcp_remote_write_batch_max_bytes,
            b"onetwothree".len() as u64
        );
        assert_eq!(stats.tcp_remote_write_wait_events, 1);
        assert_eq!(stats.tcp_remote_flush_wait_events, 1);
    }

    #[tokio::test]
    async fn stack_to_remote_write_batch_drains_a_full_channel_before_flushing() {
        let (tx, mut rx) = mpsc::channel(TCP_BRIDGE_CHANNEL_DEPTH);
        for _ in 0..TCP_BRIDGE_CHANNEL_DEPTH {
            tx.try_send(Bytes::from_static(&[0x5a; 1024])).unwrap();
        }
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            Bytes::from_static(&[0x7b; 1024]),
            &mut rx,
            &tun,
        )
        .await
        .unwrap();

        let stats = tun.stats().await;
        assert_eq!(stats.tcp_remote_write_batches, 1);
        assert_eq!(
            stats.tcp_remote_write_batch_messages,
            TCP_BRIDGE_CHANNEL_DEPTH as u64 + 1
        );
        assert_eq!(
            stats.tcp_remote_write_batch_max_bytes,
            ((TCP_BRIDGE_CHANNEL_DEPTH + 1) * 1024) as u64
        );
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test]
    async fn stack_to_remote_write_batch_drains_larger_tcp_upload_burst_before_flushing() {
        let expected_queued_messages = 256usize;
        let (tx, mut rx) = mpsc::channel(expected_queued_messages);
        for _ in 0..expected_queued_messages {
            tx.try_send(Bytes::from_static(&[0x5a; 1024])).unwrap();
        }
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            Bytes::from_static(&[0x7b; 1024]),
            &mut rx,
            &tun,
        )
        .await
        .unwrap();

        let stats = tun.stats().await;
        assert_eq!(stats.tcp_remote_write_batches, 1);
        assert_eq!(stats.tcp_remote_write_batch_messages, 257);
        assert_eq!(stats.tcp_remote_write_batch_max_bytes, 257 * 1024);
        assert_eq!(writer.flushes, 1);
    }

    #[tokio::test]
    async fn stack_to_remote_write_batch_allows_two_mib_before_flushing() {
        let chunk = Bytes::from_static(&[0x5a; 16 * 1024]);
        let (tx, mut rx) = mpsc::channel(TCP_BRIDGE_CHANNEL_DEPTH);
        for _ in 0..TCP_BRIDGE_CHANNEL_DEPTH {
            tx.try_send(chunk.clone()).unwrap();
        }
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();

        write_stack_batch_to_remote(&mut writer, &target, Some("proxy"), chunk, &mut rx, &tun)
            .await
            .unwrap();

        let stats = tun.stats().await;
        assert_eq!(stats.tcp_remote_write_batches, 1);
        assert_eq!(stats.tcp_remote_write_batch_messages, 128);
        assert_eq!(stats.tcp_remote_write_batch_max_bytes, 2 * 1024 * 1024);
        assert_eq!(writer.flushes, 1);
    }

    #[test]
    fn packet_device_receives_queued_inbound_packet() {
        let mut device = PacketDevice::new(1500);
        device.push_inbound(Bytes::from_static(&[0x45, 0x00, 0x00, 0x14]));

        let (rx, _) = device.receive(Instant::from_millis(0)).unwrap();

        rx.consume(|packet| assert_eq!(packet, &[0x45, 0x00, 0x00, 0x14]));
    }

    #[test]
    fn packet_device_transmits_outbound_packet() {
        let mut device = PacketDevice::new(1500);

        let tx = device.transmit(Instant::from_millis(0)).unwrap();
        tx.consume(4, |packet| {
            packet.copy_from_slice(&[0x45, 0x00, 0x00, 0x14])
        });

        assert_eq!(
            device.pop_outbound(),
            Some(Bytes::from_static(&[0x45, 0x00, 0x00, 0x14]))
        );
    }

    #[test]
    fn mobile_remote_buffer_policy_uses_4mib_normal_with_memory_pressure_budgets() {
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.normal_per_flow_bytes,
            NORMAL_TCP_REMOTE_PENDING_LIMIT
        );
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_per_flow_bytes,
            PRESSURE_TCP_REMOTE_PENDING_LIMIT
        );
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_start_total_bytes,
            24 * 1024 * 1024
        );
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_release_total_bytes,
            16 * 1024 * 1024
        );
        assert_eq!(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes,
            40 * 1024 * 1024
        );
    }

    #[test]
    fn flow_budget_state_uses_hysteresis_for_memory_pressure() {
        let mut state = mobile_tcp_flow_budget_state();

        assert_eq!(state.per_flow_limit(), NORMAL_TCP_REMOTE_PENDING_LIMIT);

        state.record_pending_remote_enqueue(0, 24 * 1024 * 1024);
        assert_eq!(state.per_flow_limit(), PRESSURE_TCP_REMOTE_PENDING_LIMIT);

        state.record_pending_remote_dequeue(24 * 1024 * 1024, 8 * 1024 * 1024 - 1);
        assert_eq!(state.per_flow_limit(), PRESSURE_TCP_REMOTE_PENDING_LIMIT);

        state.record_pending_remote_dequeue(16 * 1024 * 1024 + 1, 1);
        assert_eq!(state.per_flow_limit(), NORMAL_TCP_REMOTE_PENDING_LIMIT);
    }

    #[test]
    fn flow_budget_state_rejects_data_over_hard_total_budget() {
        let mut state = mobile_tcp_flow_budget_state();
        state.record_pending_remote_enqueue(0, MOBILE_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes);

        assert!(!state.can_enqueue_remote_data(0, 1));
    }

    #[test]
    fn flow_budget_state_applies_pressure_limit_after_soft_budget() {
        let mut state = mobile_tcp_flow_budget_state();
        state.record_pending_remote_enqueue(
            0,
            MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_start_total_bytes,
        );

        assert!(!state.can_enqueue_remote_data(PRESSURE_TCP_REMOTE_PENDING_LIMIT, 1));
        assert!(state.can_enqueue_remote_data(PRESSURE_TCP_REMOTE_PENDING_LIMIT - 1, 1));
    }

    #[test]
    fn flow_budget_state_allows_full_per_flow_budget_below_soft_budget() {
        let state = mobile_tcp_flow_budget_state();

        assert!(state.can_enqueue_remote_data(1024 * 1024, 1024 * 1024));
        assert!(!state.can_enqueue_remote_data(NORMAL_TCP_REMOTE_PENDING_LIMIT, 1));
    }

    #[test]
    fn flow_budget_state_tracks_total_pending_bytes_without_flow_scans() {
        let mut state = mobile_tcp_flow_budget_state();

        state.record_pending_remote_enqueue(0, 4096);
        state.record_pending_remote_enqueue(4096, 2048);
        state.record_pending_remote_dequeue(6144, 1024);

        assert_eq!(state.pending_total_bytes(), 5120);
        assert_eq!(state.pending_flow_count(), 1);
    }

    #[test]
    fn flow_budget_state_removes_pending_bytes_when_flow_is_cleaned_up() {
        let mut state = mobile_tcp_flow_budget_state();

        state.record_pending_remote_enqueue(0, 4096);
        state.record_pending_remote_remove_flow(4096);

        assert_eq!(state.pending_total_bytes(), 0);
        assert_eq!(state.pending_flow_count(), 0);
        assert_eq!(state.per_flow_limit(), NORMAL_TCP_REMOTE_PENDING_LIMIT);
    }

    fn test_flow_budget(max_active_udp_flows: usize) -> FlowBudgetState {
        FlowBudgetState::new(FlowBudgetPolicy {
            tcp_remote: MOBILE_TCP_REMOTE_BUFFER_POLICY,
            udp: UdpFlowBudgetPolicy {
                max_active_flows: max_active_udp_flows,
            },
        })
    }

    fn test_udp_key(octet: u8) -> UdpFlowKey {
        UdpFlowKey {
            client: EndpointKey {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
                port: 40_000 + u16::from(octet),
            },
            target: EndpointKey {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, octet)),
                port: 443,
            },
        }
    }

    fn insert_udp_flow(
        flows: &mut HashMap<UdpFlowKey, UdpFlow>,
        key: UdpFlowKey,
        last_used_sequence: u64,
    ) {
        let (to_remote, _from_stack) = mpsc::channel(1);
        flows.insert(
            key,
            UdpFlow {
                to_remote,
                last_used_sequence,
            },
        );
    }

    #[test]
    fn mobile_flow_budget_keeps_udp_capacity_high_but_bounded() {
        assert_eq!(MOBILE_FLOW_BUDGET_POLICY.udp.max_active_flows, 512);
        assert_eq!(DESKTOP_FLOW_BUDGET_POLICY.udp.max_active_flows, 1024);
    }

    #[test]
    fn low_memory_profile_reduces_tun_flow_budgets() {
        let policy = flow_budget_policy_for_runtime_options(TunRuntimeOptions::with_profile(
            TunRuntimeProfile::LowMemory,
        ));

        assert_eq!(policy.udp.max_active_flows, 128);
        assert_eq!(policy.tcp_remote.normal_per_flow_bytes, 1024 * 1024);
        assert_eq!(policy.tcp_remote.hard_total_bytes, 20 * 1024 * 1024);
    }

    #[test]
    fn mobile_plus_profile_uses_larger_tcp_and_udp_flow_budgets() {
        let policy = flow_budget_policy_for_runtime_options(TunRuntimeOptions::with_profile(
            TunRuntimeProfile::MobilePlus,
        ));

        assert_eq!(
            policy.tcp_remote.normal_per_flow_bytes,
            DESKTOP_TCP_REMOTE_BUFFER_POLICY.normal_per_flow_bytes
        );
        assert_eq!(
            policy.tcp_remote.hard_total_bytes,
            DESKTOP_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes
        );
        assert_eq!(policy.udp.max_active_flows, 512);
    }

    #[test]
    fn flow_budget_accepts_existing_udp_flow_without_eviction() {
        let mut budget = test_flow_budget(1);
        let mut flows = HashMap::new();
        let key = test_udp_key(1);
        let UdpFlowAdmission::Admit { sequence } = budget.admit_udp_flow(&mut flows, key) else {
            panic!("first packet should admit a new UDP flow");
        };
        insert_udp_flow(&mut flows, key, sequence);

        let admission = budget.admit_udp_flow(&mut flows, key);

        assert!(matches!(admission, UdpFlowAdmission::Existing));
        assert_eq!(flows.len(), 1);
        assert_eq!(budget.udp_budget_drops(), 0);
        assert_eq!(budget.udp_evicted_flows(), 0);
    }

    #[test]
    fn flow_budget_evicts_oldest_udp_flow_when_limit_is_full() {
        let mut budget = test_flow_budget(2);
        let mut flows = HashMap::new();
        let oldest = test_udp_key(1);
        let newest = test_udp_key(2);
        insert_udp_flow(&mut flows, oldest, 1);
        insert_udp_flow(&mut flows, newest, 2);

        let admitted = budget.admit_udp_flow(&mut flows, test_udp_key(3));

        assert!(matches!(admitted, UdpFlowAdmission::Admit { .. }));
        assert!(!flows.contains_key(&oldest));
        assert!(flows.contains_key(&newest));
        assert_eq!(budget.udp_evicted_flows(), 1);
        assert_eq!(budget.udp_budget_drops(), 0);
    }

    #[test]
    fn flow_budget_drops_new_udp_flow_when_limit_is_zero() {
        let mut budget = test_flow_budget(0);
        let mut flows = HashMap::new();

        let admitted = budget.admit_udp_flow(&mut flows, test_udp_key(1));

        assert!(matches!(admitted, UdpFlowAdmission::Drop));
        assert!(flows.is_empty());
        assert_eq!(budget.udp_budget_drops(), 1);
        assert_eq!(budget.udp_evicted_flows(), 0);
    }

    #[test]
    fn remote_tcp_data_is_deferred_when_pending_flow_buffer_is_full() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut flow_budget_state = test_flow_budget(256);
        flow_budget_state.record_pending_remote_enqueue(0, NORMAL_TCP_REMOTE_PENDING_LIMIT);
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: NORMAL_TCP_REMOTE_PENDING_LIMIT,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                data: Bytes::from_static(&[1, 2, 3, 4]),
            })
            .unwrap();

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert!(flow.pending_remote.is_empty());
        assert_eq!(flow.pending_remote_bytes, NORMAL_TCP_REMOTE_PENDING_LIMIT);
        assert_eq!(delayed_stack_events.len(), 1);
    }

    #[test]
    fn deferred_remote_tcp_data_is_applied_after_pending_flow_buffer_has_room() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut flow_budget_state = test_flow_budget(256);
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (_stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::from([StackEvent::RemoteData {
            handle,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        }]);

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert_eq!(flow.pending_remote.len(), 1);
        assert_eq!(flow.pending_remote_bytes, 4);
        assert!(delayed_stack_events.is_empty());
    }

    #[test]
    fn remote_tcp_data_can_exceed_1mib_below_soft_budget() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut flow_budget_state = test_flow_budget(256);
        flow_budget_state.record_pending_remote_enqueue(0, 1024 * 1024);
        let mut pending_remote = VecDeque::new();
        pending_remote.push_back(Bytes::from(vec![0; 1024 * 1024]));
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote,
                pending_remote_bytes: 1024 * 1024,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                data: Bytes::from_static(&[1, 2, 3, 4]),
            })
            .unwrap();

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert_eq!(flow.pending_remote.len(), 2);
        assert_eq!(flow.pending_remote_bytes, 1024 * 1024 + 4);
        assert!(delayed_stack_events.is_empty());
    }

    #[test]
    fn remote_tcp_data_is_deferred_when_hard_total_budget_is_full() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut flow_budget_state = test_flow_budget(256);
        flow_budget_state
            .record_pending_remote_enqueue(0, MOBILE_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes);
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                data: Bytes::from_static(&[1, 2, 3, 4]),
            })
            .unwrap();

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert!(flow.pending_remote.is_empty());
        assert_eq!(flow.pending_remote_bytes, 0);
        assert_eq!(delayed_stack_events.len(), 1);
    }

    #[test]
    fn remote_tcp_data_is_deferred_for_large_flow_while_pressure_is_active() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut flow_budget_state = test_flow_budget(256);
        flow_budget_state.record_pending_remote_enqueue(
            0,
            MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_start_total_bytes,
        );
        let mut pending_remote = VecDeque::new();
        pending_remote.push_back(Bytes::from(vec![0; PRESSURE_TCP_REMOTE_PENDING_LIMIT]));
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote,
                pending_remote_bytes: PRESSURE_TCP_REMOTE_PENDING_LIMIT,
                remote_closed: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                data: Bytes::from_static(&[1, 2, 3, 4]),
            })
            .unwrap();

        drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            None,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert_eq!(flow.pending_remote.len(), 1);
        assert_eq!(flow.pending_remote_bytes, PRESSURE_TCP_REMOTE_PENDING_LIMIT);
        assert_eq!(delayed_stack_events.len(), 1);
    }

    #[test]
    fn remote_tcp_drain_polls_queued_ack_after_send_buffer_stalls() {
        let client_ip = Ipv4Addr::new(10, 10, 0, 2);
        let server_ip = Ipv4Addr::new(203, 0, 113, 7);
        let client_port = 49_152;
        let server_port = 443;
        let client_seq = 1_000u32;
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(server_ip), server_port);

        let mut device = PacketDevice::new(1500);
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = DEFAULT_RANDOM_SEED;
        let mut iface = Interface::new(iface_config, &mut device, Instant::now());
        iface.set_any_ip(true);
        let mut sockets = SocketSet::new(Vec::new());
        let mut listeners = HashMap::new();
        ensure_tcp_listener(&mut sockets, &mut listeners, endpoint);
        let handle = *listeners.get(&endpoint).unwrap();

        device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
            client_ip,
            client_port,
            server_ip,
            server_port,
            client_seq,
            0,
            TCP_SYN,
            &[],
        )));
        iface.poll(Instant::now(), &mut device, &mut sockets);
        let syn_ack = device.pop_outbound().unwrap();
        let server_seq = ipv4_tcp_sequence(&syn_ack).unwrap();

        device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
            client_ip,
            client_port,
            server_ip,
            server_port,
            client_seq + 1,
            server_seq + 1,
            TCP_ACK,
            &[],
        )));
        iface.poll(Instant::now(), &mut device, &mut sockets);
        while device.pop_outbound().is_some() {}

        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut pending_remote = VecDeque::new();
        pending_remote.push_back(Bytes::from(vec![0x5a; TCP_BUFFER_SIZE]));
        let mut flow_budget_state = test_flow_budget(256);
        flow_budget_state.record_pending_remote_enqueue(0, TCP_BUFFER_SIZE);
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                to_remote,
                pending_remote,
                pending_remote_bytes: TCP_BUFFER_SIZE,
                remote_closed: false,
            },
        );

        assert_eq!(
            write_remote_data_to_sockets(&mut sockets, &mut tcp_flows, &mut flow_budget_state),
            TCP_BUFFER_SIZE
        );
        iface.poll(Instant::now(), &mut device, &mut sockets);

        let mut sent_payload_bytes = 0usize;
        while let Some(packet) = device.pop_outbound() {
            sent_payload_bytes += ipv4_tcp_payload_len(&packet).unwrap_or(0);
        }
        assert!(sent_payload_bytes >= 1024);

        {
            let flow = tcp_flows.get_mut(&handle).unwrap();
            flow.pending_remote.push_back(Bytes::from(vec![0x7b; 1024]));
            flow.pending_remote_bytes = 1024;
        }
        flow_budget_state.record_pending_remote_enqueue(0, 1024);
        device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
            client_ip,
            client_port,
            server_ip,
            server_port,
            client_seq + 1,
            server_seq + 1 + sent_payload_bytes as u32,
            TCP_ACK,
            &[],
        )));

        drain_tcp_remote_data_to_sockets(
            &mut iface,
            &mut device,
            &mut sockets,
            &mut tcp_flows,
            &mut flow_budget_state,
        );

        let flow = tcp_flows.get(&handle).unwrap();
        assert!(flow.pending_remote.is_empty());
        assert_eq!(flow.pending_remote_bytes, 0);
        assert_eq!(flow_budget_state.pending_total_bytes(), 0);
    }

    #[test]
    fn fake_ip_mapper_allocates_stable_ipv4_and_restores_domain_target() {
        let mut mapper = FakeIpMapper::new(FakeIpRuntimeConfig {
            ipv4_network: Ipv4Addr::new(198, 18, 0, 0),
            ipv4_prefix: 15,
            ttl: 60,
        })
        .unwrap();

        let first = mapper.fake_ipv4_for_domain("Example.COM").unwrap();
        let second = mapper.fake_ipv4_for_domain("example.com").unwrap();
        let target = mapper
            .target_for_endpoint(
                IpEndpoint::new(IpAddress::Ipv4(first), 443),
                RoutingNetwork::Tcp,
            )
            .unwrap();

        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(second, first);
        assert_eq!(
            target,
            Target::new(
                RoutingTargetAddr::Domain("example.com".to_owned()),
                443,
                RoutingNetwork::Tcp,
            )
        );
    }

    #[test]
    fn fake_dns_response_answers_a_query_and_records_mapping() {
        let mut mapper = FakeIpMapper::new(FakeIpRuntimeConfig {
            ipv4_network: Ipv4Addr::new(198, 18, 0, 0),
            ipv4_prefix: 15,
            ttl: 120,
        })
        .unwrap();
        let query = build_dns_a_query(0x1203, "www.example.com");

        let response = mapper.fake_dns_response(&query).unwrap();
        let fake_ip = mapper.domain_for_ipv4(Ipv4Addr::new(198, 18, 0, 1));

        assert_eq!(dns_response_id(&response), Some(0x1203));
        assert_eq!(
            dns_response_answer_ipv4(&response),
            Some(Ipv4Addr::new(198, 18, 0, 1))
        );
        assert_eq!(fake_ip, Some("www.example.com"));
    }

    #[test]
    fn fake_dns_udp_packet_builds_tun_reply_packet() {
        let mut mapper = FakeIpMapper::new(FakeIpRuntimeConfig {
            ipv4_network: Ipv4Addr::new(198, 18, 0, 0),
            ipv4_prefix: 15,
            ttl: 60,
        })
        .unwrap();
        let request = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            53_000,
            Ipv4Addr::new(1, 1, 1, 1),
            DNS_PORT,
            &build_dns_a_query(0x1203, "www.example.com"),
        )
        .unwrap();
        let parsed = parse_udp_packet(&request).unwrap();
        let response = mapper.fake_dns_response(&parsed.payload).unwrap();
        let reply = build_udp_packet(parsed.target, parsed.client, &response).unwrap();

        assert_eq!(
            ipv4_udp_payload_for_destination(&reply, 53_000)
                .as_deref()
                .and_then(dns_response_answer_ipv4),
            Some(Ipv4Addr::new(198, 18, 0, 1))
        );
    }

    fn build_dns_a_query(id: u16, domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&0x0100_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        packet.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    fn dns_response_id(packet: &[u8]) -> Option<u16> {
        Some(u16::from_be_bytes([*packet.first()?, *packet.get(1)?]))
    }

    fn dns_response_answer_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
        if packet.len() < 16 {
            return None;
        }
        let answer_count = u16::from_be_bytes([packet[6], packet[7]]);
        if answer_count == 0 {
            return None;
        }
        let mut offset = 12usize;
        loop {
            let len = *packet.get(offset)? as usize;
            offset += 1;
            if len == 0 {
                break;
            }
            offset = offset.checked_add(len)?;
            if offset > packet.len() {
                return None;
            }
        }
        offset = offset.checked_add(4)?;
        if packet.get(offset)? & 0xc0 != 0xc0 {
            return None;
        }
        offset = offset.checked_add(2 + 2 + 2 + 4)?;
        let rdlen = u16::from_be_bytes([*packet.get(offset)?, *packet.get(offset + 1)?]);
        offset += 2;
        if rdlen != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            *packet.get(offset)?,
            *packet.get(offset + 1)?,
            *packet.get(offset + 2)?,
            *packet.get(offset + 3)?,
        ))
    }

    const TCP_SYN: u8 = 0x02;
    const TCP_ACK: u8 = 0x10;

    #[allow(clippy::too_many_arguments)]
    fn build_ipv4_tcp_packet(
        source: Ipv4Addr,
        source_port: u16,
        destination: Ipv4Addr,
        destination_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let total_len = 20 + tcp_len;
        let mut packet = vec![0; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = TCP_PROTOCOL;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());

        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        tcp[20..].copy_from_slice(payload);
        let tcp_checksum = ipv4_tcp_checksum(source, destination, tcp);
        tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

        let ip_checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

        packet
    }

    fn ipv4_tcp_checksum(source: Ipv4Addr, destination: Ipv4Addr, tcp: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&source.octets());
        pseudo.extend_from_slice(&destination.octets());
        pseudo.extend_from_slice(&[0, TCP_PROTOCOL]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        internet_checksum(&pseudo)
    }

    fn ipv4_tcp_sequence(packet: &[u8]) -> Option<u32> {
        let tcp = ipv4_tcp_header_and_payload(packet)?;
        Some(u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]))
    }

    fn ipv4_tcp_payload_len(packet: &[u8]) -> Option<usize> {
        let tcp = ipv4_tcp_header_and_payload(packet)?;
        let header_len = usize::from(tcp[12] >> 4) * 4;
        if header_len < 20 || tcp.len() < header_len {
            return None;
        }
        Some(tcp.len() - header_len)
    }

    fn ipv4_tcp_header_and_payload(packet: &[u8]) -> Option<&[u8]> {
        if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != TCP_PROTOCOL {
            return None;
        }
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if header_len < 20 || total_len < header_len + 20 || packet.len() < total_len {
            return None;
        }
        Some(&packet[header_len..total_len])
    }

    #[test]
    fn tcp_syn_destination_extracts_ipv4_destination() {
        let packet = [
            0x45,
            0x00,
            0x00,
            0x28,
            0x00,
            0x00,
            0x00,
            0x00,
            64,
            TCP_PROTOCOL,
            0x00,
            0x00,
            10,
            10,
            0,
            2,
            127,
            0,
            0,
            1,
            0xc0,
            0x00,
            0x1f,
            0x90,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x50,
            0x02,
            0x04,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        ];

        let endpoint = tcp_syn_destination(&packet).unwrap();

        assert_eq!(endpoint.addr, IpAddress::Ipv4(Ipv4Addr::LOCALHOST));
        assert_eq!(endpoint.port, 8080);
    }
}
