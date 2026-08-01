use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinError, JoinSet};
use tokio::time::{sleep, Duration, Instant as TokioInstant};
use xray_config::{
    CoreConfig, DnsQueryStrategy as ConfigDnsQueryStrategy, DnsServerConfig, InboundSniffingConfig,
};
use xray_routing::{Network as RoutingNetwork, Target, TargetAddr as RoutingTargetAddr};
use xray_transport::{
    dns_response_matches_query, protect_udp_socket, BoxedTransportStream, DnsLookup,
    DnsQueryStrategy as TransportDnsQueryStrategy, DnsResolver, TransportDialer, TransportError,
};
use xray_tun::{
    TunEndpoint, TunError, TunTcpBufferState, TunTcpFlowSummaryEvent, TunTcpOpenErrorEvent,
    TunTcpRemoteWriteSlowEvent, TunTcpSlowFlowEvent, TunTcpSlowFlowKind, TunUdpResponseGapEvent,
    TunUdpSlowFlowEvent,
};

use crate::dns_outbound_runtime::{FakeIpTargetProvenance, RestoredClientTarget};
use crate::fake_dns::FakeIpMapper;
use crate::outbound::{
    open_tcp_stream_with_resolver_and_dialer,
    open_vless_udp_stream_with_resolver_dialer_and_options, DnsOutbound, TcpOutbound, UdpOutbound,
    UdpSessionOutbound, VlessTcpOutbound, VlessUdpFraming, VlessUdpOpenOptions,
};
use crate::policy::{effective_policy_for_level, EffectivePolicy};
use crate::{OutboundRouter, RuntimeLogger, TunRuntimeOptions, TunRuntimeProfile};
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, encode_xudp_new_packet, read_udp_packet,
    read_xudp_packet,
};

const DEFAULT_RANDOM_SEED: u64 = 0x7872_6179_7275_7374;
const ICMPV4_PROTOCOL: u8 = 1;
const ICMPV6_PROTOCOL: u8 = 58;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
pub(crate) const DNS_PORT: u16 = 53;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;
const DNS_RCODE_NOERROR: u16 = 0;
const DNS_RCODE_SERVFAIL: u16 = 2;
pub(crate) const TUN_DNS_ANCHOR: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);
pub(crate) const TUN_CLIENT_IPV4: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
const TCP_BUFFER_SIZE: usize = 32 * 1024;
const TUN_TCP_SNIFF_BUFFER_SIZE: usize = 8 * 1024;
const TUN_TCP_SNIFF_TIMEOUT: Duration = Duration::from_millis(250);
const STACK_EVENT_CHANNEL_DEPTH: usize = 64;
const TCP_BRIDGE_CHANNEL_DEPTH: usize = 256;
const MOBILE_TCP_BRIDGE_CHANNEL_DEPTH: usize = 128;
const LOW_MEMORY_TCP_BRIDGE_CHANNEL_DEPTH: usize = 64;
// Burst-heavy UDP (DNS fan-out, QUIC fallback retries) overflows a 64-deep
// channel and surfaces as udp_channel_dropped_packets.
const UDP_BRIDGE_CHANNEL_DEPTH: usize = 256;
const BRIDGE_READ_BUFFER_SIZE: usize = 16 * 1024;
const TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES: usize = TCP_BRIDGE_CHANNEL_DEPTH + 1;
const MOBILE_TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES: usize = MOBILE_TCP_BRIDGE_CHANNEL_DEPTH + 1;
const LOW_MEMORY_TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES: usize =
    LOW_MEMORY_TCP_BRIDGE_CHANNEL_DEPTH + 1;
const TCP_BRIDGE_WRITE_BATCH_MAX_BYTES: usize = 2 * 1024 * 1024;
const MOBILE_TCP_BRIDGE_WRITE_BATCH_MAX_BYTES: usize = 1024 * 1024;
const LOW_MEMORY_TCP_BRIDGE_WRITE_BATCH_MAX_BYTES: usize = 256 * 1024;
const MAX_TUN_INBOUND_DRAIN_PER_TICK: usize = 256;
const MAX_BRIDGE_TASK_COMPLETIONS_PER_TICK: usize = 64;
const MAX_UDP_TASK_COMPLETIONS_PER_TICK: usize = MAX_TUN_INBOUND_DRAIN_PER_TICK + 1;
const MAX_DNS_UDP_TASKS: usize = 64;
const MAX_DNS_TCP_FLOWS: usize = 32;
const TCP_REMOTE_DRAIN_MAX_PASSES_PER_TICK: usize = 4;
const TCP_REMOTE_DRAIN_MAX_BYTES_PER_TICK: usize = 4 * 1024 * 1024;
const TUN_FLOW_STATS_INTERVAL: Duration = Duration::from_secs(1);
const TUN_BACKPRESSURE_RETRY_INTERVAL: Duration = Duration::from_millis(25);
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

#[path = "tun_dns.rs"]
mod dns_proxy;
use dns_proxy::{DnsTcpAction, DnsUdpAction, TunDnsMode};

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

const MOBILE_PLUS_TCP_REMOTE_BUFFER_POLICY: TcpRemoteBufferPolicy = TcpRemoteBufferPolicy {
    normal_per_flow_bytes: MOBILE_TCP_REMOTE_BUFFER_POLICY.normal_per_flow_bytes,
    pressure_per_flow_bytes: MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_per_flow_bytes,
    pressure_start_total_bytes: 30 * 1024 * 1024,
    pressure_release_total_bytes: 20 * 1024 * 1024,
    hard_total_bytes: MOBILE_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpFlowBudgetPolicy {
    max_active_flows: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpFlowBudgetPolicy {
    max_active_flows: usize,
    max_pending_opens: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowBudgetPolicy {
    tcp_remote: TcpRemoteBufferPolicy,
    tcp: TcpFlowBudgetPolicy,
    udp: UdpFlowBudgetPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpUploadBridgePolicy {
    channel_depth: usize,
    max_batch_messages: usize,
    max_batch_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TunRuntimePolicy {
    flows: FlowBudgetPolicy,
    tcp_upload: TcpUploadBridgePolicy,
}

const MOBILE_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: MOBILE_TCP_REMOTE_BUFFER_POLICY,
    tcp: TcpFlowBudgetPolicy {
        // Every smoltcp TCP flow owns two fixed 32 KiB buffers. Pending opens
        // also retain TLS state, so bound both dimensions independently.
        max_active_flows: 256,
        max_pending_opens: 64,
    },
    udp: UdpFlowBudgetPolicy {
        // Speedtests and DNS-heavy bursts easily exceed 256 concurrent UDP
        // flows; dropping fresh flows shows up as failed probes.
        max_active_flows: 512,
    },
};

const MOBILE_PLUS_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: MOBILE_PLUS_TCP_REMOTE_BUFFER_POLICY,
    tcp: TcpFlowBudgetPolicy {
        max_active_flows: 384,
        max_pending_opens: 96,
    },
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 512,
    },
};

const DESKTOP_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: DESKTOP_TCP_REMOTE_BUFFER_POLICY,
    tcp: TcpFlowBudgetPolicy {
        max_active_flows: 2048,
        max_pending_opens: 512,
    },
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
    tcp: TcpFlowBudgetPolicy {
        max_active_flows: 128,
        max_pending_opens: 32,
    },
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 128,
    },
};

const THROUGHPUT_FLOW_BUDGET_POLICY: FlowBudgetPolicy = FlowBudgetPolicy {
    tcp_remote: DESKTOP_TCP_REMOTE_BUFFER_POLICY,
    tcp: TcpFlowBudgetPolicy {
        max_active_flows: 4096,
        max_pending_opens: 1024,
    },
    udp: UdpFlowBudgetPolicy {
        max_active_flows: 2048,
    },
};

const DEFAULT_TCP_UPLOAD_BRIDGE_POLICY: TcpUploadBridgePolicy = TcpUploadBridgePolicy {
    channel_depth: TCP_BRIDGE_CHANNEL_DEPTH,
    max_batch_messages: TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES,
    max_batch_bytes: TCP_BRIDGE_WRITE_BATCH_MAX_BYTES,
};

const MOBILE_TCP_UPLOAD_BRIDGE_POLICY: TcpUploadBridgePolicy = TcpUploadBridgePolicy {
    channel_depth: MOBILE_TCP_BRIDGE_CHANNEL_DEPTH,
    max_batch_messages: MOBILE_TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES,
    max_batch_bytes: MOBILE_TCP_BRIDGE_WRITE_BATCH_MAX_BYTES,
};

const LOW_MEMORY_TCP_UPLOAD_BRIDGE_POLICY: TcpUploadBridgePolicy = TcpUploadBridgePolicy {
    channel_depth: LOW_MEMORY_TCP_BRIDGE_CHANNEL_DEPTH,
    max_batch_messages: LOW_MEMORY_TCP_BRIDGE_WRITE_BATCH_MAX_MESSAGES,
    max_batch_bytes: LOW_MEMORY_TCP_BRIDGE_WRITE_BATCH_MAX_BYTES,
};

const MOBILE_TUN_RUNTIME_POLICY: TunRuntimePolicy = TunRuntimePolicy {
    flows: MOBILE_FLOW_BUDGET_POLICY,
    tcp_upload: MOBILE_TCP_UPLOAD_BRIDGE_POLICY,
};

const MOBILE_PLUS_TUN_RUNTIME_POLICY: TunRuntimePolicy = TunRuntimePolicy {
    flows: MOBILE_PLUS_FLOW_BUDGET_POLICY,
    tcp_upload: MOBILE_TCP_UPLOAD_BRIDGE_POLICY,
};

const DESKTOP_TUN_RUNTIME_POLICY: TunRuntimePolicy = TunRuntimePolicy {
    flows: DESKTOP_FLOW_BUDGET_POLICY,
    tcp_upload: DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
};

const LOW_MEMORY_TUN_RUNTIME_POLICY: TunRuntimePolicy = TunRuntimePolicy {
    flows: LOW_MEMORY_FLOW_BUDGET_POLICY,
    tcp_upload: LOW_MEMORY_TCP_UPLOAD_BRIDGE_POLICY,
};

const THROUGHPUT_TUN_RUNTIME_POLICY: TunRuntimePolicy = TunRuntimePolicy {
    flows: THROUGHPUT_FLOW_BUDGET_POLICY,
    tcp_upload: DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
};

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
))]
const TUN_RUNTIME_POLICY: TunRuntimePolicy = MOBILE_TUN_RUNTIME_POLICY;

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos"
)))]
const TUN_RUNTIME_POLICY: TunRuntimePolicy = DESKTOP_TUN_RUNTIME_POLICY;

fn tun_runtime_policy_for_options(options: TunRuntimeOptions) -> TunRuntimePolicy {
    match options.profile {
        TunRuntimeProfile::Default => TUN_RUNTIME_POLICY,
        TunRuntimeProfile::Mobile => MOBILE_TUN_RUNTIME_POLICY,
        TunRuntimeProfile::MobilePlus => MOBILE_PLUS_TUN_RUNTIME_POLICY,
        TunRuntimeProfile::Desktop => DESKTOP_TUN_RUNTIME_POLICY,
        TunRuntimeProfile::LowMemory => LOW_MEMORY_TUN_RUNTIME_POLICY,
        TunRuntimeProfile::Throughput => THROUGHPUT_TUN_RUNTIME_POLICY,
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

    #[cfg(test)]
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
        self.refresh_pressure_state_for_total(self.pending_total_bytes);
    }

    fn refresh_pressure_state_for_total(&mut self, pending_total_bytes: usize) {
        if self.pressure_active {
            if pending_total_bytes <= self.policy.pressure_release_total_bytes {
                self.pressure_active = false;
            }
        } else if pending_total_bytes >= self.policy.pressure_start_total_bytes {
            self.pressure_active = true;
        }
    }
}

#[derive(Debug, Default)]
struct TcpUploadBufferState {
    pending_bytes: AtomicUsize,
    pending_max_bytes: AtomicUsize,
}

impl TcpUploadBufferState {
    fn reserve(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        let pending = self
            .pending_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        self.pending_max_bytes.fetch_max(pending, Ordering::Relaxed);
    }

    fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        let _ = self
            .pending_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |pending| {
                Some(pending.saturating_sub(bytes))
            });
    }

    fn pending_bytes(&self) -> usize {
        self.pending_bytes.load(Ordering::Relaxed)
    }

    fn pending_max_bytes(&self) -> usize {
        self.pending_max_bytes.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
struct TcpUploadReservation {
    state: Arc<TcpUploadBufferState>,
    bytes: usize,
}

impl TcpUploadReservation {
    fn new(state: Arc<TcpUploadBufferState>, bytes: usize) -> Self {
        state.reserve(bytes);
        Self { state, bytes }
    }
}

impl Drop for TcpUploadReservation {
    fn drop(&mut self) {
        self.state.release(self.bytes);
    }
}

#[derive(Debug)]
struct StackToRemoteData {
    data: Bytes,
    reservation: Option<TcpUploadReservation>,
}

impl StackToRemoteData {
    fn tracked(data: Bytes, reservation: TcpUploadReservation) -> Self {
        Self {
            data,
            reservation: Some(reservation),
        }
    }

    #[cfg(test)]
    fn untracked(data: Bytes) -> Self {
        Self {
            data,
            reservation: None,
        }
    }

    fn len(&self) -> usize {
        self.data.len()
    }
}

#[derive(Debug)]
struct FlowBudgetState {
    policy: FlowBudgetPolicy,
    tcp_remote: TcpRemoteBufferState,
    tcp_upload: Arc<TcpUploadBufferState>,
    udp_sequence: u64,
    udp_budget_drops: u64,
    udp_evicted_flows: u64,
    udp_channel_dropped_packets: u64,
}

impl FakeIpMapper {
    fn fake_dns_response(
        &mut self,
        query: &[u8],
        respond_nodata_for_unsupported: bool,
    ) -> Option<Bytes> {
        let question = parse_dns_question(query)?;
        if question.domain == "." {
            return Some(build_dns_response(
                query,
                &question,
                None,
                self.ttl(),
                DNS_RCODE_NOERROR,
            ));
        }
        if question.qtype == DNS_TYPE_A && question.qclass == DNS_CLASS_IN {
            if self.query_strategy() == ConfigDnsQueryStrategy::UseIpv6 {
                return Some(build_dns_response(
                    query,
                    &question,
                    None,
                    self.ttl(),
                    DNS_RCODE_NOERROR,
                ));
            }
            let Some(ip) = self.allocate_ipv4(&question.domain) else {
                return Some(build_dns_response(
                    query,
                    &question,
                    None,
                    self.ttl(),
                    DNS_RCODE_SERVFAIL,
                ));
            };
            return Some(build_dns_response(
                query,
                &question,
                Some(ip),
                self.ttl(),
                DNS_RCODE_NOERROR,
            ));
        }

        if matches!(question.qtype, DNS_TYPE_A | DNS_TYPE_AAAA) || respond_nodata_for_unsupported {
            return Some(build_dns_response(
                query,
                &question,
                None,
                self.ttl(),
                DNS_RCODE_NOERROR,
            ));
        }

        None
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TunWaitPlan {
    duration: Duration,
    drive_tcp_stack_on_expiry: bool,
}

fn tun_wait_plan(
    smoltcp_deadline: Option<Instant>,
    now: Instant,
    stats_wait: Duration,
    has_delayed_stack_events: bool,
    has_pending_outbound: bool,
) -> TunWaitPlan {
    let mut plan = TunWaitPlan {
        duration: stats_wait,
        drive_tcp_stack_on_expiry: false,
    };

    if has_pending_outbound {
        plan.duration = plan.duration.min(TUN_BACKPRESSURE_RETRY_INTERVAL);
        return plan;
    }

    if let Some(deadline) = smoltcp_deadline {
        let micros = deadline
            .total_micros()
            .saturating_sub(now.total_micros())
            .max(0) as u64;
        let wait = Duration::from_micros(micros);
        if wait <= plan.duration {
            plan.duration = wait;
            plan.drive_tcp_stack_on_expiry = true;
        }
    }

    if has_delayed_stack_events && TUN_BACKPRESSURE_RETRY_INTERVAL <= plan.duration {
        plan.duration = TUN_BACKPRESSURE_RETRY_INTERVAL;
        plan.drive_tcp_stack_on_expiry = true;
    }

    plan
}

impl FlowBudgetState {
    fn new(policy: FlowBudgetPolicy) -> Self {
        Self {
            policy,
            tcp_remote: TcpRemoteBufferState::new(policy.tcp_remote),
            tcp_upload: Arc::new(TcpUploadBufferState::default()),
            udp_sequence: 0,
            udp_budget_drops: 0,
            udp_evicted_flows: 0,
            udp_channel_dropped_packets: 0,
        }
    }

    fn can_enqueue_remote_data(&mut self, flow_pending_bytes: usize, data_len: usize) -> bool {
        self.refresh_tcp_pressure_state();
        if self.pending_tcp_buffer_bytes().saturating_add(data_len)
            > self.policy.tcp_remote.hard_total_bytes
        {
            return false;
        }

        flow_pending_bytes.saturating_add(data_len) <= self.per_flow_limit()
    }

    fn record_pending_remote_enqueue(&mut self, flow_pending_bytes: usize, data_len: usize) {
        self.tcp_remote
            .record_pending_remote_enqueue(flow_pending_bytes, data_len);
        self.refresh_tcp_pressure_state();
    }

    fn record_pending_remote_dequeue(&mut self, flow_pending_bytes: usize, data_len: usize) {
        self.tcp_remote
            .record_pending_remote_dequeue(flow_pending_bytes, data_len);
        self.refresh_tcp_pressure_state();
    }

    fn record_pending_remote_remove_flow(&mut self, flow_pending_bytes: usize) {
        self.tcp_remote
            .record_pending_remote_remove_flow(flow_pending_bytes);
        self.refresh_tcp_pressure_state();
    }

    #[cfg(test)]
    fn try_reserve_pending_upload(&mut self, data_len: usize) -> bool {
        if !self.can_reserve_pending_upload(data_len) {
            return false;
        }

        self.tcp_upload.reserve(data_len);
        self.refresh_tcp_pressure_state();
        true
    }

    fn reserve_pending_upload(&mut self, data_len: usize) -> Option<TcpUploadReservation> {
        if !self.can_reserve_pending_upload(data_len) {
            return None;
        }

        let reservation = TcpUploadReservation::new(self.tcp_upload.clone(), data_len);
        self.refresh_tcp_pressure_state();
        Some(reservation)
    }

    fn can_reserve_pending_upload(&mut self, data_len: usize) -> bool {
        self.refresh_tcp_pressure_state();
        self.pending_tcp_buffer_bytes().saturating_add(data_len)
            <= self.policy.tcp_remote.hard_total_bytes
    }

    #[cfg(test)]
    fn record_pending_upload_dequeue(&mut self, data_len: usize) {
        self.tcp_upload.release(data_len);
        self.refresh_tcp_pressure_state();
    }

    fn pending_total_bytes(&self) -> usize {
        self.tcp_remote.pending_total_bytes()
    }

    fn pending_upload_bytes(&self) -> usize {
        self.tcp_upload.pending_bytes()
    }

    fn pending_upload_max_bytes(&self) -> usize {
        self.tcp_upload.pending_max_bytes()
    }

    fn pending_tcp_buffer_bytes(&self) -> usize {
        self.tcp_remote
            .pending_total_bytes()
            .saturating_add(self.tcp_upload.pending_bytes())
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

    fn hard_total_bytes(&self) -> usize {
        self.policy.tcp_remote.hard_total_bytes
    }

    fn available_upload_bytes(&self) -> usize {
        self.policy
            .tcp_remote
            .hard_total_bytes
            .saturating_sub(self.pending_tcp_buffer_bytes())
    }

    fn refresh_tcp_pressure_state(&mut self) {
        self.tcp_remote
            .refresh_pressure_state_for_total(self.pending_tcp_buffer_bytes());
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

    fn record_udp_budget_drop(&mut self) {
        self.udp_budget_drops = self.udp_budget_drops.saturating_add(1);
    }

    fn next_udp_sequence(&mut self) -> u64 {
        self.udp_sequence = self.udp_sequence.saturating_add(1);
        self.udp_sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunPacketOutcome {
    Continue { tcp_stack_dirty: bool },
    QueueClosed,
}

impl TunPacketOutcome {
    fn tcp_stack_dirty(self) -> Option<bool> {
        match self {
            Self::Continue { tcp_stack_dirty } => Some(tcp_stack_dirty),
            Self::QueueClosed => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackEventApplication {
    continue_draining: bool,
    tcp_stack_dirty: bool,
}

#[expect(
    clippy::too_many_arguments,
    reason = "TUN runtime task receives shared dependencies explicitly"
)]
pub(crate) async fn serve_tun_endpoint(
    tun: Arc<TunEndpoint>,
    inbound_tag: Option<String>,
    sniffing: Option<InboundSniffingConfig>,
    inbound_policy: EffectivePolicy,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolver: Arc<dyn DnsResolver>,
    dns_bootstrap_resolver: Option<Arc<dyn DnsResolver>>,
    dns_outbound_runtime: Arc<crate::dns_outbound_runtime::DnsOutboundRuntime>,
    transport_dialer: Arc<TransportDialer>,
    tun_runtime_options: TunRuntimeOptions,
    runtime_logger: RuntimeLogger,
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
    let mut bridge_tasks = JoinSet::new();
    let mut udp_tasks = JoinSet::new();
    let runtime_policy = tun_runtime_policy_for_options(tun_runtime_options);
    let tcp_pending_open_permits =
        Arc::new(Semaphore::new(runtime_policy.flows.tcp.max_pending_opens));
    let dns_tcp_flow_permits = Arc::new(Semaphore::new(dns_tcp_flow_limit(
        runtime_policy.flows.tcp.max_active_flows,
    )));
    let dns_tcp_connection_pool = Arc::new(dns_proxy::DnsTcpConnectionPool::new(
        tun_runtime_options.profile,
    ));
    let tcp_flow_generation = Arc::new(AtomicU64::new(0));
    let udp_task_limit = runtime_policy.flows.udp.max_active_flows;
    let udp_task_permits = Arc::new(Semaphore::new(udp_task_limit));
    let dns_udp_task_permits = Arc::new(Semaphore::new(dns_udp_task_limit(udp_task_limit)));
    let mut flow_budget_state = FlowBudgetState::new(runtime_policy.flows);
    let mut udp_flows = HashMap::new();
    let mut delayed_stack_events = VecDeque::new();
    let (stack_tx, mut stack_rx) = mpsc::channel(STACK_EVENT_CHANNEL_DEPTH);
    let fake_ip_mapper = dns_outbound_runtime.fake_ip_mapper();
    let dns_mode = TunDnsMode::from_config(config.as_ref(), fake_ip_mapper);
    let runtime_context = TunRuntimeContext {
        inbound_tag,
        sniffing,
        inbound_policy,
        config,
        outbound_router,
        dns_resolver,
        dns_bootstrap_resolver,
        dns_outbound_runtime,
        transport_dialer,
        stack_tx,
        tun: Arc::clone(&tun),
        tun_runtime_options,
        runtime_policy,
        tcp_pending_open_permits,
        dns_tcp_flow_permits,
        dns_tcp_connection_pool,
        tcp_flow_generation,
        udp_task_permits,
        dns_udp_task_permits,
        dns_mode,
        runtime_logger,
    };
    let mut last_flow_stats = StdInstant::now();
    let mut next_smoltcp_deadline = None;
    let mut tcp_stack_dirty = false;

    'runtime: loop {
        let smoltcp_now = Instant::now();
        let stats_wait = TUN_FLOW_STATS_INTERVAL.saturating_sub(last_flow_stats.elapsed());
        let wait_plan = tun_wait_plan(
            next_smoltcp_deadline,
            smoltcp_now,
            stats_wait,
            !delayed_stack_events.is_empty(),
            device.has_pending_outbound(),
        );
        let mut timer_expired = false;
        let mut tcp_stack_driven = false;

        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            packet = tun.poll_inbound() => {
                match packet {
                    Ok(packet) => {
                        match process_tun_packet(
                            packet,
                            &tun,
                            &mut iface,
                            &mut sockets,
                            &mut tcp_listeners,
                            &mut tcp_flows,
                            &mut udp_flows,
                            &mut flow_budget_state,
                            &runtime_context,
                            shutdown.clone(),
                            &mut bridge_tasks,
                            &mut udp_tasks,
                            &mut device,
                        )
                        .await
                        .tcp_stack_dirty()
                        {
                            Some(dirty) => tcp_stack_dirty |= dirty,
                            None => break,
                        }
                    }
                    Err(TunError::QueueClosed) => break,
                    Err(_) => {}
                }
            }
            event = stack_rx.recv(), if delayed_stack_events.is_empty() => {
                if let Some(event) = event {
                    let application = apply_or_delay_stack_event(
                        event,
                        &mut delayed_stack_events,
                        &mut tcp_flows,
                        &mut flow_budget_state,
                        &mut udp_flows,
                        &mut device,
                        Some(tun.as_ref()),
                    );
                    tcp_stack_dirty |= application.tcp_stack_dirty;
                }
            }
            joined = bridge_tasks.join_next(), if !bridge_tasks.is_empty() => {
                if let Some(result) = joined {
                    log_bridge_task_result(result, &runtime_context.runtime_logger);
                }
            }
            joined = udp_tasks.join_next(), if !udp_tasks.is_empty() => {
                if let Some(result) = joined {
                    log_bridge_task_result(result, &runtime_context.runtime_logger);
                }
            }
            () = sleep(wait_plan.duration) => {
                timer_expired = true;
            }
        }
        drain_completed_tasks(
            &mut bridge_tasks,
            &runtime_context.runtime_logger,
            MAX_BRIDGE_TASK_COMPLETIONS_PER_TICK,
        );
        drain_completed_tasks(
            &mut udp_tasks,
            &runtime_context.runtime_logger,
            MAX_UDP_TASK_COMPLETIONS_PER_TICK,
        );

        for _ in 0..MAX_TUN_INBOUND_DRAIN_PER_TICK {
            match tun.try_poll_inbound().await {
                Ok(Some(packet)) => {
                    match process_tun_packet(
                        packet,
                        &tun,
                        &mut iface,
                        &mut sockets,
                        &mut tcp_listeners,
                        &mut tcp_flows,
                        &mut udp_flows,
                        &mut flow_budget_state,
                        &runtime_context,
                        shutdown.clone(),
                        &mut bridge_tasks,
                        &mut udp_tasks,
                        &mut device,
                    )
                    .await
                    .tcp_stack_dirty()
                    {
                        Some(dirty) => tcp_stack_dirty |= dirty,
                        None => break 'runtime,
                    }
                }
                Ok(None) => break,
                Err(TunError::QueueClosed) => break 'runtime,
                Err(_) => {}
            }
        }

        tcp_stack_dirty |= drain_stack_events(
            &mut stack_rx,
            &mut delayed_stack_events,
            &mut tcp_flows,
            &mut flow_budget_state,
            &mut udp_flows,
            &mut device,
            Some(tun.as_ref()),
        );
        let outbound_backpressured = match flush_tun_outbound(&tun, &mut device).await {
            TunOutboundFlush::Complete => false,
            TunOutboundFlush::Backpressured => true,
            TunOutboundFlush::QueueClosed => break,
        };
        if !outbound_backpressured
            && (tcp_stack_dirty || (timer_expired && wait_plan.drive_tcp_stack_on_expiry))
        {
            drive_tun_tcp_stack(
                &tun,
                &mut iface,
                &mut device,
                &mut sockets,
                &mut tcp_listeners,
                &mut tcp_flows,
                &mut flow_budget_state,
                &runtime_context,
                shutdown.clone(),
                &mut bridge_tasks,
                tcp_stack_dirty,
            );
            tcp_stack_driven = true;
            tcp_stack_dirty = false;

            if drain_stack_events(
                &mut stack_rx,
                &mut delayed_stack_events,
                &mut tcp_flows,
                &mut flow_budget_state,
                &mut udp_flows,
                &mut device,
                Some(tun.as_ref()),
            ) {
                drive_tun_tcp_stack(
                    &tun,
                    &mut iface,
                    &mut device,
                    &mut sockets,
                    &mut tcp_listeners,
                    &mut tcp_flows,
                    &mut flow_budget_state,
                    &runtime_context,
                    shutdown.clone(),
                    &mut bridge_tasks,
                    true,
                );
                tcp_stack_driven = true;
            }
        }
        if tcp_stack_driven {
            let now = Instant::now();
            next_smoltcp_deadline = iface.poll_at(now, &sockets);
        }

        let active_udp_tasks = runtime_context
            .runtime_policy
            .flows
            .udp
            .max_active_flows
            .saturating_sub(runtime_context.udp_task_permits.available_permits());
        record_flow_counts(
            tun.as_ref(),
            &flow_budget_state,
            tcp_flows.len(),
            active_udp_tasks,
        );
        if last_flow_stats.elapsed() >= TUN_FLOW_STATS_INTERVAL {
            runtime_context
                .dns_tcp_connection_pool
                .prune_expired(TokioInstant::now());
            record_flow_budget_stats(
                tun.as_ref(),
                &mut flow_budget_state,
                &tcp_flows,
                active_udp_tasks,
            );
            last_flow_stats = StdInstant::now();
        }

        if matches!(
            flush_tun_outbound(&tun, &mut device).await,
            TunOutboundFlush::QueueClosed
        ) {
            break;
        }
    }

    bridge_tasks.abort_all();
    udp_tasks.abort_all();
    while bridge_tasks.join_next().await.is_some() {}
    while udp_tasks.join_next().await.is_some() {}
}

fn log_bridge_task_result(result: Result<(), JoinError>, runtime_logger: &RuntimeLogger) {
    if let Err(error) = result {
        if error.is_cancelled() {
            return;
        }
        runtime_logger.error(|| "Debug tunBridgeTask failed error=<redacted>".to_owned());
    }
}

fn drain_completed_tasks(
    tasks: &mut JoinSet<()>,
    runtime_logger: &RuntimeLogger,
    max_completions: usize,
) -> usize {
    let mut drained = 0usize;
    for _ in 0..max_completions {
        let Some(result) = tasks.try_join_next() else {
            break;
        };
        log_bridge_task_result(result, runtime_logger);
        drained += 1;
    }
    drained
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunOutboundFlush {
    Complete,
    Backpressured,
    QueueClosed,
}

async fn flush_tun_outbound(tun: &TunEndpoint, device: &mut PacketDevice) -> TunOutboundFlush {
    while let Some(packet) = device.front_outbound().cloned() {
        match tun.push_outbound(packet).await {
            Ok(()) => {
                device.pop_outbound();
            }
            Err(TunError::QueueFull) => return TunOutboundFlush::Backpressured,
            Err(TunError::QueueClosed) => return TunOutboundFlush::QueueClosed,
            Err(TunError::PacketTooLarge { .. }) => {
                device.pop_outbound();
            }
        }
    }
    TunOutboundFlush::Complete
}

#[expect(
    clippy::too_many_arguments,
    reason = "TUN stack drive owns the mutable packet-stack state"
)]
fn drive_tun_tcp_stack(
    tun: &TunEndpoint,
    iface: &mut Interface,
    device: &mut PacketDevice,
    sockets: &mut SocketSet<'static>,
    tcp_listeners: &mut HashMap<IpEndpoint, TcpListenerState>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
    bridge_tasks: &mut JoinSet<()>,
    tcp_state_dirty: bool,
) {
    if tcp_state_dirty || flow_budget_state.pending_total_bytes() > 0 {
        drain_tcp_remote_data_to_sockets(iface, device, sockets, tcp_flows, flow_budget_state);
    }

    iface.poll(Instant::now(), device, sockets);
    open_ready_tcp_flows(
        sockets,
        tcp_listeners,
        tcp_flows,
        context,
        shutdown,
        bridge_tasks,
    );
    read_socket_data_to_remote(tun, sockets, tcp_flows, flow_budget_state);
    cleanup_closed_tcp_flows(sockets, tcp_flows, flow_budget_state);
}

#[allow(clippy::too_many_arguments)]
async fn process_tun_packet(
    packet: Bytes,
    tun: &TunEndpoint,
    iface: &mut Interface,
    sockets: &mut SocketSet<'static>,
    tcp_listeners: &mut HashMap<IpEndpoint, TcpListenerState>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
    bridge_tasks: &mut JoinSet<()>,
    udp_tasks: &mut JoinSet<()>,
    device: &mut PacketDevice,
) -> TunPacketOutcome {
    if !valid_tun_ip_packet(&packet) {
        return TunPacketOutcome::Continue {
            tcp_stack_dirty: false,
        };
    }
    if let Some(reply) = icmp_echo_reply(&packet) {
        return match tun.push_outbound(reply).await {
            Err(TunError::QueueClosed) => TunPacketOutcome::QueueClosed,
            Ok(()) | Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {
                TunPacketOutcome::Continue {
                    tcp_stack_dirty: false,
                }
            }
        };
    }
    if let Some(udp_packet) = parse_udp_packet(&packet) {
        let dns_selection = match context
            .selected_dns_outbound_with_resolver(udp_packet.target, RoutingNetwork::Udp)
            .await
        {
            Ok(outbound) => outbound,
            Err(_) => {
                if let Some(reply) =
                    dns_proxy::dns_error_reply_packet(&udp_packet, DNS_RCODE_SERVFAIL)
                {
                    let _ = tun.push_outbound(reply).await;
                }
                return TunPacketOutcome::Continue {
                    tcp_stack_dirty: false,
                };
            }
        };
        let dns_outbound = dns_selection.as_ref().map(|(outbound, _)| outbound.clone());
        match dns_proxy::udp_action(&context.dns_mode, &udp_packet, dns_outbound) {
            DnsUdpAction::Drop => {
                return TunPacketOutcome::Continue {
                    tcp_stack_dirty: false,
                };
            }
            DnsUdpAction::Reply(reply) => {
                return match tun.push_outbound(reply).await {
                    Err(TunError::QueueClosed) => TunPacketOutcome::QueueClosed,
                    Ok(()) | Err(TunError::QueueFull | TunError::PacketTooLarge { .. }) => {
                        TunPacketOutcome::Continue {
                            tcp_stack_dirty: false,
                        }
                    }
                };
            }
            DnsUdpAction::Proxy(plan) => {
                let dns_permit = Arc::clone(&context.dns_udp_task_permits).try_acquire_owned();
                let Ok(dns_permit) = dns_permit else {
                    flow_budget_state.record_udp_budget_drop();
                    if let Some(reply) =
                        dns_proxy::dns_error_reply_packet(&udp_packet, DNS_RCODE_SERVFAIL)
                    {
                        let _ = tun.push_outbound(reply).await;
                    }
                    return TunPacketOutcome::Continue {
                        tcp_stack_dirty: false,
                    };
                };
                let global_permit = Arc::clone(&context.udp_task_permits).try_acquire_owned();
                let Ok(global_permit) = global_permit else {
                    flow_budget_state.record_udp_budget_drop();
                    if let Some(reply) =
                        dns_proxy::dns_error_reply_packet(&udp_packet, DNS_RCODE_SERVFAIL)
                    {
                        let _ = tun.push_outbound(reply).await;
                    }
                    return TunPacketOutcome::Continue {
                        tcp_stack_dirty: false,
                    };
                };
                udp_tasks.spawn(dns_proxy::bridge_udp_query(
                    plan,
                    udp_packet,
                    context.clone(),
                    shutdown,
                    global_permit,
                    dns_permit,
                ));
                return TunPacketOutcome::Continue {
                    tcp_stack_dirty: false,
                };
            }
            DnsUdpAction::Outbound { outbound, decision } => {
                let Some((_, client_target)) = dns_selection else {
                    return TunPacketOutcome::Continue {
                        tcp_stack_dirty: false,
                    };
                };
                let dns_permit = Arc::clone(&context.dns_udp_task_permits).try_acquire_owned();
                let Ok(dns_permit) = dns_permit else {
                    flow_budget_state.record_udp_budget_drop();
                    if let Some(reply) =
                        dns_proxy::dns_error_reply_packet(&udp_packet, DNS_RCODE_SERVFAIL)
                    {
                        let _ = tun.push_outbound(reply).await;
                    }
                    return TunPacketOutcome::Continue {
                        tcp_stack_dirty: false,
                    };
                };
                let global_permit = Arc::clone(&context.udp_task_permits).try_acquire_owned();
                let Ok(global_permit) = global_permit else {
                    flow_budget_state.record_udp_budget_drop();
                    if let Some(reply) =
                        dns_proxy::dns_error_reply_packet(&udp_packet, DNS_RCODE_SERVFAIL)
                    {
                        let _ = tun.push_outbound(reply).await;
                    }
                    return TunPacketOutcome::Continue {
                        tcp_stack_dirty: false,
                    };
                };
                udp_tasks.spawn(dns_proxy::bridge_dns_outbound_udp_query(
                    outbound,
                    decision,
                    client_target,
                    udp_packet,
                    context.clone(),
                    shutdown,
                    global_permit,
                    dns_permit,
                ));
                return TunPacketOutcome::Continue {
                    tcp_stack_dirty: false,
                };
            }
            DnsUdpAction::Pass => {}
        }
        handle_udp_packet(
            udp_packet,
            packet,
            udp_flows,
            flow_budget_state,
            context,
            shutdown,
            udp_tasks,
        );
        return TunPacketOutcome::Continue {
            tcp_stack_dirty: false,
        };
    }
    if let Some(endpoint) = tcp_syn_destination(&packet) {
        admit_tcp_listener(sockets, tcp_listeners, tcp_flows.len(), endpoint, context);
        device.push_inbound(packet);
        iface.poll(Instant::now(), device, sockets);
        open_ready_tcp_flows(
            sockets,
            tcp_listeners,
            tcp_flows,
            context,
            shutdown,
            bridge_tasks,
        );
        return TunPacketOutcome::Continue {
            tcp_stack_dirty: true,
        };
    }
    device.push_inbound(packet);
    TunPacketOutcome::Continue {
        tcp_stack_dirty: true,
    }
}

fn valid_tun_ip_packet(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => {
            if packet.len() < 20 {
                return false;
            }
            let header_len = usize::from(packet[0] & 0x0f) * 4;
            if header_len < 20 || packet.len() < header_len {
                return false;
            }
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            total_len >= header_len
                && packet.len() >= total_len
                && internet_checksum(&packet[..header_len]) == 0
        }
        Some(6) => {
            if packet.len() < 40 {
                return false;
            }
            let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            packet.len() >= 40 + payload_len
        }
        _ => false,
    }
}

#[derive(Clone)]
struct TunRuntimeContext {
    inbound_tag: Option<String>,
    sniffing: Option<InboundSniffingConfig>,
    inbound_policy: EffectivePolicy,
    config: Arc<CoreConfig>,
    outbound_router: Arc<OutboundRouter>,
    dns_resolver: Arc<dyn DnsResolver>,
    dns_bootstrap_resolver: Option<Arc<dyn DnsResolver>>,
    dns_outbound_runtime: Arc<crate::dns_outbound_runtime::DnsOutboundRuntime>,
    transport_dialer: Arc<TransportDialer>,
    stack_tx: mpsc::Sender<StackEvent>,
    tun: Arc<TunEndpoint>,
    tun_runtime_options: TunRuntimeOptions,
    runtime_policy: TunRuntimePolicy,
    tcp_pending_open_permits: Arc<Semaphore>,
    dns_tcp_flow_permits: Arc<Semaphore>,
    dns_tcp_connection_pool: Arc<dns_proxy::DnsTcpConnectionPool>,
    tcp_flow_generation: Arc<AtomicU64>,
    udp_task_permits: Arc<Semaphore>,
    dns_udp_task_permits: Arc<Semaphore>,
    dns_mode: TunDnsMode,
    runtime_logger: RuntimeLogger,
}

fn dns_udp_task_limit(global_udp_task_limit: usize) -> usize {
    if global_udp_task_limit == 0 {
        return 0;
    }
    (global_udp_task_limit / 4).clamp(1, MAX_DNS_UDP_TASKS)
}

fn dns_tcp_flow_limit(global_tcp_flow_limit: usize) -> usize {
    if global_tcp_flow_limit == 0 {
        return 0;
    }
    (global_tcp_flow_limit / 8).clamp(1, MAX_DNS_TCP_FLOWS)
}

impl TunRuntimeContext {
    fn bootstrap_dns_resolver(&self) -> &dyn DnsResolver {
        self.dns_bootstrap_resolver
            .as_deref()
            .unwrap_or(self.dns_resolver.as_ref())
    }

    fn target_from_endpoint(
        &self,
        endpoint: IpEndpoint,
        network: RoutingNetwork,
    ) -> Option<Target> {
        self.restored_target_from_endpoint(endpoint, network)
            .map(|restored| restored.target)
    }

    fn restored_target_from_endpoint(
        &self,
        endpoint: IpEndpoint,
        network: RoutingNetwork,
    ) -> Option<RestoredClientTarget> {
        let target = target_from_endpoint_with_network(endpoint, network)?;
        Some(self.dns_outbound_runtime.restore_client_target(&target))
    }

    fn selected_dns_outbound(
        &self,
        endpoint: IpEndpoint,
        network: RoutingNetwork,
    ) -> Result<Option<(DnsOutbound, Target)>, crate::CoreError> {
        let Some(target) = self.target_from_endpoint(endpoint, network) else {
            return Ok(None);
        };
        self.outbound_router
            .select_dns_outbound_for_session(self.inbound_tag.as_deref(), &target)
            .map(|outbound| outbound.map(|outbound| (outbound, target)))
    }

    async fn selected_dns_outbound_with_resolver(
        &self,
        endpoint: IpEndpoint,
        network: RoutingNetwork,
    ) -> Result<Option<(DnsOutbound, Target)>, crate::CoreError> {
        let Some(target) = self.target_from_endpoint(endpoint, network) else {
            return Ok(None);
        };
        self.outbound_router
            .select_dns_outbound_for_session_with_resolver(
                self.inbound_tag.as_deref(),
                &target,
                self.dns_resolver.as_ref(),
            )
            .await
            .map(|outbound| outbound.map(|outbound| (outbound, target)))
    }
}

#[derive(Debug)]
struct TcpFlow {
    generation: u64,
    to_remote: mpsc::Sender<StackToRemoteData>,
    task: Option<AbortHandle>,
    remote_open: bool,
    pending_remote: VecDeque<Bytes>,
    pending_remote_bytes: usize,
    remote_closed: bool,
    remote_aborted: bool,
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

struct TcpListenerState {
    handle: SocketHandle,
}

#[derive(Clone)]
enum TcpBridgeDestination {
    Standard(RestoredClientTarget),
    DnsProxy {
        client_target: Target,
        plan: Arc<dns_proxy::DnsProxyPlan>,
    },
    DnsOutbound {
        client_target: Target,
        outbound: DnsOutbound,
    },
}

enum ReadyTcpFlow {
    Bridge(TcpBridgeDestination),
    FakeDns(Arc<Mutex<FakeIpMapper>>),
    Reject(&'static str),
    Closed,
}

enum AdmittedTcpFlow {
    Bridge {
        destination: TcpBridgeDestination,
        permits: TcpBridgePermits,
    },
    FakeDns {
        mapper: Arc<Mutex<FakeIpMapper>>,
        permit: OwnedSemaphorePermit,
    },
}

struct TcpBridgePermits {
    pending_open: OwnedSemaphorePermit,
    dns_flow: Option<OwnedSemaphorePermit>,
}

struct TcpDialCandidate {
    target: Target,
    dns_upstream: Option<dns_proxy::DnsProxyUpstream>,
}

impl TcpBridgeDestination {
    fn client_target(&self) -> &Target {
        match self {
            Self::Standard(restored) => &restored.target,
            Self::DnsProxy {
                client_target: target,
                ..
            }
            | Self::DnsOutbound {
                client_target: target,
                ..
            } => target,
        }
    }

    fn dial_candidates(&self) -> Vec<TcpDialCandidate> {
        match self {
            Self::Standard(restored) => vec![TcpDialCandidate {
                target: restored.target.clone(),
                dns_upstream: None,
            }],
            Self::DnsProxy { plan, .. } => plan
                .upstreams()
                .iter()
                .map(|upstream| TcpDialCandidate {
                    target: upstream.target(RoutingNetwork::Tcp),
                    dns_upstream: Some(upstream.clone()),
                })
                .collect(),
            Self::DnsOutbound { .. } => Vec::new(),
        }
    }

    fn is_dns_proxy(&self) -> bool {
        matches!(self, Self::DnsProxy { .. } | Self::DnsOutbound { .. })
    }
}

struct TcpBridgeCloseGuard {
    handle: SocketHandle,
    generation: u64,
    stack_tx: mpsc::Sender<StackEvent>,
    armed: bool,
}

impl TcpBridgeCloseGuard {
    fn new(handle: SocketHandle, generation: u64, stack_tx: mpsc::Sender<StackEvent>) -> Self {
        Self {
            handle,
            generation,
            stack_tx,
            armed: true,
        }
    }

    async fn close(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self
            .stack_tx
            .send(StackEvent::RemoteClosed {
                handle: self.handle,
                generation: self.generation,
            })
            .await;
        self.armed = false;
    }

    async fn abort(&mut self) {
        if !self.armed {
            return;
        }
        let _ = self
            .stack_tx
            .send(StackEvent::RemoteAborted {
                handle: self.handle,
                generation: self.generation,
            })
            .await;
        self.armed = false;
    }
}

impl Drop for TcpBridgeCloseGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.stack_tx.try_send(StackEvent::RemoteAborted {
                handle: self.handle,
                generation: self.generation,
            });
        }
    }
}

#[derive(Debug)]
struct UdpFlow {
    to_remote: mpsc::Sender<Bytes>,
    generation: u64,
    last_used_sequence: u64,
    task: Option<AbortHandle>,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
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
    RemoteOpened {
        handle: SocketHandle,
        generation: u64,
    },
    RemoteData {
        handle: SocketHandle,
        generation: u64,
        data: Bytes,
    },
    RemoteClosed {
        handle: SocketHandle,
        generation: u64,
    },
    RemoteAborted {
        handle: SocketHandle,
        generation: u64,
    },
    UdpDatagram {
        client: IpEndpoint,
        source: IpEndpoint,
        payload: Bytes,
    },
    UdpClosed {
        key: UdpFlowKey,
        generation: u64,
    },
}

fn open_ready_tcp_flows(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<IpEndpoint, TcpListenerState>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
    bridge_tasks: &mut JoinSet<()>,
) {
    let ready = listeners
        .iter()
        .filter_map(|(endpoint, listener)| {
            let socket = sockets.get::<tcp::Socket>(listener.handle);
            if socket.is_listening() || flows.contains_key(&listener.handle) {
                return None;
            }
            let Some(local_endpoint) = socket.local_endpoint() else {
                return Some((*endpoint, ReadyTcpFlow::Closed));
            };
            let dns_selection = context.selected_dns_outbound(local_endpoint, RoutingNetwork::Tcp);
            let ready = match dns_selection {
                Err(_) => ReadyTcpFlow::Reject("TUN DNS outbound selection failed"),
                Ok(dns_selection) => {
                    let dns_outbound = dns_selection.as_ref().map(|(outbound, _)| outbound.clone());
                    match dns_proxy::tcp_action(&context.dns_mode, local_endpoint, dns_outbound) {
                        DnsTcpAction::Pass => context
                            .restored_target_from_endpoint(local_endpoint, RoutingNetwork::Tcp)
                            .map(TcpBridgeDestination::Standard)
                            .map(ReadyTcpFlow::Bridge)
                            .unwrap_or(ReadyTcpFlow::Reject(
                                "TUN TCP target mapping is unavailable",
                            )),
                        DnsTcpAction::Proxy(plan) => {
                            match target_from_endpoint_with_network(
                                local_endpoint,
                                RoutingNetwork::Tcp,
                            ) {
                                Some(client_target) => {
                                    ReadyTcpFlow::Bridge(TcpBridgeDestination::DnsProxy {
                                        client_target,
                                        plan,
                                    })
                                }
                                None => ReadyTcpFlow::Reject("TUN DNS TCP target is invalid"),
                            }
                        }
                        DnsTcpAction::Outbound(outbound) => {
                            match dns_selection.map(|(_, target)| target) {
                                Some(client_target) => {
                                    ReadyTcpFlow::Bridge(TcpBridgeDestination::DnsOutbound {
                                        client_target,
                                        outbound,
                                    })
                                }
                                None => ReadyTcpFlow::Reject("TUN DNS TCP target is invalid"),
                            }
                        }
                        DnsTcpAction::FakeIp(mapper) => ReadyTcpFlow::FakeDns(mapper),
                        DnsTcpAction::Reject => {
                            ReadyTcpFlow::Reject("TUN DNS TCP proxy is unavailable")
                        }
                    }
                }
            };
            Some((*endpoint, ready))
        })
        .collect::<Vec<_>>();

    for (endpoint, ready) in ready {
        let Some(listener) = listeners.remove(&endpoint) else {
            continue;
        };
        let handle = listener.handle;
        let generation = context.tcp_flow_generation.fetch_add(1, Ordering::Relaxed);
        let admitted = match ready {
            ReadyTcpFlow::Bridge(destination) => {
                let dns_flow_permit = if destination.is_dns_proxy() {
                    match Arc::clone(&context.dns_tcp_flow_permits).try_acquire_owned() {
                        Ok(permit) => Some(permit),
                        Err(_) => {
                            record_tcp_admission_rejection(
                                context,
                                endpoint,
                                "TUN DNS TCP flow limit reached",
                            );
                            insert_aborted_tcp_flow(handle, generation, flows);
                            continue;
                        }
                    }
                } else {
                    None
                };
                let pending_open_permit =
                    match Arc::clone(&context.tcp_pending_open_permits).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            record_tcp_admission_rejection(
                                context,
                                endpoint,
                                "TUN TCP pending-open limit reached",
                            );
                            insert_aborted_tcp_flow(handle, generation, flows);
                            continue;
                        }
                    };
                AdmittedTcpFlow::Bridge {
                    destination,
                    permits: TcpBridgePermits {
                        pending_open: pending_open_permit,
                        dns_flow: dns_flow_permit,
                    },
                }
            }
            ReadyTcpFlow::FakeDns(mapper) => {
                let permit = match Arc::clone(&context.dns_tcp_flow_permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        record_tcp_admission_rejection(
                            context,
                            endpoint,
                            "TUN fake DNS TCP flow limit reached",
                        );
                        insert_aborted_tcp_flow(handle, generation, flows);
                        continue;
                    }
                };
                AdmittedTcpFlow::FakeDns { mapper, permit }
            }
            ReadyTcpFlow::Reject(reason) => {
                record_tcp_endpoint_rejection(context, endpoint, reason);
                insert_aborted_tcp_flow(handle, generation, flows);
                continue;
            }
            ReadyTcpFlow::Closed => {
                sockets.remove(handle);
                continue;
            }
        };
        let (to_remote, from_stack) =
            mpsc::channel(context.runtime_policy.tcp_upload.channel_depth);
        flows.insert(
            handle,
            TcpFlow {
                generation,
                to_remote,
                task: None,
                remote_open: false,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
                remote_aborted: false,
            },
        );
        let task = match admitted {
            AdmittedTcpFlow::Bridge {
                destination,
                permits,
            } => match destination {
                TcpBridgeDestination::DnsProxy {
                    client_target,
                    plan,
                } => {
                    let TcpBridgePermits {
                        pending_open,
                        dns_flow,
                    } = permits;
                    bridge_tasks.spawn(dns_proxy::bridge_raw_dns_tcp_flow(
                        handle,
                        generation,
                        client_target,
                        plan,
                        context.clone(),
                        from_stack,
                        shutdown.clone(),
                        pending_open,
                        dns_flow,
                    ))
                }
                TcpBridgeDestination::DnsOutbound {
                    client_target,
                    outbound,
                } => {
                    let TcpBridgePermits {
                        pending_open,
                        dns_flow,
                    } = permits;
                    bridge_tasks.spawn(dns_proxy::bridge_dns_outbound_tcp_flow(
                        handle,
                        generation,
                        client_target,
                        outbound,
                        context.clone(),
                        from_stack,
                        shutdown.clone(),
                        Some(pending_open),
                        dns_flow,
                        false,
                        VecDeque::new(),
                    ))
                }
                destination => bridge_tasks.spawn(bridge_tcp_flow(
                    handle,
                    generation,
                    destination,
                    context.clone(),
                    from_stack,
                    shutdown.clone(),
                    permits,
                )),
            },
            AdmittedTcpFlow::FakeDns { mapper, permit } => {
                bridge_tasks.spawn(dns_proxy::bridge_fake_ip_tcp_flow(
                    handle,
                    generation,
                    mapper,
                    context.clone(),
                    from_stack,
                    shutdown.clone(),
                    permit,
                ))
            }
        };
        if let Some(flow) = flows.get_mut(&handle) {
            flow.task = Some(task);
        } else {
            task.abort();
        }
    }
}

fn insert_aborted_tcp_flow(
    handle: SocketHandle,
    generation: u64,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
) {
    let (to_remote, from_stack) = mpsc::channel(1);
    drop(from_stack);
    flows.insert(
        handle,
        TcpFlow {
            generation,
            to_remote,
            task: None,
            remote_open: false,
            pending_remote: VecDeque::new(),
            pending_remote_bytes: 0,
            remote_closed: false,
            remote_aborted: true,
        },
    );
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
    let joined = labels.join(".");
    let domain = if joined.is_empty() {
        ".".to_owned()
    } else {
        normalize_dns_domain(&joined)?
    };

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
    rcode: u16,
) -> Bytes {
    let has_answer =
        rcode == DNS_RCODE_NOERROR && answer.is_some() && question.qclass == DNS_CLASS_IN;
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let response_flags = 0x8000 | (request_flags & 0x0100) | 0x0080 | (rcode & 0x000f);
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
) -> bool {
    let mut tcp_stack_dirty = false;

    while let Some(event) = delayed_stack_events.pop_front() {
        let application = apply_or_delay_stack_event(
            event,
            delayed_stack_events,
            tcp_flows,
            flow_budget_state,
            udp_flows,
            device,
            tun,
        );
        tcp_stack_dirty |= application.tcp_stack_dirty;
        if !application.continue_draining {
            return tcp_stack_dirty;
        }
    }

    while let Ok(event) = stack_rx.try_recv() {
        let application = apply_or_delay_stack_event(
            event,
            delayed_stack_events,
            tcp_flows,
            flow_budget_state,
            udp_flows,
            device,
            tun,
        );
        tcp_stack_dirty |= application.tcp_stack_dirty;
        if !application.continue_draining {
            return tcp_stack_dirty;
        }
    }

    tcp_stack_dirty
}

fn apply_or_delay_stack_event(
    event: StackEvent,
    delayed_stack_events: &mut VecDeque<StackEvent>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    device: &mut PacketDevice,
    tun: Option<&TunEndpoint>,
) -> StackEventApplication {
    let tcp_stack_dirty = !matches!(
        &event,
        StackEvent::UdpDatagram { .. } | StackEvent::UdpClosed { .. }
    );
    match try_apply_stack_event(event, tcp_flows, flow_budget_state, udp_flows, device) {
        Ok(()) => StackEventApplication {
            continue_draining: true,
            tcp_stack_dirty,
        },
        Err(event) => {
            if let Some(tun) = tun {
                tun.record_tcp_remote_to_stack_backpressure();
            }
            delayed_stack_events.push_front(event);
            StackEventApplication {
                continue_draining: false,
                tcp_stack_dirty,
            }
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
        StackEvent::RemoteOpened { handle, generation } => {
            if let Some(flow) = tcp_flows
                .get_mut(&handle)
                .filter(|flow| flow.generation == generation)
            {
                flow.remote_open = true;
            }
        }
        StackEvent::RemoteData {
            handle,
            generation,
            data,
        } => {
            let Some(flow) = tcp_flows
                .get_mut(&handle)
                .filter(|flow| flow.generation == generation)
            else {
                return Ok(());
            };
            if !flow_budget_state.can_enqueue_remote_data(flow.pending_remote_bytes, data.len()) {
                return Err(StackEvent::RemoteData {
                    handle,
                    generation,
                    data,
                });
            }
            let pending_before = flow.pending_remote_bytes;
            let next_pending_bytes = pending_before.saturating_add(data.len());
            flow.pending_remote_bytes = next_pending_bytes;
            flow_budget_state.record_pending_remote_enqueue(pending_before, data.len());
            flow.pending_remote.push_back(data);
        }
        StackEvent::RemoteClosed { handle, generation } => {
            if let Some(flow) = tcp_flows
                .get_mut(&handle)
                .filter(|flow| flow.generation == generation)
            {
                flow.remote_closed = true;
            }
        }
        StackEvent::RemoteAborted { handle, generation } => {
            if let Some(flow) = tcp_flows
                .get_mut(&handle)
                .filter(|flow| flow.generation == generation)
            {
                flow.remote_aborted = true;
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
        StackEvent::UdpClosed { key, generation } => {
            remove_udp_flow_generation(udp_flows, key, generation);
        }
    }
    Ok(())
}

fn remove_udp_flow_generation(
    udp_flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    key: UdpFlowKey,
    generation: u64,
) -> bool {
    if udp_flows
        .get(&key)
        .is_none_or(|flow| flow.generation != generation)
    {
        return false;
    }
    udp_flows.remove(&key);
    true
}

fn record_flow_budget_stats(
    tun: &TunEndpoint,
    flow_budget_state: &mut FlowBudgetState,
    flows: &HashMap<SocketHandle, TcpFlow>,
    active_udp_tasks: usize,
) {
    flow_budget_state.refresh_tcp_pressure_state();
    let mut max_pending_bytes = 0usize;

    for flow in flows.values() {
        if flow.pending_remote_bytes > 0 {
            max_pending_bytes = max_pending_bytes.max(flow.pending_remote_bytes);
        }
    }

    tun.record_tcp_buffer_state(TunTcpBufferState {
        remote_bytes: flow_budget_state.pending_total_bytes(),
        remote_flows: flow_budget_state.pending_flow_count(),
        remote_max_bytes: max_pending_bytes,
        upload_bytes: flow_budget_state.pending_upload_bytes(),
        upload_max_bytes: flow_budget_state.pending_upload_max_bytes(),
        total_bytes: flow_budget_state.pending_tcp_buffer_bytes(),
        per_flow_limit_bytes: flow_budget_state.per_flow_limit(),
        hard_limit_bytes: flow_budget_state.hard_total_bytes(),
        pressure_active: flow_budget_state.pressure_active(),
    });
    record_flow_counts(tun, flow_budget_state, flows.len(), active_udp_tasks);
}

fn record_flow_counts(
    tun: &TunEndpoint,
    flow_budget_state: &FlowBudgetState,
    tcp_flows: usize,
    udp_flows: usize,
) {
    tun.record_flow_budget(
        tcp_flows,
        udp_flows,
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
        if flow.remote_aborted {
            socket.abort();
            continue;
        }
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
    flow_budget_state: &mut FlowBudgetState,
) {
    for (handle, flow) in flows {
        // Until the remote stream exists, leave client data in smoltcp's fixed
        // receive window instead of growing the bridge upload queues.
        if !flow.remote_open {
            continue;
        }
        let socket = sockets.get_mut::<tcp::Socket>(*handle);
        while socket.can_recv() {
            let max_read = flow_budget_state
                .available_upload_bytes()
                .min(TCP_BUFFER_SIZE);
            if max_read == 0 {
                tun.record_tcp_stack_to_remote_backpressure();
                break;
            }
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
                let len = data.len().min(max_read);
                (len, Bytes::copy_from_slice(&data[..len]))
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
            let Some(reservation) = flow_budget_state.reserve_pending_upload(data.len()) else {
                tun.record_tcp_stack_to_remote_backpressure();
                socket.abort();
                break;
            };
            tun.record_tcp_stack_to_remote(data.len());
            permit.send(StackToRemoteData::tracked(data, reservation));
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

async fn open_tcp_bridge_stream(
    outbound: &TcpOutbound,
    target: &Target,
    dns_upstream: Option<&dns_proxy::DnsProxyUpstream>,
    context: &TunRuntimeContext,
) -> Result<BoxedTransportStream, crate::CoreError> {
    if let Some(upstream) = dns_upstream {
        if upstream.is_local() {
            let candidates = dns_proxy::resolve_freedom_dns_upstreams(upstream, context).await?;
            return Ok(crate::dns::open_local_dns_tcp_stream(
                context.transport_dialer.as_ref(),
                target,
                &candidates,
            )
            .await?);
        }
        match outbound {
            TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => {
                let candidates =
                    dns_proxy::resolve_freedom_dns_upstreams(upstream, context).await?;
                return Ok(crate::dns::open_routed_freedom_dns_tcp_stream(
                    context.transport_dialer.as_ref(),
                    target,
                    &candidates,
                    outbound.freedom_happy_eyeballs(),
                )
                .await?);
            }
            TcpOutbound::Vless(_)
                if upstream
                    .socket_addr()
                    .is_some_and(socket_addr_has_nonzero_scope) =>
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "scoped IPv6 DNS upstream cannot be encoded in a VLESS target",
                )
                .into());
            }
            TcpOutbound::Vless(_) => {}
        }
    }
    let resolver = match outbound {
        TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => {
            context.dns_resolver.as_ref()
        }
        TcpOutbound::Vless(_) => context.bootstrap_dns_resolver(),
    };
    open_tcp_stream_with_resolver_and_dialer(outbound, target, resolver, &context.transport_dialer)
        .await
}

fn socket_addr_has_nonzero_scope(addr: SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(addr) if addr.scope_id() != 0)
}

async fn bridge_tcp_flow(
    handle: SocketHandle,
    generation: u64,
    mut destination: TcpBridgeDestination,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<StackToRemoteData>,
    mut shutdown: watch::Receiver<bool>,
    permits: TcpBridgePermits,
) {
    let mut client_already_opened = false;
    let mut initial_upload = VecDeque::new();
    if let TcpBridgeDestination::Standard(restored) = &destination {
        let sniffing_config = context
            .sniffing
            .as_ref()
            .filter(|config| should_sniff_tun_tcp(Some(config), restored.provenance));
        if let Some(sniffing_config) = sniffing_config {
            let opened = tokio::select! {
                biased;
                () = wait_for_tun_shutdown(&mut shutdown) => false,
                result = tokio::time::timeout(
                    context.inbound_policy.handshake,
                    context.stack_tx.send(StackEvent::RemoteOpened { handle, generation }),
                ) => matches!(result, Ok(Ok(()))),
            };
            if !opened {
                return;
            }
            client_already_opened = true;
            let Some((upload, sniffed)) = read_tun_tcp_sniff_payload(
                &mut from_stack,
                &mut shutdown,
                sniffing_config,
                &restored.target,
            )
            .await
            else {
                let mut close_guard =
                    TcpBridgeCloseGuard::new(handle, generation, context.stack_tx.clone());
                close_guard.close().await;
                return;
            };
            initial_upload = upload;
            if let Some(sniffed) = sniffed {
                destination = TcpBridgeDestination::Standard(RestoredClientTarget {
                    target: sniffed.route_target,
                    provenance: FakeIpTargetProvenance::InPoolUnmapped,
                });
            }
        }
    }

    if let TcpBridgeDestination::Standard(restored) = &destination {
        let client_target = &restored.target;
        let selected_dns_outbound = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(&mut shutdown) => return,
            result = context
                .outbound_router
                .select_dns_outbound_for_session_with_resolver(
                    context.inbound_tag.as_deref(),
                    client_target,
                    context.dns_resolver.as_ref(),
                ) => result,
        };
        match selected_dns_outbound {
            Ok(Some(outbound)) => {
                let TcpBridgePermits {
                    pending_open,
                    dns_flow,
                } = permits;
                debug_assert!(dns_flow.is_none());
                let dns_flow = match Arc::clone(&context.dns_tcp_flow_permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        record_tcp_target_rejection(
                            &context,
                            client_target,
                            "TUN DNS TCP flow limit reached",
                        );
                        let mut close_guard =
                            TcpBridgeCloseGuard::new(handle, generation, context.stack_tx.clone());
                        close_guard.abort().await;
                        return;
                    }
                };
                dns_proxy::bridge_dns_outbound_tcp_flow(
                    handle,
                    generation,
                    client_target.clone(),
                    outbound,
                    context,
                    from_stack,
                    shutdown,
                    Some(pending_open),
                    Some(dns_flow),
                    client_already_opened,
                    initial_upload,
                )
                .await;
                return;
            }
            Ok(None) => {}
            Err(_) => {
                record_tcp_target_rejection(
                    &context,
                    client_target,
                    "TUN DNS outbound selection failed",
                );
                let mut close_guard =
                    TcpBridgeCloseGuard::new(handle, generation, context.stack_tx.clone());
                close_guard.abort().await;
                return;
            }
        }
    }
    let TcpBridgePermits {
        pending_open,
        dns_flow: dns_flow_permit,
    } = permits;
    let close_guard = TcpBridgeCloseGuard::new(handle, generation, context.stack_tx.clone());
    bridge_tcp_flow_inner(
        handle,
        generation,
        destination,
        context,
        from_stack,
        shutdown,
        Some(pending_open),
        dns_flow_permit,
        close_guard,
        client_already_opened,
        true,
        None,
        None,
        initial_upload,
    )
    .await;
}

fn should_sniff_tun_tcp(
    config: Option<&InboundSniffingConfig>,
    provenance: FakeIpTargetProvenance,
) -> bool {
    provenance == FakeIpTargetProvenance::InPoolUnmapped
        && crate::sniffing::should_sniff_tcp(config)
}

async fn read_tun_tcp_sniff_payload(
    from_stack: &mut mpsc::Receiver<StackToRemoteData>,
    shutdown: &mut watch::Receiver<bool>,
    config: &InboundSniffingConfig,
    target: &Target,
) -> Option<(
    VecDeque<StackToRemoteData>,
    Option<crate::sniffing::SniffedTarget>,
)> {
    let mut initial_upload = VecDeque::new();
    let mut sniff_buffer = BytesMut::with_capacity(TUN_TCP_SNIFF_BUFFER_SIZE);
    let timeout = sleep(TUN_TCP_SNIFF_TIMEOUT);
    tokio::pin!(timeout);

    loop {
        let data = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return None;
                }
                continue;
            }
            () = &mut timeout => return Some((initial_upload, None)),
            data = from_stack.recv() => data?,
        };
        let remaining = TUN_TCP_SNIFF_BUFFER_SIZE.saturating_sub(sniff_buffer.len());
        let inspected = data.data.len().min(remaining);
        sniff_buffer.extend_from_slice(&data.data[..inspected]);
        initial_upload.push_back(data);

        if let Some(sniffed) =
            crate::sniffing::sniff_tcp_initial_payload(config, target, &sniff_buffer)
        {
            return Some((initial_upload, Some(sniffed)));
        }
        if sniff_buffer.len() >= TUN_TCP_SNIFF_BUFFER_SIZE {
            return Some((initial_upload, None));
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "transparent DNS fallback transfers already-open client state into the generic bridge"
)]
async fn bridge_preopened_dns_tcp_flow(
    handle: SocketHandle,
    generation: u64,
    client_target: Target,
    plan: Arc<dns_proxy::DnsProxyPlan>,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<StackToRemoteData>,
    shutdown: watch::Receiver<bool>,
    dns_flow_permit: Option<OwnedSemaphorePermit>,
    close_guard: TcpBridgeCloseGuard,
    initial_upload: VecDeque<StackToRemoteData>,
    client_upload_allowed: bool,
    idle_timeout_override: Option<Duration>,
    operation_timeout_override: Option<Duration>,
) {
    bridge_tcp_flow_inner(
        handle,
        generation,
        TcpBridgeDestination::DnsProxy {
            client_target,
            plan,
        },
        context,
        from_stack,
        shutdown,
        None,
        dns_flow_permit,
        close_guard,
        true,
        client_upload_allowed,
        idle_timeout_override,
        operation_timeout_override,
        initial_upload,
    )
    .await;
}

#[expect(
    clippy::too_many_arguments,
    reason = "generic bridge state is shared with the pre-opened transparent DNS handoff"
)]
async fn bridge_tcp_flow_inner(
    handle: SocketHandle,
    generation: u64,
    destination: TcpBridgeDestination,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<StackToRemoteData>,
    mut shutdown: watch::Receiver<bool>,
    pending_open: Option<OwnedSemaphorePermit>,
    _dns_flow_permit: Option<OwnedSemaphorePermit>,
    mut close_guard: TcpBridgeCloseGuard,
    client_already_opened: bool,
    client_upload_allowed: bool,
    idle_timeout_override: Option<Duration>,
    operation_timeout_override: Option<Duration>,
    mut initial_upload: VecDeque<StackToRemoteData>,
) {
    let collect_tcp_timings = context.tun_runtime_options.collect_tcp_timings;
    let tcp_timing_start = collect_tcp_timings.then(StdInstant::now);
    let client_target = destination.client_target().clone();
    let is_dns_proxy = destination.is_dns_proxy();
    let is_tcp443 = client_target.port == 443;
    let dns_operation_timeout =
        operation_timeout_override.unwrap_or(dns_proxy::DNS_TCP_PROXY_TOTAL_TIMEOUT);
    let dns_deadline = is_dns_proxy.then(|| TokioInstant::now() + dns_operation_timeout);
    let mut opened = None;
    let mut last_failure = None;

    let dial_candidates = destination.dial_candidates();
    let dial_candidate_count = dial_candidates.len();
    for (candidate_index, candidate) in dial_candidates.into_iter().enumerate() {
        let dial_target = candidate.target;
        let dns_upstream = candidate.dns_upstream;
        let routing_inbound_tag = dns_upstream
            .as_ref()
            .map(dns_proxy::DnsProxyUpstream::inbound_tag)
            .or(context.inbound_tag.as_deref());
        let candidate_deadline = dns_deadline.map(|total_deadline| {
            let now = TokioInstant::now();
            let remaining = total_deadline.saturating_duration_since(now);
            let remaining_candidate_count = dial_candidate_count.saturating_sub(candidate_index);
            let divisor = u32::try_from(remaining_candidate_count.max(1)).unwrap_or(u32::MAX);
            now + (remaining / divisor).min(dns_proxy::DNS_TCP_PROXY_ATTEMPT_TIMEOUT)
        });
        let selection_remaining = candidate_deadline
            .map(|deadline| deadline.saturating_duration_since(TokioInstant::now()));
        if selection_remaining.is_some_and(|remaining| remaining.is_zero()) {
            last_failure = Some(("DNS TCP proxy deadline elapsed".to_owned(), None));
            break;
        }
        let outbound_result = if dns_upstream
            .as_ref()
            .is_some_and(dns_proxy::DnsProxyUpstream::is_local)
        {
            Ok((TcpOutbound::Freedom, None))
        } else {
            tokio::select! {
                biased;
                () = wait_for_tun_shutdown(&mut shutdown) => return,
                result = async {
                    let select = async {
                        if is_dns_proxy {
                            context
                                .outbound_router
                                .select_tcp_outbound_for_session_with_tag(
                                    routing_inbound_tag,
                                    &dial_target,
                                    collect_tcp_timings,
                                )
                        } else {
                            context.outbound_router
                                .select_tcp_outbound_for_session_with_tag_and_resolver(
                                    routing_inbound_tag,
                                    &dial_target,
                                    collect_tcp_timings,
                                    context.dns_resolver.as_ref(),
                                )
                                .await
                        }
                    };
                    if let Some(remaining) = selection_remaining {
                        tokio::time::timeout(remaining, select)
                            .await
                            .map_err(|_| "DNS TCP route selection timed out".to_owned())?
                            .map_err(|error| error.to_string())
                    } else {
                        select.await.map_err(|error| error.to_string())
                    }
                } => result.map(|selection| (selection.outbound, selection.tag)),
            }
        };
        let (outbound, outbound_tag) = match outbound_result {
            Ok(selection) => selection,
            Err(error) => {
                last_failure = Some((error, None));
                continue;
            }
        };
        let policy_timeout = match &outbound {
            TcpOutbound::Freedom | TcpOutbound::FreedomHappyEyeballs(_) => {
                context.inbound_policy.handshake
            }
            TcpOutbound::Vless(outbound) => {
                effective_policy_for_level(&context.config, Some(outbound.user().level)).handshake
            }
        };
        let open_timeout = match candidate_deadline {
            Some(deadline) => {
                let remaining = deadline.saturating_duration_since(TokioInstant::now());
                if remaining.is_zero() {
                    last_failure = Some((
                        "DNS TCP proxy candidate deadline elapsed".to_owned(),
                        outbound_tag,
                    ));
                    if dns_deadline.is_some_and(|total_deadline| {
                        total_deadline
                            .saturating_duration_since(TokioInstant::now())
                            .is_zero()
                    }) {
                        break;
                    }
                    continue;
                }
                policy_timeout
                    .min(dns_proxy::DNS_TCP_PROXY_ATTEMPT_TIMEOUT)
                    .min(remaining)
            }
            None => policy_timeout,
        };
        let open_result = tokio::select! {
            biased;
            () = wait_for_tun_shutdown(&mut shutdown) => return,
            result = tokio::time::timeout(
                open_timeout,
                open_tcp_bridge_stream(
                    &outbound,
                    &dial_target,
                    dns_upstream.as_ref(),
                    &context,
                ),
            ) => result,
        };
        match open_result {
            Ok(Ok(stream)) => {
                opened = Some((
                    stream,
                    outbound,
                    outbound_tag,
                    dial_target,
                    routing_inbound_tag.map(ToOwned::to_owned),
                ));
                break;
            }
            Ok(Err(error)) => {
                last_failure = Some((error.to_string(), outbound_tag));
            }
            Err(_) => {
                last_failure = Some((
                    format!(
                        "outbound open timed out after {} ms",
                        open_timeout.as_millis()
                    ),
                    outbound_tag,
                ));
            }
        }
    }
    drop(pending_open);
    let Some((stream, outbound, outbound_tag, dial_target, routing_inbound_tag)) = opened else {
        let (error, outbound_tag) = last_failure
            .unwrap_or_else(|| ("no usable DNS TCP upstream configured".to_owned(), None));
        if context.runtime_logger.is_enabled() {
            let outbound_log_label = if outbound_tag.is_some() {
                "<configured>"
            } else {
                "untagged"
            };
            crate::debug_log::log_access_rejected(
                &context.runtime_logger,
                "tun",
                &client_target,
                &error,
            );
            context.runtime_logger.error(|| {
                format!(
                    "Debug tcpOpenError target={} outbound={outbound_log_label} error=<redacted>",
                    crate::debug_log::target_label(&client_target)
                )
            });
        }
        context.tun.record_tcp_open_error();
        record_tcp_open_error_event(
            context.tun.as_ref(),
            &client_target,
            outbound_tag.as_deref(),
            &error,
        );
        if is_dns_proxy {
            let _ =
                tokio::time::timeout(dns_proxy::DNS_TCP_PROXY_TOTAL_TIMEOUT, close_guard.abort())
                    .await;
        } else {
            close_guard.close().await;
        }
        return;
    };
    let bridge_idle_timeout = idle_timeout_override.unwrap_or(context.inbound_policy.conn_idle);
    let bridge_operation_timeout =
        is_dns_proxy.then_some(bridge_idle_timeout.min(dns_operation_timeout));
    if !client_already_opened
        && !matches!(
            await_with_optional_timeout(
                bridge_operation_timeout,
                context
                    .stack_tx
                    .send(StackEvent::RemoteOpened { handle, generation }),
            )
            .await,
            Some(Ok(()))
        )
    {
        return;
    }
    if context.runtime_logger.is_enabled() {
        let outbound_label = outbound_tag
            .as_deref()
            .unwrap_or_else(|| crate::debug_log::tcp_outbound_label(&outbound));
        crate::debug_log::log_route_decision(
            &context.runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: routing_inbound_tag.as_deref(),
                network: client_target.network,
                original_target: &client_target,
                sniffed_protocol: None,
                route_target: &dial_target,
                dial_target: &dial_target,
                selected_outbound: outbound_label,
            },
        );
        crate::debug_log::log_access_accepted(
            &context.runtime_logger,
            "tun",
            &client_target,
            outbound_label,
        );
    }
    let tcp_open_duration_ms = if let Some(start) = tcp_timing_start.as_ref() {
        let duration_ms = elapsed_ms_since(start);
        context.tun.record_tcp_open_timing(duration_ms, is_tcp443);
        record_tcp_slow_flow_event(
            context.tun.as_ref(),
            &client_target,
            TunTcpSlowFlowKind::Open,
            duration_ms,
            0,
        );
        Some(duration_ms)
    } else {
        None
    };
    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    if !initial_upload.is_empty()
        && !matches!(
            await_with_optional_timeout(
                bridge_operation_timeout,
                write_prebuffered_stack_data(
                    &mut remote_writer,
                    &dial_target,
                    outbound_tag.as_deref(),
                    &mut initial_upload,
                    context.tun.as_ref(),
                ),
            )
            .await,
            Some(Ok(()))
        )
    {
        context.tun.record_tcp_remote_write_error();
        let _ = await_with_optional_timeout(bridge_operation_timeout, close_guard.close()).await;
        return;
    }
    if let (Some(start), Some(open_duration_ms)) = (tcp_timing_start, tcp_open_duration_ms) {
        let mut timing = TcpFirstByteTimingEnabled::new(
            start,
            is_tcp443,
            open_duration_ms,
            outbound_tag.clone(),
        );
        bridge_tcp_flow_loop(
            handle,
            generation,
            &client_target,
            context,
            from_stack,
            shutdown,
            &mut remote_reader,
            &mut remote_writer,
            outbound_tag.as_deref(),
            &mut timing,
            bridge_idle_timeout,
            bridge_operation_timeout,
            client_upload_allowed,
        )
        .await;
    } else {
        let mut timing = TcpFirstByteTimingDisabled;
        bridge_tcp_flow_loop(
            handle,
            generation,
            &client_target,
            context,
            from_stack,
            shutdown,
            &mut remote_reader,
            &mut remote_writer,
            outbound_tag.as_deref(),
            &mut timing,
            bridge_idle_timeout,
            bridge_operation_timeout,
            client_upload_allowed,
        )
        .await;
    }
    let _ = await_with_optional_timeout(bridge_operation_timeout, close_guard.close()).await;
}

async fn wait_for_tun_shutdown(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if *shutdown.borrow() {
            return;
        }
    }
}

async fn await_with_optional_timeout<F>(timeout: Option<Duration>, future: F) -> Option<F::Output>
where
    F: std::future::Future,
{
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, future).await.ok(),
        None => Some(future.await),
    }
}

async fn write_prebuffered_stack_data<W>(
    remote_writer: &mut W,
    target: &Target,
    outbound_tag: Option<&str>,
    initial_upload: &mut VecDeque<StackToRemoteData>,
    tun: &TunEndpoint,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let write_start = StdInstant::now();
    let mut bytes = 0usize;
    let mut messages = 0usize;
    let mut reservations = Vec::with_capacity(initial_upload.len());
    while let Some(mut data) = initial_upload.pop_front() {
        remote_writer.write_all(&data.data).await?;
        bytes = bytes.saturating_add(data.len());
        messages = messages.saturating_add(1);
        if let Some(reservation) = data.reservation.take() {
            reservations.push(reservation);
        }
    }
    let write_duration_ms = elapsed_ms_since(&write_start);
    tun.record_tcp_remote_write_wait(write_duration_ms);
    record_tcp_remote_write_slow_event(
        tun,
        target,
        outbound_tag,
        write_duration_ms,
        bytes,
        messages,
    );
    tun.record_tcp_remote_written(bytes);
    let flush_start = StdInstant::now();
    remote_writer.flush().await?;
    tun.record_tcp_remote_flush_wait(elapsed_ms_since(&flush_start));
    tun.record_tcp_remote_write_batch(messages, bytes);
    drop(reservations);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn bridge_tcp_flow_loop<R, W, T>(
    handle: SocketHandle,
    generation: u64,
    target: &Target,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<StackToRemoteData>,
    mut shutdown: watch::Receiver<bool>,
    remote_reader: &mut R,
    remote_writer: &mut W,
    outbound_tag: Option<&str>,
    timing: &mut T,
    idle_timeout: Duration,
    operation_timeout: Option<Duration>,
    client_upload_allowed: bool,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: TcpFirstByteTiming,
{
    let mut read_buffer = vec![0; BRIDGE_READ_BUFFER_SIZE];
    let upload_policy = context.runtime_policy.tcp_upload;
    let mut upload_batch = BytesMut::new();
    let mut upload_reservations = Vec::with_capacity(upload_policy.max_batch_messages.min(64));
    let idle_sleep = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_sleep);

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            () = &mut idle_sleep => break,
            data = from_stack.recv() => {
                let Some(data) = data else {
                    break;
                };
                if !client_upload_allowed {
                    break;
                }
                let write = await_with_optional_timeout(
                    operation_timeout,
                    write_stack_batch_to_remote(
                        remote_writer,
                        target,
                        outbound_tag,
                        data,
                        &mut from_stack,
                        context.tun.as_ref(),
                        upload_policy,
                        &mut upload_batch,
                        &mut upload_reservations,
                    ),
                )
                .await;
                if !matches!(write, Some(Ok(()))) {
                    context.tun.record_tcp_remote_write_error();
                    break;
                }
                idle_sleep
                    .as_mut()
                    .reset(TokioInstant::now() + idle_timeout);
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
                let delivered = await_with_optional_timeout(
                    operation_timeout,
                    context.stack_tx.send(StackEvent::RemoteData {
                        handle,
                        generation,
                        data: Bytes::copy_from_slice(&read_buffer[..read]),
                    }),
                )
                .await;
                if !matches!(delivered, Some(Ok(()))) {
                    break;
                }
                idle_sleep
                    .as_mut()
                    .reset(TokioInstant::now() + idle_timeout);
            }
        }
    }

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

#[expect(
    clippy::too_many_arguments,
    reason = "upload batching keeps reusable scratch state and diagnostics explicit"
)]
async fn write_stack_batch_to_remote<W>(
    remote_writer: &mut W,
    target: &Target,
    outbound_tag: Option<&str>,
    first: StackToRemoteData,
    from_stack: &mut mpsc::Receiver<StackToRemoteData>,
    tun: &TunEndpoint,
    policy: TcpUploadBridgePolicy,
    batch: &mut BytesMut,
    reservations: &mut Vec<TcpUploadReservation>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    batch.clear();
    reservations.clear();

    let can_batch_more = policy.max_batch_messages > 1 && first.len() < policy.max_batch_bytes;
    let second = can_batch_more.then(|| from_stack.try_recv().ok()).flatten();

    if second.is_none() {
        let batch_bytes = first.len();
        let write_start = StdInstant::now();
        let write_result = remote_writer.write_all(&first.data).await;
        let write_duration_ms = elapsed_ms_since(&write_start);
        tun.record_tcp_remote_write_wait(write_duration_ms);
        record_tcp_remote_write_slow_event(
            tun,
            target,
            outbound_tag,
            write_duration_ms,
            batch_bytes,
            1,
        );
        write_result?;
        tun.record_tcp_remote_written(batch_bytes);
        let flush_start = StdInstant::now();
        let flush_result = remote_writer.flush().await;
        tun.record_tcp_remote_flush_wait(elapsed_ms_since(&flush_start));
        flush_result?;
        tun.record_tcp_remote_write_batch(1, batch_bytes);
        return Ok(());
    }

    let mut first = first;
    let mut batch_messages = 1usize;
    let mut batch_bytes = first.len();
    batch.reserve(first.len().min(policy.max_batch_bytes));
    batch.extend_from_slice(&first.data);
    if let Some(reservation) = first.reservation.take() {
        reservations.push(reservation);
    }

    let mut next = second;
    while let Some(mut item) = next {
        let data_len = item.data.len();
        batch.extend_from_slice(&item.data);
        if let Some(reservation) = item.reservation.take() {
            reservations.push(reservation);
        }

        batch_messages = batch_messages.saturating_add(1);
        batch_bytes = batch_bytes.saturating_add(data_len);
        if batch_messages >= policy.max_batch_messages || batch_bytes >= policy.max_batch_bytes {
            break;
        }

        next = from_stack.try_recv().ok();
    }

    let write_start = StdInstant::now();
    let write_result = remote_writer.write_all(batch).await;
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
    reservations.clear();
    Ok(())
}

fn handle_udp_packet(
    packet: UdpTunPacket,
    original_packet: Bytes,
    flows: &mut HashMap<UdpFlowKey, UdpFlow>,
    flow_budget_state: &mut FlowBudgetState,
    context: &TunRuntimeContext,
    shutdown: watch::Receiver<bool>,
    udp_tasks: &mut JoinSet<()>,
) {
    let key = UdpFlowKey::new(packet.client, packet.target);

    match flow_budget_state.admit_udp_flow(flows, key) {
        UdpFlowAdmission::Existing => {}
        UdpFlowAdmission::Admit { sequence } => {
            let Some(restored_target) =
                context.restored_target_from_endpoint(packet.target, RoutingNetwork::Udp)
            else {
                return;
            };
            let provenance = restored_target.provenance;
            let target = restored_target.target;
            let Some(task_permit) =
                try_acquire_udp_task_permit(&context.udp_task_permits, flow_budget_state)
            else {
                return;
            };
            let udp_timing_start = context
                .tun_runtime_options
                .collect_tcp_timings
                .then(StdInstant::now);
            let (to_remote, from_stack) = mpsc::channel(UDP_BRIDGE_CHANNEL_DEPTH);
            let task = udp_tasks.spawn(bridge_udp_flow(
                key,
                sequence,
                target,
                provenance,
                original_packet,
                context.clone(),
                from_stack,
                shutdown,
                udp_timing_start,
                task_permit,
            ));
            flows.insert(
                key,
                UdpFlow {
                    to_remote,
                    generation: sequence,
                    last_used_sequence: sequence,
                    task: Some(task),
                },
            );
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

fn try_acquire_udp_task_permit(
    permits: &Arc<Semaphore>,
    flow_budget_state: &mut FlowBudgetState,
) -> Option<OwnedSemaphorePermit> {
    match Arc::clone(permits).try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            flow_budget_state.record_udp_budget_drop();
            None
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "UDP bridge owns flow identity, cancellation, admission, and timing state"
)]
async fn bridge_udp_flow(
    key: UdpFlowKey,
    generation: u64,
    target: Target,
    provenance: FakeIpTargetProvenance,
    first_packet: Bytes,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    udp_timing_start: Option<StdInstant>,
    _task_permit: OwnedSemaphorePermit,
) {
    let Some(first_payload) = read_first_tun_udp_payload(&mut from_stack, &mut shutdown).await
    else {
        let _ = context
            .stack_tx
            .send(StackEvent::UdpClosed { key, generation })
            .await;
        return;
    };
    let sniffed_target = sniff_tun_udp_target(&context, &target, provenance, &first_payload);
    let sniffed_protocol = sniffed_target.sniffed_protocol;
    let route_target = sniffed_target.route_target;
    let dial_target = sniffed_target.dial_target;
    let selected = match context
        .outbound_router
        .select_udp_session_outbound_with_resolver(
            context.inbound_tag.as_deref(),
            &route_target,
            context.dns_resolver.as_ref(),
        )
        .await
    {
        Ok(outbound) => outbound,
        Err(_) => {
            if context.runtime_logger.is_enabled() {
                crate::debug_log::log_access_rejected(
                    &context.runtime_logger,
                    "tun",
                    &route_target,
                    "udp outbound selection failed",
                );
            }
            context.tun.record_udp_open_error();
            let _ = context
                .stack_tx
                .send(StackEvent::UdpClosed { key, generation })
                .await;
            return;
        }
    };

    if context.runtime_logger.is_enabled() {
        let selected_outbound = match &selected {
            UdpSessionOutbound::Transport(outbound) => {
                crate::debug_log::udp_outbound_label(outbound)
            }
            UdpSessionOutbound::Dns(_) => "dns",
        };
        crate::debug_log::log_route_decision(
            &context.runtime_logger,
            crate::debug_log::RouteDecisionLog {
                inbound_tag: context.inbound_tag.as_deref(),
                network: target.network,
                original_target: &target,
                sniffed_protocol,
                route_target: &route_target,
                dial_target: &dial_target,
                selected_outbound,
            },
        );
    }

    let outbound = match selected {
        UdpSessionOutbound::Transport(outbound) => outbound,
        UdpSessionOutbound::Dns(outbound) => {
            let Ok(dns_permit) = Arc::clone(&context.dns_udp_task_permits).try_acquire_owned()
            else {
                let _ = context
                    .stack_tx
                    .send(StackEvent::UdpClosed { key, generation })
                    .await;
                return;
            };
            bridge_udp_dns_outbound_flow(
                key,
                generation,
                dial_target,
                outbound,
                context,
                from_stack,
                shutdown,
                first_payload,
                dns_permit,
            )
            .await;
            return;
        }
    };

    if dial_target.port == 443 {
        if let UdpOutbound::Vless(outbound) = &outbound {
            if outbound.blocks_udp443() {
                if let Some(reply) = icmp_port_unreachable_reply(&first_packet) {
                    let _ = context.tun.push_outbound(reply).await;
                }
                if context.runtime_logger.is_enabled() {
                    crate::debug_log::log_access_rejected(
                        &context.runtime_logger,
                        "tun",
                        &dial_target,
                        crate::CoreError::VisionUdp443Rejected,
                    );
                    context.runtime_logger.error(|| {
                        format!(
                            "Debug udpVisionUDP443Rejected target={} outbound=vless",
                            crate::debug_log::target_label(&dial_target)
                        )
                    });
                }
                context.tun.record_udp_vision_udp443_rejection();
                let _ = context
                    .stack_tx
                    .send(StackEvent::UdpClosed { key, generation })
                    .await;
                return;
            }
        }
    }

    match outbound {
        UdpOutbound::Freedom => {
            bridge_udp_freedom_flow(
                key,
                generation,
                dial_target,
                context,
                from_stack,
                shutdown,
                udp_timing_start,
                first_payload,
            )
            .await;
        }
        UdpOutbound::Vless(outbound) => {
            bridge_udp_vless_flow(
                key,
                generation,
                dial_target,
                outbound,
                context,
                from_stack,
                shutdown,
                udp_timing_start,
                first_payload,
            )
            .await;
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "TUN DNS UDP flow owns flow identity, routing, shutdown, and admission"
)]
async fn bridge_udp_dns_outbound_flow(
    key: UdpFlowKey,
    generation: u64,
    routed_target: Target,
    outbound: DnsOutbound,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    first_payload: Bytes,
    _dns_permit: OwnedSemaphorePermit,
) {
    let client = key.client.into_endpoint();
    let response_source = key.target.into_endpoint();
    let path_payload_cap = dns_proxy::dns_udp_path_payload_cap(context.tun.mtu(), response_source);
    let idle_timeout = UDP_IDLE_TIMEOUT.min(outbound.conn_idle_timeout());
    let mut pending_payload = Some(first_payload);

    loop {
        let payload = match pending_payload.take() {
            Some(payload) => payload,
            None => {
                tokio::select! {
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                        continue;
                    }
                    () = sleep(idle_timeout) => break,
                    payload = from_stack.recv() => {
                        let Some(payload) = payload else {
                            break;
                        };
                        payload
                    }
                }
            }
        };

        let outcome = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
                continue;
            }
            outcome = context.dns_outbound_runtime.execute_message(
                &outbound,
                &routed_target,
                payload,
                crate::dns_outbound_runtime::DnsClientTransport::Udp { path_payload_cap },
            ) => outcome,
        };
        let crate::dns_outbound_runtime::DnsMessageOutcome::Reply(response) = outcome else {
            continue;
        };
        let sent = tokio::select! {
            changed = shutdown.changed() => changed.is_ok() && !*shutdown.borrow(),
            sent = context.stack_tx.send(StackEvent::UdpDatagram {
                client,
                source: response_source,
                payload: response,
            }) => sent.is_ok(),
        };
        if !sent {
            break;
        }
    }

    let _ = context
        .stack_tx
        .send(StackEvent::UdpClosed { key, generation })
        .await;
}

async fn read_first_tun_udp_payload(
    from_stack: &mut mpsc::Receiver<Bytes>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<Bytes> {
    tokio::select! {
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                None
            } else {
                from_stack.recv().await
            }
        }
        payload = from_stack.recv() => payload,
    }
}

struct TunUdpSniffedTarget {
    route_target: Target,
    dial_target: Target,
    sniffed_protocol: Option<xray_config::SniffingDestination>,
}

impl TunUdpSniffedTarget {
    fn original(target: &Target) -> Self {
        Self {
            route_target: target.clone(),
            dial_target: target.clone(),
            sniffed_protocol: None,
        }
    }

    fn from_sniffed(
        target: &Target,
        provenance: FakeIpTargetProvenance,
        sniffed: Option<crate::sniffing::SniffedTarget>,
    ) -> Self {
        if provenance == FakeIpTargetProvenance::Mapped {
            return Self::original(target);
        }
        let Some(mut sniffed) = sniffed else {
            return Self::original(target);
        };
        if provenance == FakeIpTargetProvenance::InPoolUnmapped {
            sniffed.dial_target = sniffed.route_target.clone();
        }
        let sniffed_protocol = Some(sniffed.protocol);
        Self {
            route_target: sniffed.route_target,
            dial_target: sniffed.dial_target,
            sniffed_protocol,
        }
    }
}

fn sniff_tun_udp_target(
    context: &TunRuntimeContext,
    target: &Target,
    provenance: FakeIpTargetProvenance,
    first_payload: &[u8],
) -> TunUdpSniffedTarget {
    if provenance == FakeIpTargetProvenance::Mapped {
        return TunUdpSniffedTarget::from_sniffed(target, provenance, None);
    }
    let Some(config) = context.sniffing.as_ref() else {
        return TunUdpSniffedTarget::original(target);
    };
    if !crate::sniffing::should_sniff_udp(Some(config)) {
        return TunUdpSniffedTarget::original(target);
    }
    let Some(sniffed) = crate::sniffing::sniff_udp_initial_payload(config, target, first_payload)
    else {
        return TunUdpSniffedTarget::original(target);
    };
    TunUdpSniffedTarget::from_sniffed(target, provenance, Some(sniffed))
}

#[expect(
    clippy::too_many_arguments,
    reason = "UDP freedom bridge receives bounded per-flow runtime state explicitly"
)]
async fn bridge_udp_freedom_flow(
    key: UdpFlowKey,
    generation: u64,
    target: Target,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
    udp_timing_start: Option<StdInstant>,
    first_payload: Bytes,
) {
    let target_addr = match resolve_udp_freedom_target(&target, context.dns_resolver.as_ref()).await
    {
        Ok(target) => target,
        Err(_) => {
            if context.runtime_logger.is_enabled() {
                crate::debug_log::log_access_rejected(
                    &context.runtime_logger,
                    "tun",
                    &target,
                    "udp target resolution failed",
                );
            }
            context.tun.record_udp_open_error();
            let _ = context
                .stack_tx
                .send(StackEvent::UdpClosed { key, generation })
                .await;
            return;
        }
    };
    let bind_addr = match target_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(_) => {
            if context.runtime_logger.is_enabled() {
                crate::debug_log::log_access_rejected(
                    &context.runtime_logger,
                    "tun",
                    &target,
                    "udp socket bind failed",
                );
            }
            context.tun.record_udp_open_error();
            let _ = context
                .stack_tx
                .send(StackEvent::UdpClosed { key, generation })
                .await;
            return;
        }
    };
    if protect_udp_socket(&socket, context.transport_dialer.socket_protector()).is_err() {
        if context.runtime_logger.is_enabled() {
            crate::debug_log::log_access_rejected(
                &context.runtime_logger,
                "tun",
                &target,
                "udp socket protect failed",
            );
        }
        context.tun.record_udp_open_error();
        let _ = context
            .stack_tx
            .send(StackEvent::UdpClosed { key, generation })
            .await;
        return;
    }
    context.tun.record_udp_remote_open(target.port == 443);
    if context.runtime_logger.is_enabled() {
        crate::debug_log::log_access_accepted(&context.runtime_logger, "tun", &target, "freedom");
    }
    if let Some(start) = udp_timing_start {
        let mut timing = UdpFirstResponseTimingEnabled::new(start);
        bridge_udp_freedom_flow_loop(
            key,
            generation,
            target,
            target_addr,
            socket,
            context,
            from_stack,
            shutdown,
            &mut timing,
            first_payload,
        )
        .await;
    } else {
        let mut timing = UdpFirstResponseTimingDisabled;
        bridge_udp_freedom_flow_loop(
            key,
            generation,
            target,
            target_addr,
            socket,
            context,
            from_stack,
            shutdown,
            &mut timing,
            first_payload,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_udp_freedom_flow_loop<T>(
    key: UdpFlowKey,
    generation: u64,
    target: Target,
    target_addr: SocketAddr,
    socket: UdpSocket,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    timing: &mut T,
    first_payload: Bytes,
) where
    T: UdpFirstResponseTiming,
{
    let client = key.client.into_endpoint();
    let response_source = key.target.into_endpoint();
    let mut read_buffer = vec![0; BRIDGE_READ_BUFFER_SIZE];
    let first_payload_len = first_payload.len();
    if socket.send_to(&first_payload, target_addr).await.is_err() {
        context.tun.record_udp_remote_write_error();
        let _ = context
            .stack_tx
            .send(StackEvent::UdpClosed { key, generation })
            .await;
        return;
    }
    context.tun.record_udp_remote_written(first_payload_len);
    timing.record_written(first_payload_len);

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

    let _ = context
        .stack_tx
        .send(StackEvent::UdpClosed { key, generation })
        .await;
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

#[expect(
    clippy::too_many_arguments,
    reason = "flow bridge task receives shared runtime state explicitly"
)]
async fn bridge_udp_vless_flow(
    key: UdpFlowKey,
    generation: u64,
    target: Target,
    outbound: Box<VlessTcpOutbound>,
    context: TunRuntimeContext,
    from_stack: mpsc::Receiver<Bytes>,
    shutdown: watch::Receiver<bool>,
    udp_timing_start: Option<StdInstant>,
    first_payload: Bytes,
) {
    // Regular xtls-rprx-vision cannot carry UDP/443 (QUIC); reject it
    // unconditionally as upstream xray-core does. xtls-rprx-vision-udp443 still
    // allows it. This is the backstop for any packet that reaches VLESS opening
    // without the flow-level ICMP rejection running first.
    let options = VlessUdpOpenOptions::default();
    let (stream, framing) = match open_vless_udp_stream_with_resolver_dialer_and_options(
        &outbound,
        &target,
        context.bootstrap_dns_resolver(),
        &context.transport_dialer,
        options,
    )
    .await
    {
        Ok(opened) => opened,
        Err(error) => {
            if context.runtime_logger.is_enabled() {
                crate::debug_log::log_access_rejected(
                    &context.runtime_logger,
                    "tun",
                    &target,
                    &error,
                );
                context.runtime_logger.error(|| {
                    format!(
                        "Debug udpOpenError target={} outbound=vless error=<redacted>",
                        crate::debug_log::target_label(&target)
                    )
                });
            }
            context.tun.record_udp_open_error();
            if matches!(error, crate::CoreError::VisionUdp443Rejected) {
                context.tun.record_udp_vision_udp443_rejection();
            }
            let _ = context
                .stack_tx
                .send(StackEvent::UdpClosed { key, generation })
                .await;
            return;
        }
    };
    context.tun.record_udp_remote_open(target.port == 443);
    if context.runtime_logger.is_enabled() {
        crate::debug_log::log_access_accepted(&context.runtime_logger, "tun", &target, "vless");
    }

    let (mut remote_reader, mut remote_writer) = tokio::io::split(stream);
    if let Some(start) = udp_timing_start {
        let mut timing = UdpFirstResponseTimingEnabled::new(start);
        bridge_udp_vless_flow_loop(
            key,
            generation,
            target,
            context,
            from_stack,
            shutdown,
            framing,
            &mut remote_reader,
            &mut remote_writer,
            &mut timing,
            first_payload,
        )
        .await;
    } else {
        let mut timing = UdpFirstResponseTimingDisabled;
        bridge_udp_vless_flow_loop(
            key,
            generation,
            target,
            context,
            from_stack,
            shutdown,
            framing,
            &mut remote_reader,
            &mut remote_writer,
            &mut timing,
            first_payload,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn bridge_udp_vless_flow_loop<R, W, T>(
    key: UdpFlowKey,
    generation: u64,
    target: Target,
    context: TunRuntimeContext,
    mut from_stack: mpsc::Receiver<Bytes>,
    mut shutdown: watch::Receiver<bool>,
    framing: VlessUdpFraming,
    remote_reader: &mut R,
    remote_writer: &mut W,
    timing: &mut T,
    first_payload: Bytes,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    T: UdpFirstResponseTiming,
{
    let fallback_source = key.target.into_endpoint();
    let client = key.client.into_endpoint();
    let global_id = udp_flow_global_id(key);
    let mut sent_xudp_new = false;
    let first_payload_len = first_payload.len();
    let frame = match framing {
        VlessUdpFraming::LengthPrefixed => encode_udp_packet(&first_payload),
        VlessUdpFraming::Xudp => {
            sent_xudp_new = true;
            encode_xudp_new_packet(&target, &first_payload, global_id)
        }
    };
    let Ok(frame) = frame else {
        let _ = context
            .stack_tx
            .send(StackEvent::UdpClosed { key, generation })
            .await;
        return;
    };
    if remote_writer.write_all(&frame).await.is_err() {
        context.tun.record_udp_remote_write_error();
        let _ = context
            .stack_tx
            .send(StackEvent::UdpClosed { key, generation })
            .await;
        return;
    }
    if remote_writer.flush().await.is_err() {
        context.tun.record_udp_remote_write_error();
        let _ = context
            .stack_tx
            .send(StackEvent::UdpClosed { key, generation })
            .await;
        return;
    }
    context.tun.record_udp_remote_written(first_payload_len);
    timing.record_written(first_payload_len);

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

    let _ = context
        .stack_tx
        .send(StackEvent::UdpClosed { key, generation })
        .await;
}

fn admit_tcp_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<IpEndpoint, TcpListenerState>,
    active_flow_count: usize,
    endpoint: IpEndpoint,
    context: &TunRuntimeContext,
) {
    if listeners.contains_key(&endpoint) {
        return;
    }

    if !tcp_listener_capacity_available(
        context.runtime_policy.flows.tcp,
        active_flow_count,
        listeners.len(),
    ) {
        record_tcp_admission_rejection(context, endpoint, "TUN TCP flow limit reached");
        return;
    }

    add_tcp_listener(sockets, listeners, endpoint);
}

fn tcp_listener_capacity_available(
    policy: TcpFlowBudgetPolicy,
    active_flow_count: usize,
    listener_count: usize,
) -> bool {
    active_flow_count.saturating_add(listener_count) < policy.max_active_flows
}

fn add_tcp_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<IpEndpoint, TcpListenerState>,
    endpoint: IpEndpoint,
) {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
    );
    socket.set_nagle_enabled(false);
    if socket.listen(endpoint).is_ok() {
        listeners.insert(
            endpoint,
            TcpListenerState {
                handle: sockets.add(socket),
            },
        );
    }
}

fn record_tcp_admission_rejection(
    context: &TunRuntimeContext,
    endpoint: IpEndpoint,
    reason: &'static str,
) {
    let Some(target) = context.target_from_endpoint(endpoint, RoutingNetwork::Tcp) else {
        return;
    };

    record_tcp_target_rejection(context, &target, reason);
}

fn record_tcp_endpoint_rejection(
    context: &TunRuntimeContext,
    endpoint: IpEndpoint,
    reason: &'static str,
) {
    let Some(target) = target_from_endpoint_with_network(endpoint, RoutingNetwork::Tcp) else {
        return;
    };

    record_tcp_target_rejection(context, &target, reason);
}

fn record_tcp_target_rejection(context: &TunRuntimeContext, target: &Target, reason: &'static str) {
    context.tun.record_tcp_open_error();
    record_tcp_open_error_event(context.tun.as_ref(), target, None, reason);
    if context.runtime_logger.is_enabled() {
        crate::debug_log::log_access_rejected(&context.runtime_logger, "tun", target, reason);
        context.runtime_logger.error(|| {
            format!(
                "Debug tcpOpenError target={} outbound=unselected error=<redacted>",
                crate::debug_log::target_label(target)
            )
        });
    }
}

#[cfg(test)]
fn ipv4_udp_payload_for_destination(packet: &Bytes, destination_port: u16) -> Option<Bytes> {
    let parsed = parse_ipv4_udp_packet(packet)?;
    (parsed.target.port == destination_port).then_some(parsed.payload)
}

fn parse_udp_packet(packet: &Bytes) -> Option<UdpTunPacket> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_udp_packet(packet),
        6 => parse_ipv6_udp_packet(packet),
        _ => None,
    }
}

fn parse_ipv4_udp_packet(packet: &Bytes) -> Option<UdpTunPacket> {
    let bytes = packet.as_ref();
    if bytes.len() < 28 {
        return None;
    }

    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if header_len < 20 || bytes.len() < header_len + 8 || bytes[9] != UDP_PROTOCOL {
        return None;
    }

    let fragment = u16::from_be_bytes([bytes[6], bytes[7]]);
    if fragment & 0x3fff != 0 {
        return None;
    }

    let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total_len < header_len + 8 || bytes.len() < total_len {
        return None;
    }

    let udp = &bytes[header_len..total_len];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_len < 8 || udp.len() < udp_len {
        return None;
    }

    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
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
        payload: packet.slice(header_len + 8..header_len + udp_len),
    })
}

fn parse_ipv6_udp_packet(packet: &Bytes) -> Option<UdpTunPacket> {
    let bytes = packet.as_ref();
    if bytes.len() < 48 || bytes[6] != UDP_PROTOCOL {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if payload_len < 8 || bytes.len() < 40 + payload_len {
        return None;
    }

    let source = <[u8; 16]>::try_from(&bytes[8..24]).ok()?;
    let destination = <[u8; 16]>::try_from(&bytes[24..40]).ok()?;
    let udp = &bytes[40..40 + payload_len];
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
        payload: packet.slice(48..40 + udp_len),
    })
}

fn build_udp_packet(source: IpEndpoint, destination: IpEndpoint, payload: &[u8]) -> Option<Bytes> {
    match (source.addr, destination.addr) {
        (IpAddress::Ipv4(source_addr), IpAddress::Ipv4(destination_addr)) => build_ipv4_udp_packet(
            source_addr,
            source.port,
            destination_addr,
            destination.port,
            payload,
        ),
        (IpAddress::Ipv6(source_addr), IpAddress::Ipv6(destination_addr)) => build_ipv6_udp_packet(
            source_addr,
            source.port,
            destination_addr,
            destination.port,
            payload,
        ),
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
) -> Option<Bytes> {
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

    Some(Bytes::from(packet))
}

fn build_ipv6_udp_packet(
    source: Ipv6Addr,
    source_port: u16,
    destination: Ipv6Addr,
    destination_port: u16,
    payload: &[u8],
) -> Option<Bytes> {
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
    let checksum = nonzero_udp_checksum(ipv6_transport_checksum(
        source.octets(),
        destination.octets(),
        UDP_PROTOCOL,
        udp,
    ));
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    Some(Bytes::from(packet))
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
    internet_checksum_slices([data])
}

fn internet_checksum_slices<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> u16 {
    let mut sum = 0u64;
    let mut odd_byte = None;

    for mut part in parts {
        if let Some(high) = odd_byte.take() {
            let Some((&low, rest)) = part.split_first() else {
                odd_byte = Some(high);
                continue;
            };
            sum += u64::from(u16::from_be_bytes([high, low]));
            part = rest;
        }

        let mut chunks = part.chunks_exact(2);
        for chunk in &mut chunks {
            sum += u64::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        if let Some(&byte) = chunks.remainder().first() {
            odd_byte = Some(byte);
        }
    }

    if let Some(byte) = odd_byte {
        sum += u64::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let source = source.octets();
    let destination = destination.octets();
    let protocol = [0, UDP_PROTOCOL];
    let udp_len = (udp.len() as u16).to_be_bytes();
    internet_checksum_slices([
        source.as_slice(),
        destination.as_slice(),
        protocol.as_slice(),
        udp_len.as_slice(),
        udp,
    ])
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
    let payload_len = (payload.len() as u32).to_be_bytes();
    let protocol = [0, 0, 0, next_header];
    internet_checksum_slices([
        source.as_slice(),
        destination.as_slice(),
        payload_len.as_slice(),
        protocol.as_slice(),
        payload,
    ])
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

    fn front_outbound(&self) -> Option<&Bytes> {
        self.outbound.front()
    }

    fn has_pending_outbound(&self) -> bool {
        !self.outbound.is_empty()
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

    fn test_fake_ip_mapper(
        network: Ipv4Addr,
        prefix: u8,
        pool_size: u32,
        ttl: u32,
        query_strategy: ConfigDnsQueryStrategy,
    ) -> FakeIpMapper {
        let config = xray_config::DnsFakeIpConfig {
            enabled: true,
            ipv4_pool: xray_config::IpCidr::new(IpAddr::V4(network), prefix).unwrap(),
            pool_size,
            ttl,
        };
        FakeIpMapper::from_config(&config, query_strategy, &[TUN_DNS_ANCHOR, TUN_CLIENT_IPV4])
            .unwrap()
    }

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

    fn stack_to_remote_data(data: Bytes) -> StackToRemoteData {
        StackToRemoteData::untracked(data)
    }

    #[tokio::test]
    async fn optional_bridge_operation_timeout_bounds_pending_dns_io() {
        assert_eq!(
            await_with_optional_timeout(None, std::future::ready(7_u8)).await,
            Some(7)
        );
        assert!(await_with_optional_timeout(
            Some(Duration::from_millis(10)),
            std::future::pending::<()>(),
        )
        .await
        .is_none());
    }

    #[test]
    fn tcp_slow_flow_event_records_slow_tcp_targets() {
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
                kind: TunTcpSlowFlowKind::Open,
                target: "speedtest.example:8443".to_owned(),
                open_duration_ms: TCP_SLOW_FLOW_THRESHOLD_MS + 1,
                first_byte_duration_ms: 0,
            })
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
    fn tcp_slow_flow_event_uses_500ms_threshold_for_tcp_targets() {
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
    fn tcp_remote_write_slow_event_uses_500ms_threshold_for_tcp_targets() {
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
        assert_eq!(
            tun.poll_tcp_remote_write_slow_event(),
            Some(TunTcpRemoteWriteSlowEvent {
                target: "speedtest.example:8443".to_owned(),
                outbound_tag: Some("proxy".to_owned()),
                duration_ms: 501,
                bytes: 2_048,
                messages: 2,
            })
        );

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
    fn tcp_flow_summary_event_records_large_tcp_flows() {
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
                target: "speedtest.example:8443".to_owned(),
                outbound_tag: Some("proxy".to_owned()),
                closed: true,
                duration_ms: 3_000,
                open_duration_ms: 300,
                first_byte_duration_ms: 500,
                remote_read_bytes: TCP_FLOW_SUMMARY_MIN_BYTES,
                ms_to_64kib: 700,
                ms_to_128kib: 750,
                ms_to_256kib: 800,
                ms_to_512kib: 900,
                ms_to_1mib: 0,
            })
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
        tx.try_send(stack_to_remote_data(Bytes::from_static(b"two")))
            .unwrap();
        tx.try_send(stack_to_remote_data(Bytes::from_static(b"three")))
            .unwrap();
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();
        let mut batch = BytesMut::new();
        let mut reservations = Vec::new();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            stack_to_remote_data(Bytes::from_static(b"one")),
            &mut rx,
            &tun,
            DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
            &mut batch,
            &mut reservations,
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
    async fn stack_to_remote_single_chunk_avoids_batch_copy_buffer() {
        let (_tx, mut rx) = mpsc::channel(1);
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();
        let mut batch = BytesMut::new();
        let mut reservations = Vec::new();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            stack_to_remote_data(Bytes::from_static(b"one")),
            &mut rx,
            &tun,
            DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
            &mut batch,
            &mut reservations,
        )
        .await
        .unwrap();

        assert_eq!(batch.capacity(), 0);
    }

    #[tokio::test]
    async fn stack_to_remote_batch_reuses_copy_buffer() {
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();
        let mut batch = BytesMut::new();
        let mut reservations = Vec::new();
        let mut allocated_capacity = None;

        for _ in 0..2 {
            let (tx, mut rx) = mpsc::channel(1);
            tx.try_send(stack_to_remote_data(Bytes::from_static(b"two")))
                .unwrap();
            write_stack_batch_to_remote(
                &mut writer,
                &target,
                Some("proxy"),
                stack_to_remote_data(Bytes::from_static(b"one")),
                &mut rx,
                &tun,
                DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
                &mut batch,
                &mut reservations,
            )
            .await
            .unwrap();
            allocated_capacity.get_or_insert(batch.capacity());
        }

        assert_eq!(Some(batch.capacity()), allocated_capacity);
    }

    #[tokio::test]
    async fn stack_to_remote_write_batch_uses_low_memory_upload_byte_limit() {
        let chunk = Bytes::from_static(&[0x5a; 16 * 1024]);
        let policy = tun_runtime_policy_for_options(TunRuntimeOptions::with_profile(
            TunRuntimeProfile::LowMemory,
        ))
        .tcp_upload;
        let (tx, mut rx) = mpsc::channel(TCP_BRIDGE_CHANNEL_DEPTH);
        for _ in 0..TCP_BRIDGE_CHANNEL_DEPTH {
            tx.try_send(stack_to_remote_data(chunk.clone())).unwrap();
        }
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();
        let mut batch = BytesMut::new();
        let mut reservations = Vec::new();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            stack_to_remote_data(chunk),
            &mut rx,
            &tun,
            policy,
            &mut batch,
            &mut reservations,
        )
        .await
        .unwrap();

        let stats = tun.stats().await;
        assert_eq!(stats.tcp_remote_write_batches, 1);
        assert_eq!(stats.tcp_remote_write_batch_max_messages, 16);
        assert_eq!(stats.tcp_remote_write_batch_max_bytes, 256 * 1024);
        assert_eq!(writer.written.len(), 256 * 1024);
    }

    #[tokio::test]
    async fn stack_to_remote_write_batch_drains_a_full_channel_before_flushing() {
        let (tx, mut rx) = mpsc::channel(TCP_BRIDGE_CHANNEL_DEPTH);
        for _ in 0..TCP_BRIDGE_CHANNEL_DEPTH {
            tx.try_send(stack_to_remote_data(Bytes::from_static(&[0x5a; 1024])))
                .unwrap();
        }
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();
        let mut batch = BytesMut::new();
        let mut reservations = Vec::new();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            stack_to_remote_data(Bytes::from_static(&[0x7b; 1024])),
            &mut rx,
            &tun,
            DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
            &mut batch,
            &mut reservations,
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
            tx.try_send(stack_to_remote_data(Bytes::from_static(&[0x5a; 1024])))
                .unwrap();
        }
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();
        let mut batch = BytesMut::new();
        let mut reservations = Vec::new();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            stack_to_remote_data(Bytes::from_static(&[0x7b; 1024])),
            &mut rx,
            &tun,
            DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
            &mut batch,
            &mut reservations,
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
            tx.try_send(stack_to_remote_data(chunk.clone())).unwrap();
        }
        let mut writer = CountingWrite::default();
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let target = test_tcp443_target();
        let mut batch = BytesMut::new();
        let mut reservations = Vec::new();

        write_stack_batch_to_remote(
            &mut writer,
            &target,
            Some("proxy"),
            stack_to_remote_data(chunk),
            &mut rx,
            &tun,
            DEFAULT_TCP_UPLOAD_BRIDGE_POLICY,
            &mut batch,
            &mut reservations,
        )
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

    #[test]
    fn low_memory_tcp_flow_budget_caps_active_flows_and_pending_opens() {
        let policy = LOW_MEMORY_FLOW_BUDGET_POLICY.tcp;

        assert_eq!(policy.max_active_flows, 128);
        assert_eq!(policy.max_pending_opens, 32);
        assert!(tcp_listener_capacity_available(policy, 127, 0));
        assert!(!tcp_listener_capacity_available(policy, 127, 1));
        assert!(!tcp_listener_capacity_available(policy, 128, 0));
    }

    #[test]
    fn dns_udp_task_limit_reserves_capacity_for_ordinary_udp_flows() {
        assert_eq!(dns_udp_task_limit(0), 0);
        assert_eq!(dns_udp_task_limit(1), 1);
        assert_eq!(
            dns_udp_task_limit(LOW_MEMORY_FLOW_BUDGET_POLICY.udp.max_active_flows),
            32
        );
        assert_eq!(
            dns_udp_task_limit(MOBILE_FLOW_BUDGET_POLICY.udp.max_active_flows),
            64
        );
        assert_eq!(
            dns_udp_task_limit(THROUGHPUT_FLOW_BUDGET_POLICY.udp.max_active_flows),
            64
        );
    }

    fn test_flow_budget(max_active_udp_flows: usize) -> FlowBudgetState {
        FlowBudgetState::new(FlowBudgetPolicy {
            tcp_remote: MOBILE_TCP_REMOTE_BUFFER_POLICY,
            tcp: MOBILE_FLOW_BUDGET_POLICY.tcp,
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
                generation: last_used_sequence,
                last_used_sequence,
                task: None,
            },
        );
    }

    #[test]
    fn idle_wait_plan_defers_stack_drive_until_smoltcp_deadline() {
        let now = Instant::from_millis(1_000);

        let plan = tun_wait_plan(None, now, TUN_FLOW_STATS_INTERVAL, false, false);

        assert_eq!(
            plan,
            TunWaitPlan {
                duration: TUN_FLOW_STATS_INTERVAL,
                drive_tcp_stack_on_expiry: false,
            }
        );
    }

    #[test]
    fn smoltcp_deadline_schedules_stack_drive_without_fixed_polling() {
        let now = Instant::from_millis(1_000);

        let plan = tun_wait_plan(
            Some(Instant::from_millis(1_010)),
            now,
            TUN_FLOW_STATS_INTERVAL,
            false,
            false,
        );

        assert_eq!(
            plan,
            TunWaitPlan {
                duration: Duration::from_millis(10),
                drive_tcp_stack_on_expiry: true,
            }
        );
    }

    #[test]
    fn outbound_backpressure_defers_tcp_drive_until_queued_packets_are_flushed() {
        let now = Instant::from_millis(1_000);

        let plan = tun_wait_plan(
            Some(Instant::from_millis(0)),
            now,
            TUN_FLOW_STATS_INTERVAL,
            false,
            true,
        );

        assert_eq!(
            plan,
            TunWaitPlan {
                duration: TUN_BACKPRESSURE_RETRY_INTERVAL,
                drive_tcp_stack_on_expiry: false,
            }
        );
    }

    #[tokio::test]
    async fn outbound_backpressure_preserves_packet_order_for_retry() {
        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let filler = Bytes::from_static(b"filler");
        let first = Bytes::from_static(b"first");
        let second = Bytes::from_static(b"second");
        tun.push_outbound(filler.clone()).await.unwrap();
        let mut device = PacketDevice::new(1500);
        device.push_outbound(first.clone());
        device.push_outbound(second.clone());

        assert_eq!(
            flush_tun_outbound(&tun, &mut device).await,
            TunOutboundFlush::Backpressured
        );
        assert_eq!(device.front_outbound(), Some(&first));
        assert_eq!(tun.poll_outbound().await.unwrap(), filler);

        assert_eq!(
            flush_tun_outbound(&tun, &mut device).await,
            TunOutboundFlush::Backpressured
        );
        assert_eq!(device.front_outbound(), Some(&second));
        assert_eq!(tun.poll_outbound().await.unwrap(), first);

        assert_eq!(
            flush_tun_outbound(&tun, &mut device).await,
            TunOutboundFlush::Complete
        );
        assert!(!device.has_pending_outbound());
        assert_eq!(tun.poll_outbound().await.unwrap(), second);
    }

    #[tokio::test]
    async fn completed_bridge_task_drain_is_bounded_per_tick() {
        let mut tasks = JoinSet::new();
        let completed = Arc::new(AtomicUsize::new(0));
        let task_count = MAX_BRIDGE_TASK_COMPLETIONS_PER_TICK + 3;
        for _ in 0..task_count {
            let completed = Arc::clone(&completed);
            tasks.spawn(async move {
                completed.fetch_add(1, Ordering::Release);
            });
        }
        while completed.load(Ordering::Acquire) < task_count {
            tokio::task::yield_now().await;
        }

        let drained = drain_completed_tasks(
            &mut tasks,
            &RuntimeLogger::disabled(),
            MAX_BRIDGE_TASK_COMPLETIONS_PER_TICK,
        );

        assert_eq!(drained, MAX_BRIDGE_TASK_COMPLETIONS_PER_TICK);
    }

    #[tokio::test]
    async fn completed_udp_task_drain_covers_maximum_spawn_burst() {
        let mut tasks = JoinSet::new();
        let completed = Arc::new(AtomicUsize::new(0));
        for _ in 0..MAX_UDP_TASK_COMPLETIONS_PER_TICK {
            let completed = Arc::clone(&completed);
            tasks.spawn(async move {
                completed.fetch_add(1, Ordering::Release);
            });
        }
        while completed.load(Ordering::Acquire) < MAX_UDP_TASK_COMPLETIONS_PER_TICK {
            tokio::task::yield_now().await;
        }

        let drained = drain_completed_tasks(
            &mut tasks,
            &RuntimeLogger::disabled(),
            MAX_UDP_TASK_COMPLETIONS_PER_TICK,
        );

        assert_eq!(drained, MAX_UDP_TASK_COMPLETIONS_PER_TICK);
        assert!(tasks.is_empty());
    }

    #[tokio::test]
    async fn udp_flow_eviction_aborts_owned_bridge_task() {
        let mut tasks = JoinSet::<()>::new();
        let task = tasks.spawn(std::future::pending::<()>());
        let oldest_key = test_udp_key(1);
        let mut flows = HashMap::new();
        let (to_remote, _from_stack) = mpsc::channel(1);
        flows.insert(
            oldest_key,
            UdpFlow {
                to_remote,
                generation: 1,
                last_used_sequence: 1,
                task: Some(task),
            },
        );
        let mut budget = test_flow_budget(1);

        let _ = budget.admit_udp_flow(&mut flows, test_udp_key(2));
        let joined = tokio::time::timeout(Duration::from_secs(1), tasks.join_next())
            .await
            .unwrap()
            .unwrap();

        assert!(joined.unwrap_err().is_cancelled());
    }

    #[test]
    fn udp_task_permit_caps_pending_and_active_bridges() {
        let permits = Arc::new(Semaphore::new(1));
        let mut budget = test_flow_budget(1);
        let _first = try_acquire_udp_task_permit(&permits, &mut budget).unwrap();

        let second = try_acquire_udp_task_permit(&permits, &mut budget);

        assert!(second.is_none() && budget.udp_budget_drops() == 1);
    }

    #[test]
    fn stale_udp_close_does_not_remove_replacement_generation() {
        let key = test_udp_key(1);
        let mut flows = HashMap::new();
        insert_udp_flow(&mut flows, key, 2);

        let removed = remove_udp_flow_generation(&mut flows, key, 1);

        assert!(!removed && flows.contains_key(&key));
    }

    #[test]
    fn mobile_flow_budget_keeps_udp_capacity_high_but_bounded() {
        assert_eq!(MOBILE_FLOW_BUDGET_POLICY.udp.max_active_flows, 512);
        assert_eq!(DESKTOP_FLOW_BUDGET_POLICY.udp.max_active_flows, 1024);
    }

    #[test]
    fn low_memory_profile_reduces_tun_flow_budgets() {
        let policy = tun_runtime_policy_for_options(TunRuntimeOptions::with_profile(
            TunRuntimeProfile::LowMemory,
        ));

        assert_eq!(policy.flows.udp.max_active_flows, 128);
        assert_eq!(policy.flows.tcp_remote.normal_per_flow_bytes, 1024 * 1024);
        assert_eq!(policy.flows.tcp_remote.hard_total_bytes, 20 * 1024 * 1024);
    }

    #[test]
    fn low_memory_profile_reduces_tcp_upload_bridge_limits() {
        let policy = tun_runtime_policy_for_options(TunRuntimeOptions::with_profile(
            TunRuntimeProfile::LowMemory,
        ));

        assert_eq!(policy.tcp_upload.channel_depth, 64);
        assert_eq!(policy.tcp_upload.max_batch_messages, 65);
        assert_eq!(policy.tcp_upload.max_batch_bytes, 256 * 1024);
    }

    #[test]
    fn mobile_profiles_use_reduced_tcp_upload_bridge_limits() {
        for profile in [TunRuntimeProfile::Mobile, TunRuntimeProfile::MobilePlus] {
            let policy = tun_runtime_policy_for_options(TunRuntimeOptions::with_profile(profile));

            assert_eq!(policy.tcp_upload.channel_depth, 128);
            assert_eq!(policy.tcp_upload.max_batch_messages, 129);
            assert_eq!(policy.tcp_upload.max_batch_bytes, 1024 * 1024);
        }
    }

    #[test]
    fn low_memory_runtime_policy_groups_tun_budgets() {
        let policy = tun_runtime_policy_for_options(TunRuntimeOptions::with_profile(
            TunRuntimeProfile::LowMemory,
        ));

        assert_eq!(policy.flows.udp.max_active_flows, 128);
        assert_eq!(policy.flows.tcp_remote.normal_per_flow_bytes, 1024 * 1024);
        assert_eq!(policy.tcp_upload.channel_depth, 64);
        assert_eq!(policy.tcp_upload.max_batch_bytes, 256 * 1024);
    }

    #[test]
    fn mobile_plus_profile_uses_mobile_total_budget_with_larger_pressure_window() {
        let policy = tun_runtime_policy_for_options(TunRuntimeOptions::with_profile(
            TunRuntimeProfile::MobilePlus,
        ));

        assert_eq!(
            policy.flows.tcp_remote.normal_per_flow_bytes,
            MOBILE_TCP_REMOTE_BUFFER_POLICY.normal_per_flow_bytes
        );
        assert_eq!(
            policy.flows.tcp_remote.pressure_per_flow_bytes,
            MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_per_flow_bytes
        );
        assert_eq!(
            policy.flows.tcp_remote.pressure_start_total_bytes,
            30 * 1024 * 1024
        );
        assert_eq!(
            policy.flows.tcp_remote.pressure_release_total_bytes,
            20 * 1024 * 1024
        );
        assert_eq!(policy.flows.tcp_remote.hard_total_bytes, 40 * 1024 * 1024);
        assert_eq!(policy.flows.udp.max_active_flows, 512);
        assert_eq!(policy.tcp_upload, MOBILE_TCP_UPLOAD_BRIDGE_POLICY);
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
    fn flow_budget_counts_upload_bytes_against_tcp_hard_budget() {
        let mut budget = test_flow_budget(256);

        assert!(budget.try_reserve_pending_upload(MOBILE_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes));
        assert!(!budget.can_enqueue_remote_data(0, 1));

        budget.record_pending_upload_dequeue(MOBILE_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes);

        assert!(budget.can_enqueue_remote_data(0, 1));
    }

    #[test]
    fn flow_budget_counts_upload_bytes_for_pressure_hysteresis() {
        let mut budget = test_flow_budget(256);

        assert_eq!(budget.per_flow_limit(), NORMAL_TCP_REMOTE_PENDING_LIMIT);

        assert!(budget.try_reserve_pending_upload(
            MOBILE_TCP_REMOTE_BUFFER_POLICY.pressure_start_total_bytes
        ));
        assert_eq!(budget.per_flow_limit(), PRESSURE_TCP_REMOTE_PENDING_LIMIT);

        budget.record_pending_upload_dequeue(8 * 1024 * 1024 - 1);
        assert_eq!(budget.per_flow_limit(), PRESSURE_TCP_REMOTE_PENDING_LIMIT);

        budget.record_pending_upload_dequeue(1);
        assert_eq!(budget.per_flow_limit(), NORMAL_TCP_REMOTE_PENDING_LIMIT);
    }

    #[tokio::test]
    async fn upload_tcp_data_backpressures_when_combined_budget_is_full() {
        let client_ip = Ipv4Addr::new(10, 10, 0, 2);
        let server_ip = Ipv4Addr::new(203, 0, 113, 7);
        let client_port = 49_152;
        let server_port = 443;
        let client_seq = 1_000u32;
        let payload = [0x5a; 1024];
        let endpoint = IpEndpoint::new(IpAddress::Ipv4(server_ip), server_port);

        let mut device = PacketDevice::new(1500);
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = DEFAULT_RANDOM_SEED;
        let mut iface = Interface::new(iface_config, &mut device, Instant::now());
        iface.set_any_ip(true);
        let mut sockets = SocketSet::new(Vec::new());
        let mut listeners = HashMap::new();
        add_tcp_listener(&mut sockets, &mut listeners, endpoint);
        let handle = listeners.get(&endpoint).unwrap().handle;

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

        device.push_inbound(Bytes::from(build_ipv4_tcp_packet(
            client_ip,
            client_port,
            server_ip,
            server_port,
            client_seq + 1,
            server_seq + 1,
            TCP_ACK,
            &payload,
        )));
        iface.poll(Instant::now(), &mut device, &mut sockets);

        let tun = TunEndpoint::new(xray_tun::TunConfig {
            mtu: 1500,
            queue_depth: 1,
        });
        let (to_remote, mut from_stack) = mpsc::channel(1);
        let mut flow_budget_state = test_flow_budget(256);
        flow_budget_state
            .record_pending_remote_enqueue(0, MOBILE_TCP_REMOTE_BUFFER_POLICY.hard_total_bytes);
        let mut tcp_flows = HashMap::new();
        tcp_flows.insert(
            handle,
            TcpFlow {
                generation: 1,
                to_remote,
                task: None,
                remote_open: true,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
                remote_aborted: false,
            },
        );

        read_socket_data_to_remote(&tun, &mut sockets, &mut tcp_flows, &mut flow_budget_state);

        assert!(from_stack.try_recv().is_err());
        assert_eq!(flow_budget_state.pending_upload_bytes(), 0);
        let stats = tun.stats().await;
        assert_eq!(stats.tcp_stack_to_remote_bytes, 0);
        assert_eq!(stats.tcp_stack_to_remote_backpressure_events, 1);
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
                generation: 1,
                to_remote,
                task: None,
                remote_open: true,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: NORMAL_TCP_REMOTE_PENDING_LIMIT,
                remote_closed: false,
                remote_aborted: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                generation: 1,
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
                generation: 1,
                to_remote,
                task: None,
                remote_open: true,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
                remote_aborted: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (_stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::from([StackEvent::RemoteData {
            handle,
            generation: 1,
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
    fn stale_tcp_events_do_not_mutate_a_reused_socket_handle() {
        let mut sockets = SocketSet::new(Vec::new());
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]),
        ));
        let (to_remote, _from_stack) = mpsc::channel(1);
        let mut tcp_flows = HashMap::from([(
            handle,
            TcpFlow {
                generation: 2,
                to_remote,
                task: None,
                remote_open: false,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
                remote_aborted: false,
            },
        )]);
        let mut flow_budget_state = test_flow_budget(256);
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);

        for event in [
            StackEvent::RemoteOpened {
                handle,
                generation: 1,
            },
            StackEvent::RemoteData {
                handle,
                generation: 1,
                data: Bytes::from_static(b"stale"),
            },
            StackEvent::RemoteClosed {
                handle,
                generation: 1,
            },
            StackEvent::RemoteAborted {
                handle,
                generation: 1,
            },
        ] {
            try_apply_stack_event(
                event,
                &mut tcp_flows,
                &mut flow_budget_state,
                &mut udp_flows,
                &mut device,
            )
            .unwrap();
        }

        let flow = tcp_flows.get(&handle).unwrap();
        assert!(!flow.remote_open);
        assert!(!flow.remote_closed);
        assert!(!flow.remote_aborted);
        assert!(flow.pending_remote.is_empty());
        assert_eq!(flow_budget_state.pending_total_bytes(), 0);
    }

    #[tokio::test]
    async fn dropping_tcp_flow_aborts_task_and_releases_pending_open_permit() {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let mut tasks = JoinSet::new();
        let task = tasks.spawn(async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        });
        let (to_remote, _from_stack) = mpsc::channel(1);
        let flow = TcpFlow {
            generation: 1,
            to_remote,
            task: Some(task),
            remote_open: false,
            pending_remote: VecDeque::new(),
            pending_remote_bytes: 0,
            remote_closed: false,
            remote_aborted: false,
        };

        drop(flow);

        let reacquired = tokio::time::timeout(
            Duration::from_millis(100),
            Arc::clone(&semaphore).acquire_owned(),
        )
        .await
        .expect("aborted bridge task should release its permit")
        .unwrap();
        drop(reacquired);
        assert!(tasks.join_next().await.unwrap().unwrap_err().is_cancelled());
    }

    #[test]
    fn scoped_ipv6_dns_upstreams_are_detected_before_vless_encoding() {
        assert!(socket_addr_has_nonzero_scope(
            "[fe80::53%2]:5353".parse().unwrap()
        ));
        assert!(!socket_addr_has_nonzero_scope(
            "[2001:db8::53]:5353".parse().unwrap()
        ));
        assert!(!socket_addr_has_nonzero_scope(
            "192.0.2.53:5353".parse().unwrap()
        ));
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
                generation: 1,
                to_remote,
                task: None,
                remote_open: true,
                pending_remote,
                pending_remote_bytes: 1024 * 1024,
                remote_closed: false,
                remote_aborted: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                generation: 1,
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
                generation: 1,
                to_remote,
                task: None,
                remote_open: true,
                pending_remote: VecDeque::new(),
                pending_remote_bytes: 0,
                remote_closed: false,
                remote_aborted: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                generation: 1,
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
                generation: 1,
                to_remote,
                task: None,
                remote_open: true,
                pending_remote,
                pending_remote_bytes: PRESSURE_TCP_REMOTE_PENDING_LIMIT,
                remote_closed: false,
                remote_aborted: false,
            },
        );
        let mut udp_flows = HashMap::new();
        let mut device = PacketDevice::new(1500);
        let (stack_tx, mut stack_rx) = mpsc::channel(1);
        let mut delayed_stack_events = VecDeque::new();
        stack_tx
            .try_send(StackEvent::RemoteData {
                handle,
                generation: 1,
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
        add_tcp_listener(&mut sockets, &mut listeners, endpoint);
        let handle = listeners.get(&endpoint).unwrap().handle;

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
                generation: 1,
                to_remote,
                task: None,
                remote_open: true,
                pending_remote,
                pending_remote_bytes: TCP_BUFFER_SIZE,
                remote_closed: false,
                remote_aborted: false,
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
    fn fake_ip_mapper_allocates_stable_ipv4_and_restores_domain_mapping() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            60,
            ConfigDnsQueryStrategy::UseIp,
        );

        let first = mapper.allocate_ipv4("Example.COM").unwrap();
        let second = mapper.allocate_ipv4("example.com").unwrap();
        let domain = mapper.domain_for_ipv4(first).unwrap();

        assert_eq!(first, Ipv4Addr::new(198, 18, 0, 3));
        assert_eq!(second, first);
        assert_eq!(domain.as_ref(), "example.com");
    }

    fn tun_udp_sniffed_target(original: &Target, domain: &str) -> crate::sniffing::SniffedTarget {
        let route_target = Target::new(
            RoutingTargetAddr::Domain(domain.to_owned()),
            original.port,
            RoutingNetwork::Udp,
        );
        crate::sniffing::SniffedTarget {
            route_target,
            dial_target: original.clone(),
            protocol: xray_config::SniffingDestination::Quic,
        }
    }

    #[test]
    fn mapped_fake_ip_keeps_tun_udp_target_a_over_sniffed_target_b() {
        let mapped = Target::new(
            RoutingTargetAddr::Domain("mapped-a.example".to_owned()),
            443,
            RoutingNetwork::Udp,
        );
        let result = TunUdpSniffedTarget::from_sniffed(
            &mapped,
            FakeIpTargetProvenance::Mapped,
            Some(tun_udp_sniffed_target(&mapped, "sniffed-b.example")),
        );

        assert_eq!(result.route_target, mapped);
        assert_eq!(result.dial_target, mapped);
        assert_eq!(result.sniffed_protocol, None);
    }

    #[test]
    fn mapped_fake_ip_suppresses_tun_tcp_content_sniffing() {
        let config = InboundSniffingConfig {
            enabled: true,
            dest_override: vec![xray_config::SniffingDestination::Http],
            metadata_only: false,
            route_only: false,
        };

        assert!(!should_sniff_tun_tcp(
            Some(&config),
            FakeIpTargetProvenance::Mapped,
        ));
        assert!(should_sniff_tun_tcp(
            Some(&config),
            FakeIpTargetProvenance::InPoolUnmapped,
        ));
    }

    #[test]
    fn in_pool_unmapped_route_only_uses_sniffed_domain_for_tun_udp_dialing() {
        let raw = Target::new(
            RoutingTargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(198, 18, 1, 7))),
            443,
            RoutingNetwork::Udp,
        );
        let result = TunUdpSniffedTarget::from_sniffed(
            &raw,
            FakeIpTargetProvenance::InPoolUnmapped,
            Some(tun_udp_sniffed_target(&raw, "sniffed.example")),
        );

        assert_eq!(result.dial_target, result.route_target);
        assert_eq!(
            result.route_target.addr,
            RoutingTargetAddr::Domain("sniffed.example".to_owned())
        );
    }

    #[test]
    fn fake_dns_response_answers_a_query_and_records_mapping() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            120,
            ConfigDnsQueryStrategy::UseIp,
        );
        let query = build_dns_a_query(0x1203, "www.example.com");

        let response = mapper.fake_dns_response(&query, false).unwrap();
        let fake_ip = mapper.domain_for_ipv4(Ipv4Addr::new(198, 18, 0, 3));

        assert_eq!(dns_response_id(&response), Some(0x1203));
        assert_eq!(
            dns_response_answer_ipv4(&response),
            Some(Ipv4Addr::new(198, 18, 0, 3))
        );
        assert_eq!(fake_ip.as_deref(), Some("www.example.com"));
    }

    #[test]
    fn fake_dns_response_use_ipv6_returns_nodata_without_mapping() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            120,
            ConfigDnsQueryStrategy::UseIpv6,
        );
        let query = build_dns_a_query(0x1207, "www.example.com");

        let response = mapper.fake_dns_response(&query, false).unwrap();

        assert_eq!(dns_response_id(&response), Some(0x1207));
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(mapper.mapping_count(), 0);
    }

    #[test]
    fn fake_dns_response_returns_nodata_for_https_query_without_recording_mapping() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            120,
            ConfigDnsQueryStrategy::UseIp,
        );
        let query = build_dns_query(0x1204, "www.example.com", 65, DNS_CLASS_IN);

        let response = mapper.fake_dns_response(&query, true).unwrap();

        assert_eq!(u16::from_be_bytes([response[2], response[3]]), 0x8180);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(mapper.mapping_count(), 0);
    }

    #[test]
    fn fake_dns_response_returns_nodata_for_aaaa_query() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            120,
            ConfigDnsQueryStrategy::UseIp,
        );
        let query = build_dns_query(0x1205, "www.example.com", DNS_TYPE_AAAA, DNS_CLASS_IN);

        let response = mapper.fake_dns_response(&query, false).unwrap();

        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
    }

    #[test]
    fn fake_dns_response_does_not_allocate_mapping_for_non_in_a_query() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            120,
            ConfigDnsQueryStrategy::UseIp,
        );
        let query = build_dns_query(0x1206, "www.example.com", DNS_TYPE_A, 3);

        let response = mapper.fake_dns_response(&query, false).unwrap();

        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0);
        assert_eq!(mapper.mapping_count(), 0);
    }

    #[test]
    fn fake_dns_response_leaves_unsupported_query_unhandled_without_local_anchor() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            120,
            ConfigDnsQueryStrategy::UseIp,
        );
        let query = build_dns_query(0x1207, "www.example.com", 65, DNS_CLASS_IN);

        let response = mapper.fake_dns_response(&query, false);

        assert!(response.is_none());
    }

    #[test]
    fn fake_dns_response_refuses_to_reassign_single_entry_pool_before_ttl() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 19, 0, 1),
            32,
            1,
            120,
            ConfigDnsQueryStrategy::UseIp,
        );
        let first_query = build_dns_a_query(0x1208, "first.example.com");
        let second_query = build_dns_a_query(0x1209, "second.example.com");
        mapper.fake_dns_response(&first_query, false).unwrap();

        let response = mapper.fake_dns_response(&second_query, false).unwrap();

        assert_eq!(u16::from_be_bytes([response[2], response[3]]) & 0x000f, 2);
        assert_eq!(dns_response_answer_ipv4(&response), None);
        assert_eq!(
            mapper
                .domain_for_ipv4(Ipv4Addr::new(198, 19, 0, 1))
                .as_deref(),
            Some("first.example.com")
        );
    }

    #[test]
    fn fake_dns_udp_packet_builds_tun_reply_packet() {
        let mut mapper = test_fake_ip_mapper(
            Ipv4Addr::new(198, 18, 0, 0),
            15,
            32_768,
            60,
            ConfigDnsQueryStrategy::UseIp,
        );
        let request = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 10, 0, 2),
            53_000,
            Ipv4Addr::new(1, 1, 1, 1),
            DNS_PORT,
            &build_dns_a_query(0x1203, "www.example.com"),
        )
        .unwrap();
        let parsed = parse_udp_packet(&request).unwrap();
        let response = mapper.fake_dns_response(&parsed.payload, false).unwrap();
        let reply = build_udp_packet(parsed.target, parsed.client, &response).unwrap();

        assert_eq!(
            ipv4_udp_payload_for_destination(&reply, 53_000)
                .as_deref()
                .and_then(dns_response_answer_ipv4),
            Some(Ipv4Addr::new(198, 18, 0, 3))
        );
    }

    #[test]
    fn ipv4_udp_parser_borrows_payload_from_packet_storage() {
        let packet = build_ipv4_udp_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            40_000,
            Ipv4Addr::new(203, 0, 113, 2),
            443,
            b"payload",
        )
        .unwrap();
        let payload_ptr = packet[28..].as_ptr();

        let parsed = parse_udp_packet(&packet).unwrap();

        assert_eq!(parsed.payload.as_ptr(), payload_ptr);
    }

    #[test]
    fn ipv6_udp_parser_borrows_payload_from_packet_storage() {
        let packet = build_ipv6_udp_packet(
            Ipv6Addr::LOCALHOST,
            40_000,
            "2001:db8::1".parse().unwrap(),
            443,
            b"payload",
        )
        .unwrap();
        let payload_ptr = packet[48..].as_ptr();

        let parsed = parse_udp_packet(&packet).unwrap();

        assert_eq!(parsed.payload.as_ptr(), payload_ptr);
    }

    #[test]
    fn incremental_checksum_matches_known_value_across_odd_slices() {
        let packet = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];

        let checksum =
            internet_checksum_slices([&packet[..1], &packet[1..4], &packet[4..7], &packet[7..]]);

        assert_eq!(checksum, 0x220d);
    }

    fn build_dns_a_query(id: u16, domain: &str) -> Vec<u8> {
        build_dns_query(id, domain, DNS_TYPE_A, DNS_CLASS_IN)
    }

    fn build_dns_query(id: u16, domain: &str, qtype: u16, qclass: u16) -> Vec<u8> {
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
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&qclass.to_be_bytes());
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
