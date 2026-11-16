//! Heap the TUN runtime keeps for each idle TCP flow.
//!
//! A counting allocator tracks the bytes live on the heap. The test opens a
//! number of TCP flows through the TUN to a loopback server, exchanges a few
//! bytes on each, lets them go idle, and divides the heap the runtime gained
//! by the number of flows. The client stack and the server sockets are set up
//! before the first sample, so what remains is the runtime's share: the
//! smoltcp socket, the bridge task and its buffers, and the outbound stream.
//!
//! The measurement is printed with `--nocapture`:
//!
//! ```text
//! cargo test --release -p xray-core-rs --test tun_flow_memory -- --nocapture
//! ```
//!
//! `TUN_MEMORY_PROFILE` selects `low-memory` (the default), `mobile` or
//! `desktop`, and `TUN_MEMORY_FLOWS` the number of flows. An ignored
//! companion measures one flow's bulk download through the same path, which
//! the read buffers are on:
//!
//! ```text
//! cargo test --release -p xray-core-rs --test tun_flow_memory -- --ignored --nocapture
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::time::{sleep, Duration, Instant as TokioInstant};
use xray_config::parse_xray_json;
use xray_core_rs::{Core, TunRuntimeOptions, TunRuntimeProfile};
use xray_tun::{TunEndpoint, TunError};

struct CountingAllocator;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every method forwards to `System` unchanged.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE_BYTES.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn live_bytes() -> isize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

struct ClientDevice {
    inbound: VecDeque<Bytes>,
    outbound: VecDeque<Bytes>,
}

impl Device for ClientDevice {
    type RxToken<'a>
        = ClientRx
    where
        Self: 'a;
    type TxToken<'a>
        = ClientTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((
            ClientRx(packet),
            ClientTx {
                outbound: &mut self.outbound,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(ClientTx {
            outbound: &mut self.outbound,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1500;
        capabilities
    }
}

struct ClientRx(Bytes);

impl RxToken for ClientRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct ClientTx<'a> {
    outbound: &'a mut VecDeque<Bytes>,
}

impl TxToken for ClientTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.outbound.push_back(Bytes::from(packet));
        result
    }
}

/// The app side of the TUN: one smoltcp stack holding every flow's socket.
struct Client {
    iface: Interface,
    device: ClientDevice,
    sockets: SocketSet<'static>,
    flows: Vec<SocketHandle>,
}

impl Client {
    fn new(flows: usize, buffer_size: usize) -> Self {
        let mut device = ClientDevice {
            inbound: VecDeque::new(),
            outbound: VecDeque::new(),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x6d65_6d6f_7279;
        let mut iface = Interface::new(config, &mut device, Instant::now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 10, 0, 2), 24))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(10, 10, 0, 1))
            .unwrap();
        let mut sockets = SocketSet::new(Vec::with_capacity(flows));
        let flows = (0..flows)
            .map(|_| {
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; buffer_size]),
                    tcp::SocketBuffer::new(vec![0; buffer_size]),
                );
                socket.set_congestion_control(tcp::CongestionControl::None);
                sockets.add(socket)
            })
            .collect();
        Self {
            iface,
            device,
            sockets,
            flows,
        }
    }

    fn poll(&mut self) {
        self.iface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);
    }

    async fn pump(&mut self, tun: &TunEndpoint) {
        self.poll();
        while let Some(packet) = self.device.outbound.pop_front() {
            // A full queue drops the packet, as an interface would.
            match tun.push_inbound(packet).await {
                Ok(()) | Err(TunError::QueueFull) => {}
                Err(error) => panic!("TUN push failed: {error}"),
            }
        }
        while let Some(packet) = tun.try_poll_outbound().await.unwrap() {
            self.device.inbound.push_back(packet);
        }
        self.poll();
    }

    fn socket(&mut self, index: usize) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(self.flows[index])
    }
}

/// Accepts every flow, answers its request with a short reply, and keeps the
/// connection open until the test ends.
async fn spawn_reply_server(release: Arc<Notify>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                let mut request = [0; 4];
                if stream.read_exact(&mut request).await.is_err() {
                    return;
                }
                let _ = stream.write_all(b"pong").await;
                release.notified().await;
            });
        }
    });
    addr
}

fn profile_from_env() -> (TunRuntimeProfile, &'static str) {
    match std::env::var("TUN_MEMORY_PROFILE").as_deref() {
        Ok("mobile") => (TunRuntimeProfile::Mobile, "mobile"),
        Ok("desktop") => (TunRuntimeProfile::Desktop, "desktop"),
        _ => (TunRuntimeProfile::LowMemory, "low-memory"),
    }
}

/// Upper bound the runtime's heap per idle TCP flow is held to. It measured
/// 146 KiB in a release build while every flow kept a 64 KiB download
/// buffer, and 80 KiB without it, 64 KiB of which are the smoltcp socket's
/// receive and send buffers.
const IDLE_TCP_FLOW_HEAP_LIMIT: isize = 96 * 1024;

#[test]
fn idle_tun_tcp_flow_heap() {
    let flows: usize = std::env::var("TUN_MEMORY_FLOWS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(64);
    let (profile, profile_name) = profile_from_env();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let per_flow = runtime.block_on(async move {
        let release = Arc::new(Notify::new());
        let server = spawn_reply_server(Arc::clone(&release)).await;
        let config = parse_xray_json(
            r#"{"inbounds":[{"protocol":"tun"}],"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        let mut core = Core::with_tun_runtime_options(
            config.config,
            TunRuntimeOptions {
                profile,
                ..Default::default()
            },
        )
        .unwrap();
        core.start().await.unwrap();
        let mut client = Client::new(flows, 4096);
        let SocketAddr::V4(target) = server else {
            unreachable!()
        };

        // One flow first, so lazily created runtime state (the flow tables,
        // the outbound's resolver, tokio's I/O driver slabs) is in place
        // before the baseline.
        let warmup = |client: &mut Client, index: usize| {
            let context = client.iface.context();
            let handle = client.flows[index];
            client
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .connect(context, (*target.ip(), target.port()), 40000 + index as u16)
                .unwrap();
        };
        warmup(&mut client, 0);
        exchange(&mut client, core.tun(), 0..1).await;
        settle(&mut client, core.tun()).await;

        let before = live_bytes();
        // In batches below every profile's limit on flows waiting for their
        // outbound.
        for start in (1..flows).step_by(16) {
            let batch = start..(start + 16).min(flows);
            for index in batch.clone() {
                warmup(&mut client, index);
            }
            exchange(&mut client, core.tun(), batch).await;
        }
        settle(&mut client, core.tun()).await;
        let after = live_bytes();
        let stats = core.tun().stats().await;
        assert_eq!(stats.active_tcp_flows, flows as u64, "{stats:?}");

        release.notify_waiters();
        core.stop().await.unwrap();
        (after - before) / (flows as isize - 1)
    });
    println!(
        "profile {profile_name}: {flows} idle TUN TCP flows, {:.1} KiB of heap per flow",
        per_flow as f64 / 1024.0
    );
    assert!(
        per_flow <= IDLE_TCP_FLOW_HEAP_LIMIT,
        "an idle TUN TCP flow holds {per_flow} bytes of heap"
    );
}

/// Sends each flow's request and waits for its reply.
async fn exchange(client: &mut Client, tun: &TunEndpoint, flows: std::ops::Range<usize>) {
    let deadline = TokioInstant::now() + Duration::from_secs(10);
    let mut sent = vec![false; flows.len()];
    let mut replied = vec![false; flows.len()];
    while replied.iter().any(|done| !done) {
        client.pump(tun).await;
        for (slot, index) in flows.clone().enumerate() {
            let socket = client.socket(index);
            if !sent[slot] && socket.may_send() {
                socket.send_slice(b"ping").unwrap();
                sent[slot] = true;
            }
            if socket.can_recv() {
                let mut reply = [0; 4];
                let read = socket.recv_slice(&mut reply).unwrap();
                assert_eq!(&reply[..read], &b"pong"[..read]);
                replied[slot] = true;
            }
        }
        assert!(
            TokioInstant::now() < deadline,
            "flows did not complete their exchange"
        );
        sleep(Duration::from_millis(1)).await;
    }
}

/// Lets the acknowledgements and the runtime's bookkeeping finish.
async fn settle(client: &mut Client, tun: &TunEndpoint) {
    for _ in 0..50 {
        client.pump(tun).await;
        sleep(Duration::from_millis(2)).await;
    }
}

/// Bulk download through one TUN TCP flow: the remote read path's throughput.
/// `TUN_BENCH_BYTES` sets the size (256 MiB by default).
#[test]
#[ignore = "throughput measurement, run explicitly"]
fn tun_tcp_download_throughput() {
    let bytes: usize = std::env::var("TUN_BENCH_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(256 * 1024 * 1024);
    let (profile, profile_name) = profile_from_env();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let elapsed = runtime.block_on(async move {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let SocketAddr::V4(target) = listener.local_addr().unwrap() else {
            unreachable!()
        };
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            let chunk = vec![0x5a; 64 * 1024];
            let mut left = bytes;
            while left > 0 {
                let take = left.min(chunk.len());
                stream.write_all(&chunk[..take]).await.unwrap();
                left -= take;
            }
            stream.shutdown().await.unwrap();
        });
        let config = parse_xray_json(
            r#"{"inbounds":[{"protocol":"tun"}],"outbounds":[{"protocol":"freedom"}]}"#,
        )
        .unwrap();
        let mut core = Core::with_tun_runtime_options(
            config.config,
            TunRuntimeOptions {
                profile,
                ..Default::default()
            },
        )
        .unwrap();
        core.start().await.unwrap();
        let mut client = Client::new(1, 256 * 1024);
        let context = client.iface.context();
        let handle = client.flows[0];
        client
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(context, (*target.ip(), target.port()), 40000)
            .unwrap();
        let started = TokioInstant::now();
        let mut sent = false;
        let mut received = 0;
        let mut scratch = vec![0; 256 * 1024];
        while received < bytes {
            client.pump(core.tun()).await;
            let socket = client.socket(0);
            if !sent && socket.may_send() {
                socket.send_slice(b"ping").unwrap();
                sent = true;
            }
            let mut progressed = false;
            while socket.can_recv() {
                let read = socket.recv_slice(&mut scratch).unwrap();
                received += read;
                progressed |= read > 0;
            }
            assert!(
                !sent || received == bytes || socket.may_recv(),
                "the flow closed after {received} of {bytes} bytes"
            );
            assert!(
                started.elapsed() < Duration::from_secs(120),
                "download stalled at {received} of {bytes} bytes"
            );
            if !progressed {
                tokio::task::yield_now().await;
            }
        }
        let elapsed = started.elapsed();
        core.stop().await.unwrap();
        elapsed
    });
    println!(
        "profile {profile_name}: {} MiB through one TUN TCP flow in {:.3} s, {:.1} MiB/s",
        bytes / (1024 * 1024),
        elapsed.as_secs_f64(),
        bytes as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    );
}
