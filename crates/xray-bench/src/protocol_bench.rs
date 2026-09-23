//! Process benchmarks using an explicit synthetic outbound configuration.
//! The frozen engine is external; this module changes only the traffic driver.
use super::*;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    binary: PathBuf,
    config: Value,
    path: String,
    traffic: String,
    connections: usize,
    #[serde(default)]
    idle_connections: usize,
    iterations: usize,
    payload_size: usize,
    output: PathBuf,
    #[serde(default)]
    prepare_client: bool,
    #[serde(default)]
    warmup: bool,
    #[serde(default)]
    client_env: std::collections::BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedClient {
    binary: PathBuf,
    args: Vec<String>,
}

// Unlike a bare fixture handle, every measured process must be reaped on all
// exit paths, including startup errors and cancelled/failed workloads.
struct MeasuredProcess {
    child: Child,
}

impl Drop for MeasuredProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn invalid(message: impl Into<String>) -> BenchError {
    BenchError::InvalidArguments(message.into())
}

fn io_error(source: io::Error) -> BenchError {
    BenchError::Io {
        action: "protocol benchmark I/O".into(),
        source,
    }
}

fn validate(r: &Request) -> Result<(), BenchError> {
    if !matches!(r.path.as_str(), "socks" | "tun")
        || !matches!(
            r.traffic.as_str(),
            "upload" | "download" | "full-duplex" | "tcp-latency" | "udp"
        )
        || !(1..=16).contains(&r.connections)
        || r.idle_connections > 16 - r.connections.min(16)
        || (r.idle_connections != 0 && (r.path != "socks" || r.traffic == "udp"))
        || !(1..=16384).contains(&r.iterations)
        || !(1..=65536).contains(&r.payload_size)
        || (r.traffic == "udp" && r.payload_size > 1372)
        || r.config.as_object().is_none()
        || (r.path == "tun" && (r.prepare_client || r.warmup))
    {
        return Err(invalid("invalid bounded protocol benchmark request"));
    }
    Ok(())
}

/// Keep the synthetic link from being limited by Darwin's 4 KiB default queue.
/// This changes only the new driver; historical benchmark socketpairs stay intact.
fn configure_link_buffers(pair: &TunSocketPair) -> Result<Value, BenchError> {
    let mut buffers = Vec::new();
    for fd in [pair.engine_fd.raw(), pair.workload_fd.raw()] {
        let mut sizes = Vec::new();
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            let requested: libc::c_int = 1024 * 1024;
            let mut actual: libc::c_int = 0;
            let mut len = std::mem::size_of_val(&actual) as libc::socklen_t;
            // Both descriptors are live, and each pointer covers an initialized c_int.
            let set = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::from_ref(&requested).cast(),
                    len,
                )
            };
            if set != 0 {
                return Err(io_error(io::Error::last_os_error()));
            }
            let get = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    option,
                    std::ptr::from_mut(&mut actual).cast(),
                    &mut len,
                )
            };
            if get != 0 {
                return Err(io_error(io::Error::last_os_error()));
            }
            sizes.push(actual);
        }
        buffers.push(json!({"send_bytes":sizes[0], "receive_bytes":sizes[1]}));
    }
    Ok(json!(buffers))
}

/// Run one fresh child, retain validated payload counts and raw resource samples.
pub async fn run(args: Vec<String>) -> Result<(), BenchError> {
    if args.len() != 1 {
        return Err(invalid("usage: xray-bench protocol-run REQUEST.json"));
    }
    let bytes = fs::read(&args[0]).map_err(io_error)?;
    if bytes.len() > 262144 {
        return Err(invalid("benchmark request exceeds 256 KiB"));
    }
    let r: Request = serde_json::from_slice(&bytes).map_err(|e| invalid(e.to_string()))?;
    validate(&r)?;
    fs::create_dir(&r.output).map_err(io_error)?;
    let port = allocate_loopback_port()?;
    let socks = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let mut config = r.config.clone();
    config["inbounds"] = if r.path == "tun" {
        json!([{"protocol":"tun"}])
    } else {
        json!([{"protocol":"socks","listen":"127.0.0.1","port":port,"settings":{"auth":"noauth","udp":true}}])
    };
    let config_path = r.output.join("config.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&config).map_err(|e| invalid(e.to_string()))?,
    )
    .map_err(io_error)?;
    let pair = if r.path == "tun" {
        Some(create_tun_socket_pair()?)
    } else {
        None
    };
    let link_buffers = pair.as_ref().map(configure_link_buffers).transpose()?;
    let stdout = r.output.join("stdout.log");
    let stderr = r.output.join("stderr.log");
    // Translate reference configs before spawning the measured process. exec()
    // preserves a launcher's CPU usage, which would bias lifetime CPU comparisons.
    let prepared = if r.prepare_client {
        let output = Command::new(&r.binary)
            .args(["prepare", "-config"])
            .arg(&config_path)
            .output()
            .map_err(io_error)?;
        if !output.status.success() || output.stdout.len() > 262144 {
            return Err(invalid("reference configuration preparation failed"));
        }
        serde_json::from_slice::<PreparedClient>(&output.stdout)
            .map_err(|e| invalid(e.to_string()))?
    } else {
        PreparedClient {
            binary: r.binary.clone(),
            args: vec![
                "run".into(),
                "-config".into(),
                config_path.to_string_lossy().into_owned(),
            ],
        }
    };
    let engine_sha256 = file_sha256(&prepared.binary);
    let mut command = Command::new(&prepared.binary);
    command
        .args(&prepared.args)
        .envs(&r.client_env)
        .stdout(fs::File::create(&stdout).map_err(io_error)?)
        .stderr(fs::File::create(&stderr).map_err(io_error)?);
    if let Some(pair) = &pair {
        configure_tun_fd_env(&mut command, pair);
    }
    let client_started = Instant::now();
    let mut child = MeasuredProcess {
        child: command.spawn().map_err(io_error)?,
    };
    let fd = pair.and_then(into_tun_workload_fd);
    if fd.is_some() {
        wait_for_process_started(&mut child.child, &stdout, &stderr).await?;
    } else {
        wait_for_tcp_listener(&mut child.child, socks, &stdout, &stderr).await?;
    }
    if r.warmup {
        tokio::time::timeout(Duration::from_secs(15), warmup_client(socks))
            .await
            .map_err(|_| invalid("client warmup exceeded 15 seconds"))??;
    }
    let _idle_connections = if r.idle_connections != 0 {
        let idle = tokio::time::timeout(
            Duration::from_secs(30),
            IdleConnections::open(socks, r.idle_connections),
        )
        .await
        .map_err(|_| invalid("idle connection setup exceeded 30 seconds"))??;
        // Keep the verified connections open but inactive before starting bulk
        // traffic. Their resident buffers remain part of the measured client.
        sleep(Duration::from_secs(2)).await;
        Some(idle)
    } else {
        None
    };
    let client_startup_seconds = client_started.elapsed().as_secs_f64();
    let startup_sample = sample_process(child.child.id(), client_started, BenchmarkPhase::Startup)?;
    let options = BenchOptions {
        connections: r.connections,
        iterations: r.iterations,
        payload_size: r.payload_size,
        settle: Duration::from_millis(500),
        ..BenchOptions::default()
    };
    let phase = BenchmarkPhaseTracker::default();
    let measured = async {
        sleep(Duration::from_millis(500)).await;
        phase.set(BenchmarkPhase::Traffic);
        let started = Instant::now();
        let outcome = match (fd.as_ref(), r.traffic.as_str()) {
            (Some(fd), "udp") => run_tun_udp(fd.raw(), &options).await?,
            (Some(fd), "tcp-latency") => run_tun_tcp_freedom_workload(fd.raw(), &options).await?,
            (None, "udp") => {
                run_udp_freedom_workload_on(socks, &options, local_non_loopback_ipv4()?).await?
            }
            (None, "tcp-latency") => {
                run_tcp_freedom_workload_on(socks, &options, local_non_loopback_ipv4()?).await?
            }
            (Some(fd), traffic) => {
                run_tun_bulk(fd.raw(), &options, StreamBenchTraffic::parse(traffic)?).await?
            }
            (None, traffic) => {
                stream_transport::run_workload_on(
                    socks,
                    &options,
                    StreamBenchScenario {
                        transport: StreamBenchTransport::WebSocket,
                        traffic: StreamBenchTraffic::parse(traffic)?,
                        xhttp_mode: None,
                        xhttp_profile: None,
                    },
                    phase.clone(),
                    local_non_loopback_ipv4()?,
                )
                .await?
            }
        };
        let elapsed = started.elapsed();
        phase.set(BenchmarkPhase::Settle);
        sleep(Duration::from_millis(500)).await;
        Ok((outcome, elapsed))
    };
    let result = sample_while_phased(
        child.child.id(),
        Duration::from_millis(100),
        phase.clone(),
        async {
            tokio::time::timeout(Duration::from_secs(120), measured)
                .await
                .map_err(|_| invalid("protocol benchmark exceeded 120 seconds"))?
        },
    )
    .await;
    let report = match result {
        Ok(((outcome, elapsed), samples)) => {
            let seconds = outcome
                .transfer_window
                .map(|(a, b)| (b - a).as_secs_f64())
                .unwrap_or(elapsed.as_secs_f64());
            let summary = summarize_samples(&samples);
            let cpu_ms = samples
                .last()
                .unwrap()
                .cpu_millis
                .saturating_sub(samples.first().unwrap().cpu_millis);
            json!({"status":"pass", "path":r.path,"traffic":r.traffic,
                "connections":r.connections,"iterations":r.iterations,"payload_size":r.payload_size,
                "idle_connections":r.idle_connections,
                "concurrent_flows":if r.path=="tun" && r.traffic=="tcp-latency" {1}else{r.connections},
                "bytes_sent":outcome.bytes_sent,"bytes_received":outcome.bytes_received,
                "transfer_seconds":seconds,"wall_seconds":elapsed.as_secs_f64(),
                "throughput_mib_s":(outcome.bytes_sent+outcome.bytes_received) as f64/1048576.0/seconds,
                "peak_rss_kib":summary.peak_rss_kib,"cpu_millis":cpu_ms,
                "warmup":r.warmup,"prepare_client":r.prepare_client,
                "client_startup_seconds":client_startup_seconds,
                "client_startup_cpu_millis":startup_sample.cpu_millis,
                "client_cpu_total_millis":samples.last().unwrap().cpu_millis,
                "engine_binary":prepared.binary,"engine_sha256":engine_sha256,
                "client_env":r.client_env,
                "tun_fd_buffers":link_buffers,
                "latency_us":if matches!(r.traffic.as_str(), "udp" | "tcp-latency") {summarize_latency_us(outcome.latencies_us.clone())} else {None},
                "ready_latency_us":if r.path=="tun" && !matches!(r.traffic.as_str(), "udp" | "tcp-latency") {summarize_latency_us(outcome.latencies_us)} else {None},
                "setup":summarize_flow_setup_us(outcome.setup_samples),"samples":samples})
        }
        Err(error) => {
            fs::write(
                r.output.join("result.json"),
                json!({"status":"fail","error":error.to_string()}).to_string(),
            )
            .map_err(io_error)?;
            return Err(error);
        }
    };
    fs::write(
        r.output.join("result.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| invalid(e.to_string()))?,
    )
    .map_err(io_error)?;
    println!("{}", report);
    Ok(())
}

struct IdleConnections {
    _clients: Vec<TcpStream>,
    _server: tokio::task::JoinSet<io::Result<()>>,
}

impl IdleConnections {
    async fn open(socks: SocketAddr, count: usize) -> Result<Self, BenchError> {
        let listener = TcpListener::bind((local_non_loopback_ipv4()?, 0))
            .await
            .map_err(io_error)?;
        let target = listener.local_addr().map_err(io_error)?;
        let mut server = tokio::task::JoinSet::new();
        server.spawn(async move {
            let mut echoes = tokio::task::JoinSet::new();
            for _ in 0..count {
                let (mut stream, _) = listener.accept().await?;
                echoes.spawn(async move {
                    let (mut read, mut write) = stream.split();
                    tokio::io::copy(&mut read, &mut write).await
                });
            }
            while let Some(result) = echoes.join_next().await {
                result.map_err(io::Error::other)??;
            }
            Ok(())
        });
        let mut clients = Vec::with_capacity(count);
        for _ in 0..count {
            let mut client = TcpStream::connect(socks).await.map_err(io_error)?;
            socks5_connect(&mut client, target).await?;
            let payload = [0x6a; 1024];
            let mut echo = [0; 1024];
            client.write_all(&payload).await.map_err(io_error)?;
            client.read_exact(&mut echo).await.map_err(io_error)?;
            if echo != payload {
                return Err(invalid("idle connection echo mismatch"));
            }
            clients.push(client);
        }
        Ok(Self {
            _clients: clients,
            _server: server,
        })
    }
}

async fn warmup_client(socks: SocketAddr) -> Result<(), BenchError> {
    let listener = TcpListener::bind((local_non_loopback_ipv4()?, 0))
        .await
        .map_err(io_error)?;
    let target = listener.local_addr().map_err(io_error)?;
    // JoinSet aborts the one-shot server even when warmup is cancelled.
    let mut server = tokio::task::JoinSet::new();
    server.spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let (mut read, mut write) = stream.split();
        tokio::io::copy(&mut read, &mut write).await
    });
    let mut client = TcpStream::connect(socks).await.map_err(io_error)?;
    socks5_connect(&mut client, target).await?;
    let payload = [0x5a; 1024];
    let mut echo = [0; 1024];
    client.write_all(&payload).await.map_err(io_error)?;
    client.read_exact(&mut echo).await.map_err(io_error)?;
    if echo != payload {
        return Err(invalid("warmup echo mismatch"));
    }
    // Wait for both directions to close, so warmup cannot consume one of the
    // client's TCP slots when the measured workload opens its connections.
    client.shutdown().await.map_err(io_error)?;
    if client.read(&mut echo[..1]).await.map_err(io_error)? != 0 {
        return Err(invalid("unexpected bytes after warmup echo"));
    }
    server
        .join_next()
        .await
        .expect("warmup server exists")
        .map_err(|_| invalid("warmup server task failed"))?
        .map_err(io_error)?;
    Ok(())
}

struct Flow {
    client: TunTcpBenchmarkClient,
    ready: bool,
    sent: usize,
    received: usize,
    complete: bool,
}

async fn run_tun_udp(fd: RawFd, options: &BenchOptions) -> Result<WorkloadOutcome, BenchError> {
    let ip = local_non_loopback_ipv4()?;
    let origin = UdpSocket::bind((ip, 0)).await.map_err(io_error)?;
    let port = origin.local_addr().map_err(io_error)?.port();
    let echo = tokio::spawn(async move {
        let mut buffer = [0; 65536];
        while let Ok((n, peer)) = origin.recv_from(&mut buffer).await {
            if origin.send_to(&buffer[..n], peer).await.is_err() {
                break;
            }
        }
    });
    struct Abort(tokio::task::AbortHandle);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _guard = Abort(echo.abort_handle());
    let source = Ipv4Addr::new(10, 10, 0, 2);
    let mut counts = vec![0; options.connections];
    let mut pending = vec![None; options.connections];
    let mut buffer = vec![0; 65536];
    let mut outcome = WorkloadOutcome::default();
    let start = Instant::now();
    while counts.iter().any(|n| *n < options.iterations) {
        for i in 0..counts.len() {
            if counts[i] == options.iterations || pending[i].is_some() {
                continue;
            }
            let mut payload = vec![0x5a; options.payload_size];
            if payload.len() >= 8 {
                payload[..4].copy_from_slice(&(i as u32).to_be_bytes());
                payload[4..8].copy_from_slice(&(counts[i] as u32).to_be_bytes());
            }
            let packet = ipv4_udp_packet(source, 40000 + i as u16, ip, port, &payload)?;
            match write_tun_frame(fd, &encode_darwin_utun_frame(&packet)) {
                Ok(()) => {
                    pending[i] = Some(Instant::now());
                    outcome.bytes_sent += payload.len() as u64;
                }
                Err(BenchError::Io { source, .. })
                    if source.kind() == io::ErrorKind::WouldBlock
                        || source.raw_os_error() == Some(libc::ENOBUFS) =>
                {
                    break
                }
                Err(e) => return Err(e),
            }
        }
        while let Some(n) = read_tun_frame(fd, &mut buffer)? {
            let packet = decode_darwin_utun_frame(&buffer[..n])?;
            let Some(datagram) = parse_ipv4_udp_datagram(packet) else {
                continue;
            };
            if datagram.source != ip
                || datagram.source_port != port
                || datagram.destination != source
            {
                continue;
            }
            let Some(i) = datagram
                .destination_port
                .checked_sub(40000)
                .map(usize::from)
                .filter(|i| *i < counts.len())
            else {
                continue;
            };
            let Some(sent) = pending[i].take() else {
                return Err(invalid("duplicate TUN UDP reply"));
            };
            let mut expected = vec![0x5a; options.payload_size];
            if expected.len() >= 8 {
                expected[..4].copy_from_slice(&(i as u32).to_be_bytes());
                expected[4..8].copy_from_slice(&(counts[i] as u32).to_be_bytes());
            }
            if datagram.payload != expected {
                return Err(invalid("TUN UDP payload/sequence mismatch"));
            }
            outcome.latencies_us.push(sent.elapsed().as_micros());
            outcome.bytes_received += expected.len() as u64;
            counts[i] += 1;
        }
        if pending
            .iter()
            .flatten()
            .any(|t| t.elapsed() > Duration::from_secs(5))
        {
            return Err(invalid("TUN UDP response exceeded five seconds"));
        }
        tokio::task::yield_now().await;
    }
    outcome.transfer_window = Some((start, Instant::now()));
    Ok(outcome)
}

/// Concurrent inner TCP flows over the same fd-backed production TUN path.
/// Uses the existing validated stream fixture, including its completion marker.
async fn run_tun_bulk(
    fd: RawFd,
    options: &BenchOptions,
    traffic: StreamBenchTraffic,
) -> Result<WorkloadOutcome, BenchError> {
    let listener = TcpListener::bind((local_non_loopback_ipv4()?, 0))
        .await
        .map_err(io_error)?;
    let target = listener.local_addr().map_err(io_error)?;
    let template = Arc::new(bulk_pattern_template(options.payload_size));
    let server_template = Arc::clone(&template);
    let iterations = options.iterations;
    let count = options.connections;
    let server = tokio::spawn(async move {
        stream_transport::run_target_server(listener, traffic, server_template, iterations, count)
            .await
    });
    // Abort the local fixture on error/timeout; its JoinSet cancels child flows.
    struct Abort(tokio::task::AbortHandle);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _guard = Abort(server.abort_handle());
    let total = options.payload_size * options.iterations;
    let upload = traffic != StreamBenchTraffic::Download;
    let download = traffic != StreamBenchTraffic::Upload;
    let mut flows = Vec::new();
    for i in 0..count {
        let mut client = TunTcpBenchmarkClient::new(49152 + i as u16);
        client.connect(target)?;
        flows.push(Flow {
            client,
            ready: false,
            sent: 0,
            received: 0,
            complete: false,
        });
    }
    let mut pending = VecDeque::new();
    let mut buffer = vec![0; 65536];
    let opening = Instant::now();
    let mut transfer_start = None;
    let mut setups = Vec::new();
    loop {
        while let Some(n) = read_tun_frame(fd, &mut buffer)? {
            let packet = decode_darwin_utun_frame(&buffer[..n])?;
            if let Some(flow) = flows.iter_mut().find(|f| f.client.accepts_packet(packet)) {
                flow.client
                    .device
                    .push_inbound(Bytes::copy_from_slice(packet));
            }
        }
        for flow in &mut flows {
            flow.client.poll();
            let received = flow.client.recv_available();
            for byte in received {
                if !flow.ready {
                    if byte != 0x52 {
                        return Err(invalid("TUN ready marker mismatch"));
                    }
                    flow.ready = true;
                    transfer_start.get_or_insert_with(Instant::now);
                    setups.push(opening.elapsed().as_micros());
                } else if download && flow.received < total {
                    if byte != template[flow.received % template.len()] {
                        return Err(invalid("TUN download payload mismatch"));
                    }
                    flow.received += 1;
                } else if upload && !flow.complete {
                    if byte != 0x43 {
                        return Err(invalid("TUN completion marker mismatch"));
                    }
                    flow.complete = true;
                } else {
                    return Err(invalid("unexpected extra TUN response bytes"));
                }
            }
            if flow.ready && upload && flow.sent < total {
                let socket = flow
                    .client
                    .sockets
                    .get_mut::<smol_tcp::Socket>(flow.client.tcp);
                if socket.can_send() {
                    let offset = flow.sent % template.len();
                    let end = template.len().min(offset + total - flow.sent);
                    let n = socket
                        .send_slice(&template[offset..end])
                        .map_err(|e| invalid(e.to_string()))?;
                    flow.sent += n;
                }
            }
            flow.client.poll();
            while let Some(packet) = flow.client.device.pop_outbound() {
                if pending.len() == 2048 {
                    return Err(invalid("TUN driver packet queue budget exceeded"));
                }
                pending.push_back(encode_darwin_utun_frame(&packet));
            }
        }
        while let Some(packet) = pending.front() {
            match write_tun_frame(fd, packet) {
                Ok(()) => {
                    pending.pop_front();
                }
                Err(BenchError::Io { source, .. })
                    if source.kind() == io::ErrorKind::WouldBlock
                        || source.raw_os_error() == Some(libc::ENOBUFS) =>
                {
                    break
                }
                Err(e) => return Err(e),
            }
        }
        if flows.iter().all(|f| {
            f.ready
                && (!upload || f.sent == total && f.complete)
                && (!download || f.received == total)
        }) {
            break;
        }
        tokio::task::yield_now().await;
    }
    let end = Instant::now();
    server.await.map_err(|e| invalid(e.to_string()))??;
    for flow in &mut flows {
        flow.client.abort();
        flow.client.poll();
        while let Some(packet) = flow.client.device.pop_outbound() {
            pending.push_back(encode_darwin_utun_frame(&packet));
        }
    }
    let closing_deadline = Instant::now() + Duration::from_secs(2);
    while let Some(packet) = pending.front() {
        match write_tun_frame(fd, packet) {
            Ok(()) => {
                pending.pop_front();
            }
            Err(BenchError::Io { source, .. })
                if source.kind() == io::ErrorKind::WouldBlock
                    || source.raw_os_error() == Some(libc::ENOBUFS) =>
            {
                while read_tun_frame(fd, &mut buffer)?.is_some() {}
                if Instant::now() >= closing_deadline {
                    return Err(invalid("TUN driver close timed out"));
                }
                tokio::task::yield_now().await;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(WorkloadOutcome {
        bytes_sent: if upload { (total * count) as u64 } else { 0 },
        bytes_received: if download { (total * count) as u64 } else { 0 },
        transfer_window: Some((transfer_start.unwrap(), end)),
        latencies_us: setups,
        ..WorkloadOutcome::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn measured_process_is_terminated_and_reaped_on_error() {
        let pid = std::cell::Cell::new(0);
        let run = || -> Result<(), BenchError> {
            let process = MeasuredProcess {
                child: Command::new("/bin/sleep").arg("30").spawn().unwrap(),
            };
            pid.set(process.child.id() as libc::pid_t);
            Err(invalid("simulated workload failure"))
        };
        assert!(run().is_err());
        // The guard waited for the killed child, so even a zombie cannot remain.
        assert_eq!(unsafe { libc::kill(pid.get(), 0) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn rejects_unbounded_and_unknown_requests() {
        let mut r = Request {
            binary: PathBuf::new(),
            config: json!({}),
            path: "tun".into(),
            traffic: "udp".into(),
            connections: 8,
            idle_connections: 0,
            iterations: 100,
            payload_size: 1200,
            output: PathBuf::new(),
            prepare_client: false,
            warmup: false,
            client_env: Default::default(),
        };
        assert!(validate(&r).is_ok());
        r.warmup = true;
        assert!(validate(&r).is_err());
        r.warmup = false;
        r.prepare_client = true;
        assert!(validate(&r).is_err());
        r.path = "socks".into();
        assert!(validate(&r).is_ok());
        r.prepare_client = false;
        r.payload_size = 1500;
        assert!(validate(&r).is_err());
        r.payload_size = 1200;
        r.connections = 17;
        assert!(validate(&r).is_err());
        r.connections = 8;
        r.traffic = "download".into();
        r.idle_connections = 8;
        assert!(validate(&r).is_ok());
        r.idle_connections = 9;
        assert!(validate(&r).is_err());
        r.idle_connections = usize::MAX;
        assert!(validate(&r).is_err());
        r.idle_connections = 8;
        r.path = "tun".into();
        assert!(validate(&r).is_err());
        r.path = "unknown".into();
        assert!(validate(&r).is_err());
    }

    #[test]
    fn old_requests_keep_cold_direct_launch_defaults() {
        let r: Request = serde_json::from_value(json!({
            "binary":"engine", "config":{}, "path":"socks", "traffic":"upload",
            "connections":1, "iterations":1, "payload_size":1024, "output":"result"
        }))
        .unwrap();
        assert!(!r.warmup);
        assert!(!r.prepare_client);
        assert_eq!(r.idle_connections, 0);
        assert!(r.client_env.is_empty());
        assert!(validate(&r).is_ok());
    }
}
