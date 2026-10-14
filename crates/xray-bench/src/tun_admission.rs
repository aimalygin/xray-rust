//! New TCP flow first-byte latency with disabled versus no-op host admission.
//! In-process TUN packet API plus a real local TCP target; no host route changes.
use crate::*;
use xray_core_rs::TunAdmissionPolicy;

fn invalid(message: impl ToString) -> BenchError {
    BenchError::InvalidArguments(message.to_string())
}

async fn pump(
    client: &mut TunTcpBenchmarkClient,
    tun: &xray_tun::TunEndpoint,
) -> Result<(), BenchError> {
    client.poll();
    while let Some(packet) = client.device.pop_outbound() {
        tun.push_inbound(packet).await.map_err(invalid)?;
    }
    while let Some(packet) = tun.try_poll_outbound().await.map_err(invalid)? {
        if client.accepts_packet(&packet) {
            client.device.push_inbound(packet);
        }
    }
    client.poll();
    tokio::task::yield_now().await;
    Ok(())
}

async fn sample(core: &Core, target: SocketAddr, port: u16) -> Result<u128, BenchError> {
    let mut client = TunTcpBenchmarkClient::new(port);
    let start = Instant::now();
    client.connect(target)?;
    timeout(Duration::from_secs(2), async {
        while !client.may_send() {
            pump(&mut client, core.tun()).await?;
        }
        client.send_payload(b"A")?;
        loop {
            pump(&mut client, core.tun()).await?;
            let reply = client.recv_available();
            if !reply.is_empty() {
                if reply != b"A" {
                    return Err(invalid("admission benchmark payload mismatch"));
                }
                break;
            }
        }
        let elapsed = start.elapsed().as_nanos();
        client.abort();
        pump(&mut client, core.tun()).await?;
        while !core.connection_snapshot().connections.is_empty() {
            pump(&mut client, core.tun()).await?;
        }
        Ok(elapsed)
    })
    .await
    .map_err(|_| invalid("admission benchmark flow timed out"))?
}

pub async fn run() -> Result<(), BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(invalid)?;
    let target = listener.local_addr().map_err(invalid)?;
    let server = tokio::spawn(async move {
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break; };
                    clients.spawn(async move {
                        let mut byte = [0; 1];
                        if stream.read_exact(&mut byte).await.is_ok() {
                            let _ = stream.write_all(&byte).await;
                        }
                    });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });
    // Always abort the fixture, including on a timed out measured flow.
    struct Abort(tokio::task::AbortHandle);
    impl Drop for Abort {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server_guard = Abort(server.abort_handle());
    let mut runs = Vec::new();
    for repeat in 0..5 {
        for enabled in if repeat % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        } {
            let config = parse_xray_json(
                r#"{"inbounds":[{"protocol":"tun"}],"outbounds":[{"protocol":"freedom"}]}"#,
            )
            .map_err(invalid)?;
            let mut core = Core::new(config.config).map_err(invalid)?;
            let calls = Arc::new(AtomicUsize::new(0));
            if enabled {
                let calls = Arc::clone(&calls);
                core.set_tun_admission(Some(
                    TunAdmissionPolicy::new(
                        Arc::new(move |_| {
                            calls.fetch_add(1, Ordering::Relaxed);
                            true
                        }),
                        Duration::from_millis(100),
                        false,
                    )
                    .map_err(invalid)?,
                ))
                .map_err(invalid)?;
            }
            core.start().await.map_err(invalid)?;
            let mut samples = Vec::new();
            for index in 0..1050 {
                let elapsed = sample(&core, target, 40000 + index).await?;
                if index >= 50 {
                    samples.push(elapsed);
                }
            }
            core.stop().await.map_err(invalid)?;
            if calls.load(Ordering::Relaxed) != if enabled { 1050 } else { 0 } {
                return Err(invalid("host callback count did not match new-flow count"));
            }
            samples.sort_unstable();
            runs.push(serde_json::json!({"repeat": repeat + 1, "enabled": enabled,
                "samples": samples.len(), "warmup": 50, "callback_calls": calls.load(Ordering::Relaxed),
                "p50_us": samples[499] as f64 / 1000.0, "p95_us": samples[949] as f64 / 1000.0,
                "p99_us": samples[989] as f64 / 1000.0}));
        }
    }
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({"schema_version": 1,
        "scope": "host in-process TUN + loopback freedom TCP first-byte latency; no Android UID lookup", "runs": runs})).map_err(invalid)?);
    Ok(())
}
