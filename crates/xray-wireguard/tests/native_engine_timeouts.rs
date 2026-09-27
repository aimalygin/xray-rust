#[path = "support/fault_relay.rs"]
mod fault_relay;
#[path = "support/raw_client.rs"]
mod raw_client;
mod support;
use fault_relay::{Fault, Relay};
use raw_client::RawClient;
use serde_json::json;
use std::time::Duration;
use tokio::{
    net::UdpSocket,
    task::JoinSet,
    time::{timeout, Instant},
};
use x25519_dalek::{PublicKey, StaticSecret};

const WAIT: Duration = Duration::from_secs(5);

#[tokio::test]
#[ignore = "requires pristine/patched GotaTun and official wireguard-go; use check-wireguard-timeouts.py"]
async fn three_engines_single_request_loss_and_recovery() {
    let repeats: usize = std::env::var("WIREGUARD_ENGINE_REPEATS")
        .unwrap_or_else(|_| "1".into())
        .parse()
        .unwrap();
    assert!((1..=100).contains(&repeats));
    for iteration in 0..repeats {
        for engine in ["gotatun-pristine", "gotatun-patched", "wireguard-go"] {
            for (case, fault) in [
                ("clean", Fault::None),
                ("lost-initiation", Fault::FirstInitiation),
                ("lost-response", Fault::FirstResponse),
                ("lost-upload", Fault::NextClientData),
                ("lost-download", Fault::NextServerData),
            ] {
                let _server = support::Reference::start(
                    &StaticSecret::from([0x53; 32]),
                    &PublicKey::from(&StaticSecret::from([0x42; 32])),
                )
                .await;
                let relay = Relay::start(_server.address).await;
                let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = echo.local_addr().unwrap().port();
                let mut tasks = JoinSet::new();
                tasks.spawn(async move {
                    let mut buf = [0; 2048];
                    loop {
                        let (n, source) = echo.recv_from(&mut buf).await.unwrap();
                        assert_eq!(echo.send_to(&buf[..n], source).await.unwrap(), n);
                    }
                });
                let client = RawClient::start(engine, relay.address).await;
                let data_loss = matches!(fault, Fault::NextClientData | Fault::NextServerData);
                if data_loss {
                    client.send(false, port, b"warmup").await;
                    assert_eq!(
                        timeout(WAIT, client.receive(false, port)).await.unwrap(),
                        b"warmup"
                    );
                }
                relay.arm(fault);
                let start = Instant::now();
                client
                    .send(true, port, b"single numbered IPv6 request 1")
                    .await;
                let early = timeout(WAIT, client.receive(true, port)).await;
                if fault == Fault::None {
                    assert!(
                        early.is_ok(),
                        "clean single request exceeded the original deadline"
                    );
                }
                relay.mark(json!({"engine": engine, "case": case, "originalFiveSecondDeadlinePassed": early.is_ok(),
                    "requestElapsedUs": start.elapsed().as_micros(), "applicationSends": 1}));
                if data_loss {
                    assert!(
                        early.is_err(),
                        "the injected lost datagram must not be delivered"
                    );
                } else {
                    let reply = match early {
                        Ok(reply) => reply,
                        Err(_) => timeout(Duration::from_secs(8), client.receive(true, port))
                            .await
                            .expect(
                                "single pending datagram must recover without application retry",
                            ),
                    };
                    assert_eq!(reply, b"single numbered IPv6 request 1");
                    relay.mark(json!({"eventualRecoveryUs": start.elapsed().as_micros()}));
                }
                // A distinct packet verifies that neither family stalls after
                // losing data; this is not a retry of the failed request.
                for ipv6 in [false, true] {
                    client.send(ipv6, port, b"next independent request 2").await;
                    assert_eq!(
                        timeout(WAIT, client.receive(ipv6, port)).await.unwrap(),
                        b"next independent request 2"
                    );
                }
                relay.mark(json!({"bothFamiliesNextRequestPassed": true}));
                assert_eq!(relay.snapshot()["remainingFault"], "None");
                relay.save(&format!("engine-{engine}-{case}-{iteration:03}"));
            }
        }
    }
}
