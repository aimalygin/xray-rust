//! Test-only, bounded metadata trace. No keys, plaintext or ciphertext is saved.
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::{net::UdpSocket, task::JoinHandle};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    None,
    FirstInitiation,
    FirstResponse,
    NextClientData,
    NextServerData,
}

pub struct Relay {
    pub address: SocketAddr,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}
struct State {
    start: Instant,
    fault: Fault,
    trace: VecDeque<Value>,
    omitted: usize,
}
impl State {
    fn record(&mut self, mut event: Value) {
        event["elapsedUs"] = json!(self.start.elapsed().as_micros());
        if self.trace.len() == 512 {
            self.trace.pop_front();
            self.omitted += 1;
        }
        self.trace.push_back(event);
    }
}
impl Relay {
    pub async fn start(server: SocketAddr) -> Self {
        assert!(server.ip().is_loopback());
        let front = UdpSocket::bind((server.ip(), 0)).await.unwrap();
        let address = front.local_addr().unwrap();
        let back = UdpSocket::bind((server.ip(), 0)).await.unwrap();
        back.connect(server).await.unwrap();
        let state = Arc::new(Mutex::new(State {
            start: Instant::now(),
            fault: Fault::None,
            trace: VecDeque::new(),
            omitted: 0,
        }));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut client = None;
            let mut generation = 0;
            let (mut a, mut b) = ([0; 2048], [0; 2048]);
            loop {
                let (outgoing, packet) = tokio::select! {
                    r = front.recv_from(&mut a) => {
                        let (n, source) = r.unwrap();
                        assert!(source.ip().is_loopback());
                        assert!(n < a.len());
                        if client != Some(source) {
                            generation += 1;
                            client = Some(source);
                        }
                        (true, &a[..n])
                    },
                    r = back.recv(&mut b) => {
                        let n = r.unwrap();
                        assert!(n < b.len());
                        (false, &b[..n])
                    },
                };
                let kind = packet
                    .get(..4)
                    .map(|p| u32::from_le_bytes(p.try_into().unwrap()));
                let data = kind == Some(4) && packet.len() > 32;
                let discard = {
                    let mut s = shared.lock().unwrap();
                    let discard = match s.fault {
                        Fault::None => false,
                        Fault::FirstInitiation => outgoing && kind == Some(1),
                        Fault::FirstResponse => !outgoing && kind == Some(2),
                        Fault::NextClientData => outgoing && data,
                        Fault::NextServerData => !outgoing && data,
                    };
                    if discard {
                        s.fault = Fault::None;
                    }
                    s.record(json!({"direction": if outgoing { "client-server" } else { "server-client" },
                        "type": kind, "bytes": packet.len(), "generation": generation,
                        "action": if discard { "drop" } else { "forward" }}));
                    discard
                };
                if !discard {
                    let sent = if outgoing {
                        back.send(packet).await.unwrap()
                    } else {
                        front
                            .send_to(packet, client.expect("client before reply"))
                            .await
                            .unwrap()
                    };
                    assert_eq!(sent, packet.len());
                }
            }
        });
        Self {
            address,
            state,
            task,
        }
    }
    pub fn arm(&self, fault: Fault) {
        let mut s = self.state.lock().unwrap();
        assert_eq!(s.fault, Fault::None, "previous fault was not exercised");
        s.fault = fault;
        s.record(json!({"armed": format!("{fault:?}")}));
    }
    pub fn mark(&self, event: Value) {
        self.state.lock().unwrap().record(event);
    }
    pub fn snapshot(&self) -> Value {
        let s = self.state.lock().unwrap();
        json!({"events": s.trace, "omittedEvents": s.omitted,
            "remainingFault": format!("{:?}", s.fault)})
    }
    pub fn save(&self, name: &str) {
        let snapshot = self.snapshot();
        if let Some(directory) = std::env::var_os("WIREGUARD_TIMEOUT_REPORT_DIR") {
            let directory = std::path::PathBuf::from(directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                directory.join(format!("{name}.json")),
                serde_json::to_vec_pretty(&snapshot).unwrap(),
            )
            .unwrap();
        }
        eprintln!(
            "{name}: {} events, {} omitted",
            snapshot["events"].as_array().unwrap().len(),
            snapshot["omittedEvents"]
        );
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
        if std::thread::panicking() {
            eprintln!("relay failure trace: {}", self.snapshot());
        }
    }
}
