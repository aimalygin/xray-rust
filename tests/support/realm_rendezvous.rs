//! A STUN server and a rendezvous for the `realm` interop tests. The
//! rendezvous speaks the HTTP API of Hysteria's realm server
//! (apernet/hysteria-realm-server) as far as Xray-core's realm client and
//! server use it: a server registers its addresses and listens on an event
//! stream; a client's connect pushes a punch event to it, waits for the
//! server's fresh addresses and answers with them.
#![allow(dead_code)]

use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{oneshot, Notify},
    task::JoinHandle,
};

/// Aborts its task when dropped.
pub struct Background(JoinHandle<()>);

impl Drop for Background {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// A STUN server that answers every Binding request with an
/// XOR-MAPPED-ADDRESS of its source.
pub async fn stun_server() -> (SocketAddr, Background) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((length, from)) = socket.recv_from(&mut buf).await {
            if length < 20 || buf[..2] != [0, 1] || buf[4..8] != [0x21, 0x12, 0xA4, 0x42] {
                continue;
            }
            let mut answer = vec![0x01, 0x01, 0, 0, 0x21, 0x12, 0xA4, 0x42];
            answer.extend_from_slice(&buf[8..20]);
            let mut mask = vec![0x21, 0x12, 0xA4, 0x42];
            mask.extend_from_slice(&buf[8..20]);
            let (family, ip) = match from.ip().to_canonical() {
                std::net::IpAddr::V4(ip) => (1u8, ip.octets().to_vec()),
                std::net::IpAddr::V6(ip) => (2u8, ip.octets().to_vec()),
            };
            let port = from.port() ^ 0x2112;
            let mut value = vec![0, family, (port >> 8) as u8, port as u8];
            value.extend(ip.iter().zip(&mask).map(|(byte, mask)| byte ^ mask));
            answer.extend_from_slice(&[0x00, 0x20, 0, value.len() as u8]);
            answer.extend_from_slice(&value);
            let length = (answer.len() - 20) as u16;
            answer[2..4].copy_from_slice(&length.to_be_bytes());
            let _ = socket.send_to(&answer, from).await;
        }
    });
    (address, Background(task))
}

#[derive(Default)]
struct Events {
    queue: Mutex<VecDeque<String>>,
    ready: Notify,
}

struct Session {
    realm: String,
    addresses: Vec<String>,
    events: Arc<Events>,
}

#[derive(Default)]
struct State {
    token: String,
    /// Session ID by realm name.
    realms: Mutex<HashMap<String, String>>,
    sessions: Mutex<HashMap<String, Session>>,
    pending: Mutex<HashMap<String, oneshot::Sender<Vec<String>>>>,
    connects: AtomicUsize,
    registrations: AtomicUsize,
}

/// The rendezvous, its address and how many connects it took.
pub struct Rendezvous {
    pub addr: SocketAddr,
    state: Arc<State>,
    _task: Background,
}

impl Rendezvous {
    pub async fn start(token: &str) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(State {
            token: token.to_owned(),
            ..State::default()
        });
        let shared = state.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, shared.clone()));
            }
        });
        Self {
            addr,
            state,
            _task: Background(task),
        }
    }

    /// `realm+http://{token}@{addr}/{name}`.
    pub fn url(&self, name: &str) -> String {
        format!("realm+http://{}@{}/{name}", self.state.token, self.addr)
    }

    pub fn connects(&self) -> usize {
        self.state.connects.load(Ordering::Relaxed)
    }

    /// Waits until a server registered `name`.
    pub async fn registered(&self, name: &str) {
        for _ in 0..200 {
            if self.state.realms.lock().unwrap().contains_key(name) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("no server registered {name}");
    }
}

struct Request {
    method: String,
    path: String,
    bearer: String,
    body: Vec<u8>,
}

async fn read_request(reader: &mut BufReader<TcpStream>) -> Option<Request> {
    let mut line = String::new();
    if reader.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let (mut length, mut bearer) = (0usize, String::new());
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).await.ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok()?;
        } else if name.eq_ignore_ascii_case("authorization") {
            bearer = value.strip_prefix("Bearer ").unwrap_or_default().to_owned();
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await.ok()?;
    Some(Request {
        method,
        path,
        bearer,
        body,
    })
}

async fn respond(stream: &mut BufReader<TcpStream>, status: &str, body: Option<Value>) {
    let body = body.map(|body| body.to_string() + "\n").unwrap_or_default();
    let head = if body.is_empty() {
        format!("HTTP/1.1 {status}\r\n\r\n")
    } else {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
    };
    let _ = stream
        .get_mut()
        .write_all(format!("{head}{body}").as_bytes())
        .await;
}

fn addresses(body: &[u8]) -> Option<Vec<String>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    value["addresses"].as_array().map(|list| {
        list.iter()
            .filter_map(|a| a.as_str().map(str::to_owned))
            .collect()
    })
}

async fn serve(stream: TcpStream, state: Arc<State>) {
    let mut stream = BufReader::new(stream);
    while let Some(request) = read_request(&mut stream).await {
        let segments: Vec<&str> = request.path.trim_start_matches('/').split('/').collect();
        let not_found = json!({"error":"not_found","message":"unknown path"});
        match (request.method.as_str(), segments.as_slice()) {
            ("POST", ["v1", realm]) => {
                if request.bearer != state.token {
                    respond(
                        &mut stream,
                        "401 Unauthorized",
                        Some(json!({"error":"invalid_token","message":"invalid realm token"})),
                    )
                    .await;
                    continue;
                }
                let session = format!(
                    "session-{}",
                    state.registrations.fetch_add(1, Ordering::Relaxed)
                );
                state.sessions.lock().unwrap().insert(
                    session.clone(),
                    Session {
                        realm: (*realm).to_owned(),
                        addresses: addresses(&request.body).unwrap_or_default(),
                        events: Arc::default(),
                    },
                );
                state
                    .realms
                    .lock()
                    .unwrap()
                    .insert((*realm).to_owned(), session.clone());
                respond(
                    &mut stream,
                    "200 OK",
                    Some(json!({"session_id":session,"ttl":60})),
                )
                .await;
            }
            ("DELETE", ["v1", realm]) => {
                state.realms.lock().unwrap().remove(*realm);
                state.sessions.lock().unwrap().remove(&request.bearer);
                respond(&mut stream, "204 No Content", None).await;
            }
            ("POST", ["v1", _, "heartbeat"]) => {
                if let Some(session) = state.sessions.lock().unwrap().get_mut(&request.bearer) {
                    if let Some(fresh) = addresses(&request.body) {
                        session.addresses = fresh;
                    }
                }
                respond(&mut stream, "200 OK", Some(json!({"ttl":60}))).await;
            }
            ("GET", ["v1", _, "events"]) => {
                let events = state
                    .sessions
                    .lock()
                    .unwrap()
                    .get(&request.bearer)
                    .map(|session| session.events.clone());
                let Some(events) = events else {
                    respond(
                        &mut stream,
                        "401 Unauthorized",
                        Some(json!({"error":"invalid_token","message":"invalid session token"})),
                    )
                    .await;
                    continue;
                };
                let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n";
                if stream.get_mut().write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                loop {
                    let next = events.queue.lock().unwrap().pop_front();
                    match next {
                        Some(event) => {
                            if stream.get_mut().write_all(event.as_bytes()).await.is_err() {
                                return;
                            }
                        }
                        None => events.ready.notified().await,
                    }
                }
            }
            ("POST", ["v1", realm, "connect"]) => {
                state.connects.fetch_add(1, Ordering::Relaxed);
                let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
                let session = state.realms.lock().unwrap().get(*realm).cloned();
                let found = session.and_then(|session| {
                    state
                        .sessions
                        .lock()
                        .unwrap()
                        .get(&session)
                        .map(|s| (s.addresses.clone(), s.events.clone()))
                });
                let (Some((registered, events)), true) = (found, request.bearer == state.token)
                else {
                    respond(
                        &mut stream,
                        "404 Not Found",
                        Some(json!({"error":"realm_not_found","message":"realm not registered"})),
                    )
                    .await;
                    continue;
                };
                let nonce = body["nonce"].as_str().unwrap_or_default().to_owned();
                let (sender, receiver) = oneshot::channel();
                state.pending.lock().unwrap().insert(nonce.clone(), sender);
                let event =
                    json!({"addresses":body["addresses"],"nonce":nonce,"obfs":body["obfs"]});
                events
                    .queue
                    .lock()
                    .unwrap()
                    .push_back(format!("event: punch\ndata: {event}\n\n"));
                events.ready.notify_one();
                let answered = tokio::time::timeout(Duration::from_secs(10), receiver).await;
                state.pending.lock().unwrap().remove(&nonce);
                let addresses = match answered {
                    Ok(Ok(fresh)) if !fresh.is_empty() => fresh,
                    _ => registered,
                };
                respond(
                    &mut stream,
                    "200 OK",
                    Some(json!({"addresses":addresses,"nonce":nonce,"obfs":body["obfs"]})),
                )
                .await;
            }
            ("POST", ["v1", _, "connects", nonce]) => {
                let sender = state.pending.lock().unwrap().remove(*nonce);
                match sender {
                    Some(sender) => {
                        let _ = sender.send(addresses(&request.body).unwrap_or_default());
                        respond(&mut stream, "204 No Content", None).await;
                    }
                    None => respond(&mut stream, "404 Not Found", Some(json!({"error":"attempt_not_found","message":"no pending attempt for nonce"}))).await,
                }
            }
            _ => respond(&mut stream, "404 Not Found", Some(not_found)).await,
        }
    }
}
