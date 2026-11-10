//! VLESS over XDRIVE against Xray-core v26.10.31's own XDRIVE server, the
//! two meeting in a `local` folder: TCP and UDP of both families through
//! Mux.Cool, VLESS encryption with X25519 and ML-KEM-768 authentication,
//! and sessions cut into many small segments. Then the two meet in the HTTP
//! storages of a stand-in (`tools/xdrive-oracle/standin`): an S3 bucket that
//! checks every SigV4 signature, and a REST store a `template` describes,
//! Xray-core's server over plain HTTP and this client over HTTPS and HTTP/2
//! through `streamSettings.address`. Last they meet in Xray-core's own
//! fakeDrive, which `tools/xdrive-oracle/drive_server_test.go` serves on
//! Google's paths over TLS and HTTP/3: in slots, and this client over
//! HTTP/3 through a noise mask. The S3 bucket and the REST store are written
//! from the services' documentation, not from Xray-core, and the Drive
//! stand-in picks its own paths and protocols, so Xray-core's own client
//! crosses each first with this client's configuration: a stand-in
//! Xray-core cannot use is wrong, whatever this client makes of it.
//!
//! Targets are documentation addresses: Xray's server hands each flow to a
//! freedom outbound whose redirect sends it to the loopback echo servers,
//! keeping the port.
use super::masque::{core, echo_servers, tcp_echo, udp_echo, ECHO_V4, ECHO_V6};
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::BufRead;

/// Fast polling on both ends keeps each exchange in milliseconds.
fn tuning() -> Value {
    json!({"flushIntervalMs": 5, "pollIntervalMs": 5, "maxPollIntervalMs": 50,
        "sessionTtlSeconds": 30})
}

/// The Xray-core binary under test: the one the check script built, or a
/// fresh build of the checkout.
fn xray_binary(checkout: &Path, temp_dir: &TempDir) -> PathBuf {
    env::var_os("XRAY_VLESS_FULL_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let binary = temp_dir
                .path
                .join(format!("xray{}", env::consts::EXE_SUFFIX));
            let output = Command::new("go")
                .args(["build", "-o"])
                .arg(&binary)
                .arg("./main")
                .current_dir(checkout)
                .output()
                .expect("start go build for Xray-core");
            assert!(
                output.status.success(),
                "go build ./main failed: {output:?}"
            );
            binary
        })
}

/// A fresh `xray vlessenc` pair, `(decryption, encryption)`, for X25519 or
/// ML-KEM-768 authentication.
fn vlessenc(binary: &Path, ml_kem: bool) -> (String, String) {
    let output = Command::new(binary)
        .arg("vlessenc")
        .output()
        .expect("run xray vlessenc");
    assert!(output.status.success(), "xray vlessenc failed: {output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    let section = text
        .split("Authentication: ")
        .find(|section| section.starts_with(if ml_kem { "ML-KEM-768" } else { "X25519" }))
        .expect("an authentication section");
    let value = |key: &str| {
        section
            .lines()
            .find_map(|line| line.strip_prefix(&format!("\"{key}\": \"")))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("no {key} in {section}"))
            .to_owned()
    };
    (value("decryption"), value("encryption"))
}

struct Session {
    server: XrayServer,
    folder: PathBuf,
    encryption: String,
}

/// Xray-core's VLESS inbound over XDRIVE in `folder`, with `decryption`, and
/// a freedom outbound redirected to the loopback.
async fn start_server(ml_kem: bool) -> Session {
    start_server_with(ml_kem, |folder| {
        let mut xdrive = tuning();
        xdrive["service"] = "local".into();
        xdrive["remoteFolder"] = folder.to_str().unwrap().into();
        json!({"network": "xdrive", "xdriveSettings": xdrive})
    })
    .await
}

/// Xray-core's VLESS inbound over the XDRIVE stream `stream` makes of a
/// fresh folder, and a freedom outbound redirected to the loopback.
async fn start_server_with(ml_kem: bool, stream: impl FnOnce(&Path) -> Value) -> Session {
    let checkout = resolve_xray_checkout();
    let temp_dir = create_temp_dir("xray-rust-xdrive-interop");
    let binary = xray_binary(&checkout, &temp_dir);
    let (decryption, encryption) = vlessenc(&binary, ml_kem);
    let folder = temp_dir.path.join("drive");
    let config_path = temp_dir.path.join("server.json");
    let stdout_path = temp_dir.path.join("xray.stdout.log");
    let stderr_path = temp_dir.path.join("xray.stderr.log");
    let stream = stream(&folder);
    // XDRIVE binds no socket: the port only names the inbound.
    let port = allocate_loopback_port();
    let config = json!({
        "log": {"loglevel": "debug"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless", "tag": "xdrive-in",
            "settings": {"clients": [{"id": TEST_UUID}], "decryption": decryption},
            "streamSettings": stream
        }],
        // A VLESS inbound's freedom blocks private targets unless told.
        "outbounds": [
            {"tag": "direct", "protocol": "freedom",
                "settings": {"redirect": "127.0.0.1:0", "finalRules": [{"action": "allow"}]}}
        ]
    });
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
        .spawn()
        .expect("start xray process");
    wait_for_xray_startup(&mut child, &stdout_path, &stderr_path).await;
    Session {
        server: XrayServer {
            child,
            _temp_dir: temp_dir,
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            stdout_path,
            stderr_path,
            tls_client_config: None,
        },
        folder,
        encryption,
    }
}

/// Our client: a SOCKS inbound and VLESS with encryption and Mux over
/// XDRIVE in the server's folder, with `xdrive` merged into its settings.
fn client_config(session: &Session, xdrive: Value) -> Value {
    let mut settings = tuning();
    settings["service"] = "local".into();
    settings["remoteFolder"] = session.folder.to_str().unwrap().into();
    for (key, value) in xdrive.as_object().unwrap() {
        settings[key] = value.clone();
    }
    client_config_with(
        session,
        json!({"network": "xdrive", "xdriveSettings": settings}),
    )
}

/// Our client over the XDRIVE stream `stream`.
fn client_config_with(session: &Session, stream: Value) -> Value {
    json!({
        "inbounds": [{"protocol": "socks", "tag": "socks-in", "listen": "127.0.0.1", "port": 0,
            "settings": {"udp": true}}],
        "outbounds": [{"tag": "xdrive", "protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": 443, "id": TEST_UUID,
                "encryption": session.encryption},
            "streamSettings": stream,
            "mux": {"enabled": true, "concurrency": 8, "xudpConcurrency": 8,
                "xudpProxyUDP443": "allow"}}]
    })
}

/// Xray-core's own client with `config`, one made for this client: its
/// SOCKS inbound on a port of its own.
async fn xray_client(mut config: Value) -> XrayServer {
    let checkout = resolve_xray_checkout();
    let temp_dir = create_temp_dir("xray-rust-xdrive-xray-client");
    let binary = xray_binary(&checkout, &temp_dir);
    let port = allocate_loopback_port();
    config["inbounds"][0]["port"] = port.into();
    config["log"] = json!({"loglevel": "debug"});
    let config_path = temp_dir.path.join("client.json");
    let stdout_path = temp_dir.path.join("xray-client.stdout.log");
    let stderr_path = temp_dir.path.join("xray-client.stderr.log");
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();
    let mut child = Command::new(&binary)
        .arg("run")
        .arg("-config")
        .arg(&config_path)
        .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
        .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()))
        .spawn()
        .expect("start Xray-core's client");
    wait_for_xray_startup(&mut child, &stdout_path, &stderr_path).await;
    XrayServer {
        child,
        _temp_dir: temp_dir,
        addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        stdout_path,
        stderr_path,
        tls_client_config: None,
    }
}

async fn check(
    server: &XrayServer,
    case: &str,
    run: impl std::future::Future<Output = std::io::Result<()>>,
) {
    eprintln!("XDRIVE {case}");
    let result = timeout(Duration::from_secs(60), run).await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "{case}: {result:?}; {}",
        server.logs()
    );
}

/// Sessions Xray-core's server took, by its log.
fn accepted_sessions(server: &XrayServer) -> usize {
    server.logs().matches("accepted session ").count()
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_local_carries_tcp_and_udp_through_mux() {
    let session = start_server(false).await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let mut core = core(client_config(&session, json!({}))).await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(server, "TCP over IPv4", tcp_echo(proxy, ECHO_V4, tcp_port)).await;
    check(server, "TCP over IPv6", tcp_echo(proxy, ECHO_V6, tcp_port)).await;
    check(server, "UDP over IPv4", udp_echo(proxy, ECHO_V4, udp_port)).await;
    check(server, "UDP over IPv6", udp_echo(proxy, ECHO_V6, udp_port)).await;
    check(server, "eight parallel TCP flows", async {
        let flows = (0..8).map(|_| tcp_echo(proxy, ECHO_V4, tcp_port));
        for result in futures_util::future::join_all(flows).await {
            result?;
        }
        Ok(())
    })
    .await;
    // Mux carries the flows on a few sessions, not one each.
    let sessions = accepted_sessions(server);
    assert!(
        (1..=4).contains(&sessions),
        "{sessions} sessions for twelve flows: {}",
        server.logs()
    );
    core.stop().await.unwrap();
    // The server reads and deletes every segment the client stored.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let leftover = uplink_segments(&session.folder);
        if leftover == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{leftover} uplink segments were never read: {}",
            server.logs()
        );
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_local_takes_ml_kem_and_many_small_segments() {
    let session = start_server(true).await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    // 128 KiB echoes cut into 4 KiB segments, two stored at a time.
    let mut core = core(client_config(
        &session,
        json!({"segmentBytes": 4096, "concurrency": 2}),
    ))
    .await;
    let proxy = core.inbound_addr(Some("socks-in")).unwrap();
    check(
        server,
        "ML-KEM TCP in small segments",
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    check(server, "ML-KEM UDP", udp_echo(proxy, ECHO_V6, udp_port)).await;
    core.stop().await.unwrap();
}

/// `.seg` files still waiting under every session's `c2s`.
fn uplink_segments(folder: &Path) -> usize {
    let Ok(sessions) = fs::read_dir(folder.join("streams")) else {
        return 0;
    };
    sessions
        .filter_map(Result::ok)
        .filter_map(|session| fs::read_dir(session.path().join("c2s")).ok())
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".seg"))
        .count()
}

/// The storage stand-in, serving one store over HTTP and over HTTPS with a
/// fresh self-signed certificate.
struct Standin {
    child: Child,
    dir: TempDir,
    http: SocketAddr,
    https: SocketAddr,
    /// The certificate's SHA-256, for `pinnedPeerCertSha256`.
    pin: String,
}

impl Drop for Standin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Standin {
    fn log(&self) -> String {
        fs::read_to_string(self.dir.path.join("standin.stderr.log")).unwrap_or_default()
    }

    /// Requests served whose log line holds every one of `parts`.
    fn served(&self, parts: &[&str]) -> usize {
        self.served_after(0, parts)
    }

    /// The complete lines logged so far, to count what comes after.
    fn mark(&self) -> usize {
        self.log().matches('\n').count()
    }

    /// Requests served after the first `mark` lines whose log line holds
    /// every one of `parts`.
    fn served_after(&self, mark: usize, parts: &[&str]) -> usize {
        self.log()
            .lines()
            .skip(mark)
            .filter(|line| {
                line.starts_with("served ") && parts.iter().all(|part| line.contains(part))
            })
            .count()
    }

    /// The lines that are not requests served, when something went wrong.
    fn complaints(&self) -> String {
        self.log()
            .lines()
            .filter(|line| !line.starts_with("served "))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// The stand-in binary: the one the check script built, or a fresh build.
fn standin_binary(dir: &TempDir) -> PathBuf {
    env::var_os("XDRIVE_STANDIN_BINARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let binary = dir.path.join(format!("standin{}", env::consts::EXE_SUFFIX));
            let source =
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/xdrive-oracle/standin");
            let output = Command::new("go")
                .args(["build", "-o"])
                .arg(&binary)
                .arg(".")
                .current_dir(source)
                .output()
                .expect("start go build for the stand-in");
            assert!(
                output.status.success(),
                "go build of the stand-in failed: {output:?}"
            );
            binary
        })
}

async fn start_standin(mode: &str, args: &[&str]) -> Standin {
    let dir = create_temp_dir("xray-rust-xdrive-standin");
    let identity = generate_tls_identity(&dir, "storage.test");
    let pem = fs::read_to_string(&identity.cert_path).unwrap();
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    use base64::Engine as _;
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    let pin = Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let mut child = Command::new(standin_binary(&dir))
        .args(["-mode", mode, "-cert"])
        .arg(&identity.cert_path)
        .arg("-key")
        .arg(&identity.key_path)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::from(
            fs::File::create(dir.path.join("standin.stderr.log")).unwrap(),
        ))
        .spawn()
        .expect("start the storage stand-in");
    let stdout = child.stdout.take().unwrap();
    let line = timeout(
        Duration::from_secs(20),
        tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            std::io::BufReader::new(stdout)
                .read_line(&mut line)
                .map(|_| line)
        }),
    )
    .await
    .expect("the stand-in names its addresses")
    .unwrap()
    .unwrap();
    let addresses: Value = serde_json::from_str(&line).expect("the stand-in's addresses");
    let address = |key: &str| addresses[key].as_str().unwrap().parse().unwrap();
    Standin {
        http: address("http"),
        https: address("https"),
        child,
        dir,
        pin,
    }
}

/// UDP through a storage whose answers can come seconds late, after the
/// retries the stand-in provokes: each datagram is resent every two seconds
/// until its own echo comes back, and a late echo of an earlier one is
/// skipped.
async fn patient_udp_echo(proxy: SocketAddr, target: &str, port: u16) -> std::io::Result<()> {
    let (_control, relay) = super::masque::socks(proxy, 3, "0.0.0.0", 0).await?;
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    for size in [1usize, 512, 1200] {
        let payload: Vec<u8> = (0..size).map(|n| (n * 13 + size) as u8).collect();
        let mut datagram = vec![0, 0, 0];
        match target.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => {
                datagram.push(1);
                datagram.extend(ip.octets());
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                datagram.push(4);
                datagram.extend(ip.octets());
            }
            Err(_) => panic!("{target} is no address"),
        }
        datagram.extend(port.to_be_bytes());
        datagram.extend(&payload);
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut reply = vec![0; 4096];
        'resend: loop {
            if Instant::now() > deadline {
                return Err(std::io::Error::other(format!(
                    "no UDP echo of {size} bytes"
                )));
            }
            socket.send_to(&datagram, relay).await?;
            let resend_at = Instant::now() + Duration::from_secs(2);
            while let Ok(received) =
                tokio::time::timeout_at(resend_at, socket.recv_from(&mut reply)).await
            {
                if reply[..received?.0].ends_with(&payload) {
                    break 'resend;
                }
            }
        }
    }
    Ok(())
}

/// TCP and UDP of both families, then parallel flows, through `proxy`.
async fn carry(
    server: &XrayServer,
    complaints: impl Fn() -> String,
    proxy: SocketAddr,
    tcp_port: u16,
    udp_port: u16,
) {
    let checked = |case: &str| format!("{case}; stand-in: {}", complaints());
    check(
        server,
        &checked("TCP over IPv4"),
        tcp_echo(proxy, ECHO_V4, tcp_port),
    )
    .await;
    check(
        server,
        &checked("UDP over IPv6"),
        patient_udp_echo(proxy, ECHO_V6, udp_port),
    )
    .await;
    check(server, &checked("four parallel TCP flows"), async {
        let flows = (0..4).map(|_| tcp_echo(proxy, ECHO_V6, tcp_port));
        for result in futures_util::future::join_all(flows).await {
            result?;
        }
        Ok(())
    })
    .await;
}

const S3_ACCESS: &str = "AKIAXRAYRUSTTEST0001";
const S3_SECRET: &str = "xray-rust/stand-in+secret";
const S3_TOKEN: &str = "session-token/with+symbols=";

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_s3_meets_xray_in_a_bucket_over_both_http_versions() {
    let storage = start_standin(
        "s3",
        &[
            "-access",
            S3_ACCESS,
            "-secret",
            S3_SECRET,
            "-token",
            S3_TOKEN,
            "-region",
            "eu-test-1",
            "-bucket",
            "xdrive-bucket",
            "-page",
            "1",
        ],
    )
    .await;
    let secrets = json!([S3_ACCESS, S3_SECRET, S3_TOKEN]);
    let http = storage.http;
    // Xray-core path-style over HTTP/1.1; pages of one key make every
    // listing of more go on with continuation tokens.
    let session = start_server_with(false, |_| {
        let mut xdrive = tuning();
        xdrive["service"] = "s3".into();
        xdrive["remoteFolder"] = "sessions/xray".into();
        xdrive["secrets"] = secrets.clone();
        xdrive["s3"] = json!({"endpoint": format!("http://{http}"), "region": "eu-test-1",
            "bucket": "xdrive-bucket", "pathStyle": true});
        json!({"network": "xdrive", "xdriveSettings": xdrive})
    })
    .await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    // This client virtual-hosted over HTTPS and HTTP/2, the bucket's host
    // sent to the stand-in through the stream's address and port.
    let mut xdrive = tuning();
    xdrive["service"] = "s3".into();
    xdrive["remoteFolder"] = "sessions/xray/".into();
    xdrive["secrets"] = secrets.clone();
    xdrive["s3"] = json!({"endpoint": "https://s3.storage.test/", "region": "eu-test-1",
        "bucket": "xdrive-bucket", "pathStyle": false});
    xdrive["xmux"] = json!({"maxConnections": 2});
    // Small segments, several stored at once, so that listings hold more.
    xdrive["segmentBytes"] = 4096.into();
    xdrive["concurrency"] = 4.into();
    let stream = json!({"network": "xdrive", "address": "127.0.0.1", "port": storage.https.port(),
        "security": "tls", "tlsSettings": {"pinnedPeerCertSha256": storage.pin},
        "xdriveSettings": xdrive});
    // The URL names no port: the stream's port only takes the connection.
    let host = " xdrive-bucket.s3.storage.test ";
    let stored = ["HTTP/2.0 PUT", host, "/sessions/xray/streams/"];
    // Xray-core's own client first, with this client's configuration.
    let xray = xray_client(client_config_with(&session, stream.clone())).await;
    carry(
        server,
        || storage.complaints(),
        xray.addr,
        tcp_port,
        udp_port,
    )
    .await;
    drop(xray);
    assert!(
        storage.served(&stored) > 0,
        "Xray-core's client stored nothing over HTTP/2 to {host}: {}",
        storage.log()
    );
    assert_eq!(storage.complaints(), "", "the stand-in failed Xray-core");
    let mark = storage.mark();
    let sessions = accepted_sessions(server);
    let mut client = core(client_config_with(&session, stream)).await;
    let proxy = client.inbound_addr(Some("socks-in")).unwrap();
    carry(server, || storage.complaints(), proxy, tcp_port, udp_port).await;
    client.stop().await.unwrap();
    let virtual_hosted = storage.served_after(mark, &stored);
    assert!(
        virtual_hosted > 0,
        "no PUT over HTTP/2 to {host}: {}",
        storage.log()
    );
    assert!(
        accepted_sessions(server) > sessions,
        "Xray-core took no session: {}",
        server.logs()
    );
    let sessions = accepted_sessions(server);
    // And path-style over plain HTTP/1.1, as Xray-core's server reaches it.
    let mut xdrive = tuning();
    xdrive["service"] = "s3".into();
    xdrive["remoteFolder"] = "sessions/xray".into();
    xdrive["secrets"] = secrets;
    xdrive["s3"] = json!({"endpoint": format!("http://{http}"), "region": "eu-test-1",
        "bucket": "xdrive-bucket"});
    let stream = json!({"network": "xdrive", "xdriveSettings": xdrive});
    let mut client = core(client_config_with(&session, stream)).await;
    let proxy = client.inbound_addr(Some("socks-in")).unwrap();
    carry(server, || storage.complaints(), proxy, tcp_port, udp_port).await;
    client.stop().await.unwrap();
    assert!(accepted_sessions(server) > sessions, "{}", server.logs());
    // Listings of three keys a page went on with continuation tokens.
    let continued = storage.served(&["GET", "continuation-token="]);
    assert!(continued > 0, "no listing was continued: {}", storage.log());
    assert_eq!(storage.complaints(), "");
}

/// The stand-in's REST store as a template for `base`: OAuth 2 for this
/// client, a static token for Xray-core's server.
fn rest_template(base: &str, oauth2: bool) -> Value {
    let auth = if oauth2 {
        json!({"type": "oauth2", "tokenUrl": format!("{base}/oauth/token"),
            "form": {"grant_type": "refresh_token", "refresh_token": "{secret0}",
                "client_id": "{secret1}"},
            "header": {"Authorization": "Bearer {token}"}, "expiryPath": "expires_in"})
    } else {
        json!({"type": "static", "header": {"Authorization": "Bearer {secret0}"}})
    };
    let mut put = json!({"method": "PUT", "url": format!("{base}/api/files/{{folder}}/{{name}}")});
    if oauth2 {
        // The object as base64 in a JSON body.
        put["headers"] = json!({"Content-Type": "application/json"});
        put["body"] = r#"{"content":"{data}"}"#.into();
    }
    json!({
        "flatten": true,
        "concurrency": 8,
        "auth": auth,
        "put": put,
        "get": {"url": format!("{base}/api/files/{{folder}}/{{name}}"), "hrefPath": "href"},
        "delete": {"method": "DELETE", "url": format!("{base}/api/files/{{folder}}/{{name}}")},
        "list": {"url": format!("{base}/api/list/{{folder}}"),
            "namesRegex": r#""name":"([^"]+)""#},
        "retry": {"status": [429], "rateReason": "error.reason"}
    })
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_template_meets_xray_in_a_rest_store() {
    // Tokens said to last 61 seconds are kept for one, so this client
    // fetches them again and again; the stand-in also forgets them. Xray-core
    // writes the token form unescaped, and so does this client: a `+` in the
    // refresh token would reach the service as a space.
    let storage = start_standin(
        "template",
        &[
            "-refresh-token",
            "refresh/token-1",
            "-client-id",
            "xray-rust",
            "-static-token",
            "static-token",
            "-token-lifetime",
            "61",
        ],
    )
    .await;
    let http = storage.http;
    let session = start_server_with(false, |_| {
        let mut xdrive = tuning();
        xdrive["service"] = "template".into();
        xdrive["remoteFolder"] = "xdrive".into();
        xdrive["secrets"] = json!(["static-token"]);
        xdrive["template"] = rest_template(&format!("http://{http}"), false);
        json!({"network": "xdrive", "xdriveSettings": xdrive})
    })
    .await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let mut xdrive = tuning();
    xdrive["service"] = "template".into();
    xdrive["remoteFolder"] = "xdrive".into();
    xdrive["secrets"] = json!(["refresh/token-1", "xray-rust"]);
    xdrive["template"] = rest_template("https://storage.test", true);
    let stream = json!({"network": "xdrive", "address": "127.0.0.1", "port": storage.https.port(),
        "security": "tls", "tlsSettings": {"pinnedPeerCertSha256": storage.pin},
        "xdriveSettings": xdrive});
    // Xray-core's own client first, with this client's configuration, then
    // this client; each must have crossed every path of the store.
    let xray = xray_client(client_config_with(&session, stream.clone())).await;
    carry(
        server,
        || storage.complaints(),
        xray.addr,
        tcp_port,
        udp_port,
    )
    .await;
    drop(xray);
    template_paths_crossed(&storage, 0, "Xray-core's client");
    assert_eq!(storage.complaints(), "", "the stand-in failed Xray-core");
    let mark = storage.mark();
    let sessions = accepted_sessions(server);
    let mut client = core(client_config_with(&session, stream)).await;
    let proxy = client.inbound_addr(Some("socks-in")).unwrap();
    carry(server, || storage.complaints(), proxy, tcp_port, udp_port).await;
    client.stop().await.unwrap();
    assert!(accepted_sessions(server) > sessions, "{}", server.logs());
    template_paths_crossed(&storage, mark, "this client");
    assert_eq!(storage.complaints(), "");
}

/// That the client whose requests the stand-in logged after `mark` lines
/// went every way of the REST store over HTTP/2: tokens fetched again,
/// objects as JSON, links redirected and followed, retries after rate
/// limits by reason and by status, and new tokens after forgotten ones.
fn template_paths_crossed(storage: &Standin, mark: usize, who: &str) {
    let host = " storage.test ";
    for (what, parts) in [
        (
            "tokens fetched again",
            ["HTTP/2.0 POST", host, "/oauth/token 200"].as_slice(),
        ),
        (
            "objects stored as JSON",
            ["HTTP/2.0 PUT", host, "/api/files/xdrive/streams~"].as_slice(),
        ),
        (
            "links redirected",
            ["HTTP/2.0 GET", host, "/link/", " 302"].as_slice(),
        ),
        (
            "linked bytes fetched",
            ["HTTP/2.0 GET", host, "/raw/", " 200"].as_slice(),
        ),
        (
            "rate limits by reason",
            ["HTTP/2.0", host, " 403"].as_slice(),
        ),
        (
            "rate limits by status",
            ["HTTP/2.0", host, " 429"].as_slice(),
        ),
        ("forgotten tokens", ["HTTP/2.0", host, " 401"].as_slice()),
    ] {
        let count = storage.served_after(mark, parts);
        let enough = if what == "tokens fetched again" { 2 } else { 1 };
        assert!(count >= enough, "{who}, {what}: {count}; {}", storage.log());
    }
}

/// Xray-core's own fakeDrive on Google's paths, over TLS and HTTP/3 on one
/// port (`tools/xdrive-oracle/drive_server_test.go`).
struct DriveStandin {
    child: Child,
    dir: TempDir,
    port: u16,
    /// The certificate's SHA-256, for `pinnedPeerCertSha256`.
    pin: String,
}

impl Drop for DriveStandin {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl DriveStandin {
    fn requests(&self) -> String {
        fs::read_to_string(self.dir.path.join("requests")).unwrap_or_default()
    }

    fn served(&self, parts: &[&str]) -> usize {
        self.served_after(0, parts)
    }

    /// The complete lines logged so far, to count what comes after.
    fn mark(&self) -> usize {
        self.requests().matches('\n').count()
    }

    /// Requests served after the first `mark` lines that hold every one of
    /// `parts`.
    fn served_after(&self, mark: usize, parts: &[&str]) -> usize {
        self.requests()
            .lines()
            .skip(mark)
            .filter(|line| parts.iter().all(|part| line.contains(part)))
            .count()
    }
}

/// The stand-in binary: the one the check script built, or a fresh build
/// of the overlay test in the pinned checkout.
fn drive_server_binary(dir: &TempDir) -> PathBuf {
    env::var_os("XDRIVE_DRIVE_SERVER")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let checkout = resolve_xray_checkout();
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/xdrive-oracle/drive_server_test.go");
            let overlay = dir.path.join("overlay.json");
            let target = checkout.join("transport/internet/xdrive/xray_rust_drive_server_test.go");
            fs::write(
                &overlay,
                json!({"Replace": {target.to_str().unwrap(): source.to_str().unwrap()}})
                    .to_string(),
            )
            .unwrap();
            let binary = dir.path.join("drive-server");
            let output = Command::new("go")
                .args(["test", "-c", "-mod=readonly", "-overlay"])
                .arg(&overlay)
                .arg("-o")
                .arg(&binary)
                .arg("./transport/internet/xdrive")
                .current_dir(&checkout)
                .output()
                .expect("start go test -c for the Drive stand-in");
            assert!(
                output.status.success(),
                "building the Drive stand-in failed: {output:?}"
            );
            binary
        })
}

async fn start_drive() -> DriveStandin {
    let dir = create_temp_dir("xray-rust-xdrive-drive");
    let mut child = Command::new(drive_server_binary(&dir))
        .args(["-test.run", "^TestXrayRustDriveServer$"])
        .env("XDRIVE_DRIVE_SERVER_DIR", &dir.path)
        .stdout(Stdio::null())
        .stderr(Stdio::from(
            fs::File::create(dir.path.join("stderr")).unwrap(),
        ))
        .spawn()
        .expect("start the Drive stand-in");
    let deadline = Instant::now() + Duration::from_secs(30);
    let (port, pin) = loop {
        let port = fs::read_to_string(dir.path.join("port")).unwrap_or_default();
        let pin = fs::read_to_string(dir.path.join("pin")).unwrap_or_default();
        if let (Ok(port), false) = (port.trim().parse::<u16>(), pin.is_empty()) {
            break (port, pin);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the Drive stand-in did not start");
        }
        sleep(Duration::from_millis(50)).await;
    };
    DriveStandin {
        child,
        dir,
        port,
        pin,
    }
}

/// A Google Drive stream, its connections sent to the stand-in through the
/// stream's address and port and its certificate pinned; `extra` merges
/// into the stream.
fn drive_stream(drive: &DriveStandin, extra: Value) -> Value {
    let mut xdrive = tuning();
    xdrive["service"] = "google-drive".into();
    xdrive["remoteFolder"] = "folder-id".into();
    xdrive["secrets"] = json!(["client-id", "client-secret", "refresh-token"]);
    let mut stream = json!({"network": "xdrive", "address": "127.0.0.1", "port": drive.port,
        "security": "tls", "tlsSettings": {"pinnedPeerCertSha256": drive.pin},
        "xdriveSettings": xdrive});
    for (key, value) in extra.as_object().unwrap() {
        match (key.as_str(), value) {
            ("tlsSettings", Value::Object(fields)) => {
                for (field, value) in fields {
                    stream["tlsSettings"][field] = value.clone();
                }
            }
            _ => stream[key] = value.clone(),
        }
    }
    stream
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_google_drive_meets_xray_in_slots() {
    let drive = start_drive().await;
    let stream = drive_stream(&drive, json!({}));
    let server_stream = stream.clone();
    let session = start_server_with(false, move |_| server_stream).await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    // Xray-core's own client first, with this client's configuration: the
    // stand-in serves Xray-core's fakeDrive on paths and protocols of its
    // own choosing, which Xray-core's client must cross as well.
    let xray = xray_client(client_config_with(&session, stream.clone())).await;
    carry(server, || drive.requests(), xray.addr, tcp_port, udp_port).await;
    drop(xray);
    let by_xray = server.logs().matches(" slots").count();
    assert!(
        by_xray > 0,
        "Xray-core's client: no session in slots: {}",
        server.logs()
    );
    let mut client = core(client_config_with(&session, stream)).await;
    let proxy = client.inbound_addr(Some("socks-in")).unwrap();
    carry(server, || drive.requests(), proxy, tcp_port, udp_port).await;
    client.stop().await.unwrap();
    // Xray-core's server took the sessions this client announced in rings
    // of eight slots each way.
    let slotted = server.logs().matches(" slots").count();
    assert!(slotted > by_xray, "no session in slots: {}", server.logs());
    for (what, parts) in [
        (
            "tokens",
            vec!["HTTP/2.0 POST oauth2.googleapis.com /token 200"],
        ),
        (
            "slots made",
            vec!["HTTP/2.0 POST www.googleapis.com /drive/v3/files?fields=id 200"],
        ),
        (
            "slots written",
            vec![
                "HTTP/2.0 PATCH www.googleapis.com /drive/v3/files/",
                "fields=id&supportsAllDrives=true 200",
            ],
        ),
        (
            "slots read",
            vec![
                "HTTP/2.0 GET www.googleapis.com /drive/v3/files/",
                "fields=description&supportsAllDrives=true 200",
            ],
        ),
        (
            "announcements",
            vec![
                "HTTP/2.0 GET www.googleapis.com /drive/v3/files?",
                "name+contains",
            ],
        ),
    ] {
        assert!(drive.served(&parts) > 0, "{what}: {}", drive.requests());
    }
}

#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_google_drive_over_http3_through_a_noise_mask() {
    let drive = start_drive().await;
    // Xray-core's server over HTTP/2, this client over HTTP/3 alone.
    let server_stream = drive_stream(&drive, json!({}));
    let session = start_server_with(false, move |_| server_stream).await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let stream = drive_stream(
        &drive,
        json!({"tlsSettings": {"alpn": ["h3"]},
            "finalmask": {"udp": [{"type": "noise", "settings": {"noise": [{"rand": "30-60"}]}}],
                "quicParams": {"disableChromeParrot": true}}}),
    );
    // Xray-core's own client over HTTP/3 first, then this client; only
    // clients go over HTTP/3.
    let over_http3 = [
        (
            "tokens over HTTP/3",
            ["HTTP/3.0 POST oauth2.googleapis.com /token 200"].as_slice(),
        ),
        (
            "slots written over HTTP/3",
            ["HTTP/3.0 PATCH www.googleapis.com /drive/v3/files/"].as_slice(),
        ),
        (
            "slots read over HTTP/3",
            ["HTTP/3.0 GET www.googleapis.com /drive/v3/files/"].as_slice(),
        ),
    ];
    let xray = xray_client(client_config_with(&session, stream.clone())).await;
    carry(server, || drive.requests(), xray.addr, tcp_port, udp_port).await;
    drop(xray);
    for (what, parts) in over_http3 {
        let count = drive.served(parts);
        assert!(
            count > 0,
            "Xray-core's client, {what}: {}",
            drive.requests()
        );
    }
    let mark = drive.mark();
    let mut client = core(client_config_with(&session, stream)).await;
    let proxy = client.inbound_addr(Some("socks-in")).unwrap();
    carry(server, || drive.requests(), proxy, tcp_port, udp_port).await;
    client.stop().await.unwrap();
    for (what, parts) in over_http3 {
        let count = drive.served_after(mark, parts);
        assert!(count > 0, "{what}: {}", drive.requests());
    }
    let server_http2 = drive.served(&["HTTP/2.0 GET www.googleapis.com"]);
    assert!(
        server_http2 > 0,
        "Xray-core over HTTP/2: {}",
        drive.requests()
    );
    assert!(server.logs().contains(" slots"), "{}", server.logs());
}

/// A UDP relay to `upstream` that gives each client socket a socket of its
/// own towards it, as a NAT does, and keeps every client datagram in the
/// order it came: a storage over HTTP/3 opens a QUIC connection a host,
/// each from its own socket.
struct NatRelay {
    address: SocketAddr,
    datagrams: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    tasks: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl NatRelay {
    async fn start(upstream: SocketAddr) -> Self {
        let front = Arc::new(
            tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap(),
        );
        let address = front.local_addr().unwrap();
        let datagrams = Arc::new(std::sync::Mutex::new(Vec::new()));
        let tasks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (recorded, spawned) = (Arc::clone(&datagrams), Arc::clone(&tasks));
        let task = tokio::spawn(async move {
            let mut backs = std::collections::HashMap::new();
            let mut datagram = vec![0; 65_536];
            while let Ok((len, client)) = front.recv_from(&mut datagram).await {
                recorded.lock().unwrap().push(datagram[..len].to_vec());
                if let std::collections::hash_map::Entry::Vacant(entry) = backs.entry(client) {
                    let back = Arc::new(
                        tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
                            .await
                            .unwrap(),
                    );
                    back.connect(upstream).await.unwrap();
                    let (replies, front) = (Arc::clone(&back), Arc::clone(&front));
                    spawned.lock().unwrap().push(tokio::spawn(async move {
                        let mut reply = vec![0; 65_536];
                        while let Ok(len) = replies.recv(&mut reply).await {
                            let _ = front.send_to(&reply[..len], client).await;
                        }
                    }));
                    entry.insert(back);
                }
                let _ = backs[&client].send(&datagram[..len]).await;
            }
        });
        tasks.lock().unwrap().push(task);
        Self {
            address,
            datagrams,
            tasks,
        }
    }

    /// The client datagrams since the last call, one list for each QUIC
    /// connection, in the order the connections began: the Initial packets
    /// sent to the destination ID each client flight starts with.
    fn take_flights(&self) -> Vec<Vec<Vec<u8>>> {
        use super::chrome_parrot_wire::{decrypt_initial, Frame};
        let datagrams = std::mem::take(&mut *self.datagrams.lock().unwrap());
        let mut flights: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
        for datagram in datagrams {
            let Ok(initial) = decrypt_initial(&datagram) else {
                continue;
            };
            match flights.iter_mut().find(|(dcid, _)| *dcid == initial.dcid) {
                Some((_, flight)) => flight.push(datagram),
                None if initial
                    .frames
                    .iter()
                    .any(|frame| matches!(frame, Frame::Crypto { offset: 0, .. })) =>
                {
                    flights.push((initial.dcid.clone(), vec![datagram]));
                }
                None => {}
            }
        }
        flights.into_iter().map(|(_, flight)| flight).collect()
    }
}

impl Drop for NatRelay {
    fn drop(&mut self) {
        for task in self.tasks.lock().unwrap().iter() {
            task.abort();
        }
    }
}

/// ChromeParrot on storages over HTTP/3, as Xray-core's XDRIVE client sets
/// it, `!disableChromeParrot` with zero-length connection IDs. Through a
/// relay in front of the Drive stand-in, Xray-core's own client and then
/// this one send Chrome's first flight on every QUIC connection by default,
/// and this one the stock flight with `disableChromeParrot: true`.
#[tokio::test]
#[ignore = "requires a pinned Xray-core; run check-xdrive-interop.sh"]
async fn xdrive_google_drive_over_http3_parrots_chrome() {
    use super::chrome_parrot_wire::{assert_chrome_first_flight, assert_stock_first_flight};
    let drive = start_drive().await;
    let server_stream = drive_stream(&drive, json!({}));
    let session = start_server_with(false, move |_| server_stream).await;
    let server = &session.server;
    let (tcp_port, udp_port, _tcp, _udp) = echo_servers().await;
    let relay = NatRelay::start(SocketAddr::from((Ipv4Addr::LOCALHOST, drive.port))).await;
    let through_relay = |quic: Option<Value>| {
        let mut extra = json!({"tlsSettings": {"alpn": ["h3"]}, "port": relay.address.port()});
        if let Some(quic) = quic {
            extra["finalmask"] = json!({"quicParams": quic});
        }
        drive_stream(&drive, extra)
    };
    // Xray-core's own client first: its flights are what the checks hold.
    let xray = xray_client(client_config_with(&session, through_relay(None))).await;
    carry(server, || drive.requests(), xray.addr, tcp_port, udp_port).await;
    drop(xray);
    let flights = relay.take_flights();
    assert!(
        !flights.is_empty(),
        "Xray-core's client: no QUIC connection"
    );
    for flight in &flights {
        assert_chrome_first_flight(flight, b"h3");
    }
    for (quic, chrome_parrot) in [
        (None, true),
        (Some(json!({"disableChromeParrot": true})), false),
    ] {
        let mut client = core(client_config_with(&session, through_relay(quic.clone()))).await;
        let proxy = client.inbound_addr(Some("socks-in")).unwrap();
        carry(server, || drive.requests(), proxy, tcp_port, udp_port).await;
        client.stop().await.unwrap();
        let flights = relay.take_flights();
        // A token from oauth2.googleapis.com, the files from www.googleapis.com.
        assert!(
            flights.len() >= 2,
            "{quic:?}: {} connections",
            flights.len()
        );
        for flight in &flights {
            if chrome_parrot {
                assert_chrome_first_flight(flight, b"h3");
            } else {
                assert_stock_first_flight(flight);
            }
        }
    }
    let over_http3 = drive.served(&["HTTP/3.0 PATCH www.googleapis.com /drive/v3/files/"]);
    assert!(over_http3 > 0, "{}", drive.requests());
}
