#[path = "hysteria_runtime/support.rs"]
mod hysteria_support;
#[path = "trojan_runtime/support.rs"]
mod support;
use std::sync::atomic::Ordering;
use support::*;
use tokio::{io::AsyncReadExt, net::UdpSocket, time::timeout};
use xray_core_rs::Core;
use xray_proxy::inbound::{encode_socks5_udp_datagram, parse_socks5_udp_datagram};
use xray_routing::{Network, Target, TargetAddr};

#[tokio::test]
#[ignore = "requires pinned Xray; run scripts/check-mux-interop.sh"]
async fn mux_runtime_selected_protocols_share_tcp_udp_and_close_children() {
    for protocol in ["trojan", "shadowsocks", "vmess"] {
        for carrier in ["raw", "ws", "httpupgrade", "grpc", "xhttp"] {
            for separate_udp in [false, true] {
                if carrier == "xhttp" && !separate_udp {
                    continue;
                }
                eprintln!("Mux {protocol}/{carrier}, separate UDP pool: {separate_udp}");
                let server = match protocol {
                    "trojan" => ReferenceServer::start(carrier).await,
                    "shadowsocks" => {
                        ReferenceServer::start_shadowsocks(
                            carrier,
                            "2022-blake3-aes-128-gcm",
                            false,
                        )
                        .await
                    }
                    _ => ReferenceServer::start_vmess(carrier, "aes-128-gcm", "").await,
                };
                timeout(DEADLINE,async {
                let (tcp_addr,_tcp)=tcp_echo().await;
                let (udp_addr,_udp)=udp_echo().await;
                let (_,protector,bootstrap,dialer)=server.core();
                let mut profile=server.profile();
                profile["outbounds"][0]["mux"]=serde_json::json!({"enabled":true,"concurrency":if carrier == "xhttp" {-1} else {4},"xudpConcurrency":if separate_udp {4} else {0},"xudpProxyUDP443":"allow"});
                let config=xray_config::parse_xray_json(&profile.to_string()).unwrap().config;
                let mut core=Core::with_runtime_dependencies(config,bootstrap,dialer).unwrap();
                core.start().await.unwrap();
                let proxy=core.inbound_addr(Some("socks-in")).unwrap();
                let mut streams=Vec::new();
                for index in 0..6 {
                    let (mut stream,_)=socks(proxy,1,"localhost",tcp_addr.port()).await;
                    echo(&mut stream,&vec![index;8192]).await;
                    streams.push(stream);
                }
                let (_control,relay)=socks(proxy,3,"0.0.0.0",0).await;
                let udp=UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let target=Target::new(TargetAddr::Ip(udp_addr.ip()),udp_addr.port(),Network::Udp);
                for size in [1,4096,8192] {
                    let payload=vec![0x5a;size];
                    udp.send_to(&encode_socks5_udp_datagram(&target,&payload).unwrap(),relay).await.unwrap();
                    let mut bytes=[0;9000];let n=udp.recv(&mut bytes).await.unwrap();
                    let reply=parse_socks5_udp_datagram(&bytes[..n]).unwrap();
                    assert_eq!(reply.payload.as_ref(),payload);assert_eq!(reply.target,target);
                }
                // Six TCP children share two Mux parents. A dedicated UDP pool
                // adds one parent. H2 carriers share their protected socket.
                assert_eq!(protector.0.load(Ordering::SeqCst),if matches!(carrier, "grpc" | "xhttp") {1} else if separate_udp {3} else {2});
                let id=core.connection_snapshot().connections.iter().find(|c|c.network==Network::Udp).unwrap().id;
                core.close_connection(id).unwrap();
                for stream in &mut streams {echo(stream,b"siblings survive child close").await;}
                core.stop().await.unwrap();
                assert!(core.connection_snapshot().connections.is_empty());
                for stream in &mut streams {assert!(stream.read_u8().await.is_err());}
            }).await.unwrap();
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires local reference; run protocol interop scripts"]
async fn mux_runtime_ipv6_and_domain_datagrams_preserve_destination_identity() {
    use std::net::Ipv6Addr;
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
    };
    for protocol in ["trojan", "shadowsocks", "vmess"] {
        for mux in [false, true] {
            if independent_reference() && mux {
                continue;
            }
            eprintln!("IPv6/domain {protocol}, Mux={mux}");
            let server = match protocol {
                "trojan" => ReferenceServer::start("raw").await,
                "shadowsocks" => {
                    ReferenceServer::start_shadowsocks("raw", "2022-blake3-aes-256-gcm", false)
                        .await
                }
                _ => ReferenceServer::start_vmess("raw", "chacha20-poly1305", "").await,
            };
            timeout(DEADLINE, async {
                let tcp = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
                let tcp_addr = tcp.local_addr().unwrap();
                let _tcp = hysteria_support::Task(tokio::spawn(async move {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                }));
                let udp_echo_v6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
                let udp_addr_v6 = udp_echo_v6.local_addr().unwrap();
                let _udp_v6 = hysteria_support::Task(tokio::spawn(async move {
                    let mut bytes = [0; 8192];
                    loop {
                        let (n, peer) = udp_echo_v6.recv_from(&mut bytes).await.unwrap();
                        udp_echo_v6.send_to(&bytes[..n], peer).await.unwrap();
                    }
                }));
                let (udp_addr_v4, _udp_v4) = udp_echo().await;
                let (_, _, bootstrap, dialer) = server.core();
                let mut profile = server.profile();
                if mux {
                    profile["outbounds"][0]["mux"] = serde_json::json!({"enabled":true});
                }
                let mut core = Core::with_runtime_dependencies(
                    xray_config::parse_xray_json(&profile.to_string())
                        .unwrap()
                        .config,
                    bootstrap,
                    dialer,
                )
                .unwrap();
                core.start().await.unwrap();
                let proxy = core.inbound_addr(Some("socks-in")).unwrap();
                let mut tcp = TcpStream::connect(proxy).await.unwrap();
                tcp.write_all(&[5, 1, 0]).await.unwrap();
                let mut greeting = [0; 2];
                tcp.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 0]);
                let mut request = vec![5, 1, 0, 4];
                request.extend(Ipv6Addr::LOCALHOST.octets());
                request.extend(tcp_addr.port().to_be_bytes());
                tcp.write_all(&request).await.unwrap();
                let mut reply = [0; 10];
                tcp.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply[..4], &[5, 0, 0, 1]);
                echo(&mut tcp, b"IPv6 TCP through selected protocol").await;
                let (_control, relay) = socks(proxy, 3, "0.0.0.0", 0).await;
                let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                for target in [
                    Target::new(
                        TargetAddr::Ip(udp_addr_v6.ip()),
                        udp_addr_v6.port(),
                        Network::Udp,
                    ),
                    Target::new(
                        TargetAddr::Domain("localhost".into()),
                        udp_addr_v4.port(),
                        Network::Udp,
                    ),
                ] {
                    let bytes = b"IPv6 or domain UDP";
                    udp.send_to(&encode_socks5_udp_datagram(&target, bytes).unwrap(), relay)
                        .await
                        .unwrap();
                    let mut response = [0; 8192];
                    let n = udp.recv(&mut response).await.unwrap();
                    let packet = parse_socks5_udp_datagram(&response[..n]).unwrap();
                    assert_eq!(packet.payload.as_ref(), bytes);
                    assert_eq!(packet.target.port, target.port);
                    match (&target.addr, &packet.target.addr) {
                        (TargetAddr::Ip(expected), TargetAddr::Ip(actual)) => {
                            assert_eq!(expected, actual)
                        }
                        (TargetAddr::Domain(expected), TargetAddr::Domain(actual)) => {
                            assert_eq!(expected, actual)
                        }
                        (TargetAddr::Domain(_), TargetAddr::Ip(actual)) => {
                            assert!(actual.is_loopback())
                        }
                        _ => panic!("UDP response changed address family"),
                    }
                }
                core.stop().await.unwrap();
                assert!(core.connection_snapshot().connections.is_empty());
            })
            .await
            .unwrap();
        }
    }
}
