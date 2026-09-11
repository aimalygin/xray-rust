use super::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{atomic::AtomicUsize, Arc},
};
use x25519_dalek::{PublicKey, StaticSecret};
use xray_core_rs::Core;
use xray_transport::{DnsResolver, TransportDialer, TransportError};

#[derive(Default)]
struct Bootstrap(AtomicUsize);
#[async_trait]
impl DnsResolver for Bootstrap {
    async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let ip = match domain {
            "peer4.example" => "127.0.0.1",
            "peer6.example" => "::1",
            _ => panic!("unexpected bootstrap lookup"),
        };
        Ok(SocketAddr::new(ip.parse().unwrap(), port))
    }
}
#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn wireguard_runtime_multi_peer_json_bootstrap_shared_ownership_and_host_close() {
    timeout(DEADLINE,async {
        let client_public = PublicKey::from(&StaticSecret::from([0x42;32]));
        let a = support::reference::Reference::start_with_psk(&StaticSecret::from([0x53;32]),&client_public,Some(&[0x64;32])).await;
        let b = support::reference::Reference::start_custom(&StaticSecret::from([0x63;32]),&client_public,Some(&[0x74;32]),"::1".parse().unwrap(),0).await;
        let mut profile = support::profile(a.address);
        profile["outbounds"][0]["settings"]["peers"] = json!([
            {"publicKey":STANDARD.encode(PublicKey::from(&StaticSecret::from([0x53;32])).as_bytes()),
             "preSharedKey":STANDARD.encode([0x64;32]),"endpoint":format!("peer4.example:{}",a.address.port()),
             "allowedIPs":["0.0.0.0/0","::/0"]},
            {"publicKey":STANDARD.encode(PublicKey::from(&StaticSecret::from([0x63;32])).as_bytes()),
             "preSharedKey":STANDARD.encode([0x74;32]),"endpoint":format!("peer6.example:{}",b.address.port()),
             "allowedIPs":["198.51.100.7/32","2001:db8:b::7/128"]}
        ]);
        let bootstrap = Arc::new(Bootstrap::default());
        let protector = Arc::new(Protector::default());
        let dialer = Arc::new(TransportDialer::system().unwrap().with_socket_protector(protector.clone()));
        let config = xray_config::parse_xray_json(&profile.to_string()).unwrap().config;
        let mut core = Core::with_runtime_dependencies(config,bootstrap.clone(),dialer).unwrap();
        core.start().await.unwrap();
        let (tcp_addr,_tcp) = tcp_echo().await;
        let (udp_addr,_udp) = udp_echo().await;
        let socks_addr = core.inbound_addr(Some("socks-in")).unwrap();
        let (first,second) = tokio::join!(
            socks(socks_addr,1,"192.0.2.7",tcp_addr.port()),
            socks(socks_addr,1,"198.51.100.7",tcp_addr.port())
        );
        let (mut first,_) = first; let (mut second,_) = second;
        echo(&mut first,b"default peer").await;
        echo(&mut second,b"specific peer").await;
        let (_control,relay) = socks(socks_addr,3,"0.0.0.0",0).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = Target::new(TargetAddr::Ip("2001:db8:b::7".parse().unwrap()),udp_addr.port(),Network::Udp);
        udp.send_to(&encode_socks5_udp_datagram(&target,b"IPv6 peer UDP").unwrap(),relay).await.unwrap();
        let mut packet = [0;2048]; let n = udp.recv(&mut packet).await.unwrap();
        let reply = parse_socks5_udp_datagram(&packet[..n]).unwrap();
        assert_eq!(reply.target,target); assert_eq!(reply.payload.as_ref(),b"IPv6 peer UDP");
        assert_eq!(bootstrap.0.load(Ordering::SeqCst),2,"bootstrap runs once per peer, independent of flows");
        assert_eq!(protector.0.load(Ordering::SeqCst),2,"one cached device with one socket per family");
        let snapshot = core.connection_snapshot();
        assert_eq!(snapshot.connections.len(),3);
        let first_id = snapshot.connections.iter().find(|c| c.target.addr == TargetAddr::Domain("192.0.2.7".into())).unwrap().id;
        core.close_connection(first_id).unwrap();
        assert!(first.read_u8().await.is_err());
        echo(&mut second,b"other peer survives host close").await;
        let accounting = core.outbound_accounting_snapshot();
        let proxy = accounting.outbounds.iter().find(|o| o.outbound_tag.as_deref()==Some("proxy")).unwrap();
        assert_eq!(proxy.host_closed_connections,1);
        // Outbound totals include completed flows; the second TCP and UDP
        // flows are still active here.
        assert_eq!(proxy.uplink_bytes,b"default peer".len() as u64);
        assert_eq!(proxy.downlink_bytes,b"default peer".len() as u64);
        core.stop().await.unwrap();
        assert!(second.read_u8().await.is_err());
        while !core.connection_snapshot().connections.is_empty() { tokio::task::yield_now().await; }
        let accounting = core.outbound_accounting_snapshot();
        let proxy = accounting.outbounds.iter().find(|o| o.outbound_tag.as_deref()==Some("proxy")).unwrap();
        let expected = b"default peer".len() + b"specific peer".len()
            + b"other peer survives host close".len() + b"IPv6 peer UDP".len();
        assert_eq!(proxy.completed_connections,3);
        assert_eq!(proxy.uplink_bytes,expected as u64);
        assert_eq!(proxy.downlink_bytes,expected as u64);
    }).await.unwrap();
}
