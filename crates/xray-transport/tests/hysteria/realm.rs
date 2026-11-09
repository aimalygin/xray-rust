//! Hysteria through the `realm` mask against Xray-core's server: both
//! sides learn their address from a local STUN server, the server registers
//! with a local rendezvous speaking Hysteria's realm API, the client is
//! introduced and punches, and QUIC runs over the punched path.
use super::realm_rendezvous::{stun_server, Rendezvous};
use super::support::{ReferenceServer, Task, DEADLINE, SALAMANDER_PASSWORD};
use serde_json::json;
use std::{net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use xray_routing::{Network, Target, TargetAddr};
use xray_transport::{
    hysteria::HysteriaClient,
    realm::{RealmConfig, RealmEnv, RealmFamily, RealmScheme, RealmStunServer},
    SystemDnsResolver,
};

const TOKEN: &str = "interop-token";

fn realm(rendezvous: &Rendezvous, name: &str, stun: std::net::SocketAddr) -> Arc<RealmConfig> {
    Arc::new(RealmConfig {
        scheme: RealmScheme::Http,
        host: "127.0.0.1".into(),
        port_text: rendezvous.addr.port().to_string(),
        port: rendezvous.addr.port(),
        token: Arc::new(zeroize::Zeroizing::new(TOKEN.into())),
        id: name.into(),
        stun_servers: vec![RealmStunServer {
            host: "127.0.0.1".into(),
            port_text: stun.port().to_string(),
            port: stun.port(),
        }],
        tls: None,
        family: RealmFamily::Dual,
    })
}

async fn scenario(salamander: bool) {
    let rendezvous = Rendezvous::start(TOKEN).await;
    let (stun, _stun) = stun_server().await;
    let name = if salamander {
        "hysteria-salamander"
    } else {
        "hysteria-realm"
    };
    let server_realm = json!({"type":"realm","settings":{
        "url": rendezvous.url(name), "stunServers": [stun.to_string()]}});
    let obfuscation = json!({"type":"salamander","settings":{"password":SALAMANDER_PASSWORD}});
    let masks = if salamander {
        json!([obfuscation, server_realm])
    } else {
        json!([server_realm])
    };
    let Some(server) = ReferenceServer::start_with_udp_masks(masks.clone()).await else {
        eprintln!("native Hysteria has no finalmask; skipped");
        return;
    };
    eprintln!("Hysteria realm {masks}");
    rendezvous.registered(name).await;
    let config = |name: &str| {
        let mut config = server.config();
        if salamander {
            config.carrier.salamander_password = Some(Arc::new(zeroize::Zeroizing::new(
                SALAMANDER_PASSWORD.into(),
            )));
        }
        config.carrier.realm = Some(realm(&rendezvous, name, stun));
        config.realm = Some(RealmEnv {
            resolver: Arc::new(SystemDnsResolver),
            tls: server.connector.clone(),
            protector: None,
        });
        // The server's address is never used: the punched one is.
        config.remote_addr.set_port(1);
        config
    };
    // The rendezvous knows no other name.
    let refused = timeout(
        Duration::from_secs(30),
        HysteriaClient::connect(config("unknown-realm"), &server.connector),
    )
    .await;
    assert!(!matches!(refused, Ok(Ok(_))), "an unknown realm connected");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let _echo = Task(tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    }));
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    for phase in 0..2u8 {
        let client = HysteriaClient::connect(config(name), &server.connector)
            .await
            .unwrap();
        let mut tcp = client.open_tcp(&target).await.unwrap();
        let payload = vec![0x41 + phase; 64 * 1024];
        let mut reply = vec![0; payload.len()];
        timeout(DEADLINE, async {
            let (mut r, mut w) = tokio::io::split(&mut tcp);
            let (write, read) = tokio::join!(w.write_all(&payload), r.read_exact(&mut reply));
            write.unwrap();
            read.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(reply, payload);
        // The server's NAT opened for this socket alone: a network change
        // closes the client, and the next dial is introduced again.
        assert!(client.rebind());
        timeout(Duration::from_secs(5), async {
            while client.is_live() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    assert!(rendezvous.connects() >= 3, "{}", rendezvous.connects());
}

/// Alone, and with Salamander inside it.
#[tokio::test]
#[ignore = "requires pinned Xray Hysteria; use check-realm-interop.sh"]
async fn realm_alone_and_around_salamander() {
    for salamander in [false, true] {
        timeout(Duration::from_secs(120), scenario(salamander))
            .await
            .unwrap();
    }
}
