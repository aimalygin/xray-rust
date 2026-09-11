use super::*;

// Distinct loopback backends identify the peer actually selected by the native
// client. Each peer uses an independent pinned reference process and PSK.
#[tokio::test]
#[ignore = "requires pinned reference; use check-wireguard-runtime.sh or check-native-wireguard-interop.sh"]
async fn pinned_reference_multiple_peers_overlaps_and_equal_prefixes_tcp_udp() {
    timeout(Duration::from_secs(30), async {
        let public = PublicKey::from(&StaticSecret::from([0x42; 32]));
        let mut references = Vec::new();
        let mut tasks = Vec::new();
        let mut peers = Vec::new();
        for (index, prefixes) in [
            vec!["0.0.0.0/0", "::/0"],
            vec![
                "198.51.100.1/24",
                "2001:db8:b::1/64",
                "198.51.100.7/32",
                "2001:db8:b::7/128",
            ],
            vec!["198.51.100.99/24", "2001:db8:b::99/64"],
        ]
        .into_iter()
        .enumerate()
        {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = tcp.local_addr().unwrap().port();
            let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).await.unwrap();
            let tag = index as u8;
            tasks.push(tokio::spawn(async move {
                loop {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    tokio::spawn(async move {
                        stream.write_u8(tag).await.unwrap();
                        let (mut read, mut write) = stream.split();
                        let _ = tokio::io::copy(&mut read, &mut write).await;
                    });
                }
            }));
            tasks.push(tokio::spawn(async move {
                let mut bytes = [0; 2048];
                bytes[0] = tag;
                loop {
                    let (n, source) = udp.recv_from(&mut bytes[1..]).await.unwrap();
                    udp.send_to(&bytes[..n + 1], source).await.unwrap();
                }
            }));
            let secret = StaticSecret::from([0x53 + index as u8; 32]);
            let psk = [0x64 + index as u8; 32];
            let reference = support::Reference::start_custom(
                &secret,
                &public,
                Some(&psk),
                if index == 1 {
                    "::1".parse().unwrap()
                } else {
                    "127.0.0.1".parse().unwrap()
                },
                port,
            )
            .await;
            let mut peer = config(reference.address, &PublicKey::from(&secret))
                .peers
                .remove(0);
            peer.preshared_key = Some(KeyMaterial::parse(&STANDARD.encode(psk)).unwrap());
            peer.allowed_ips = prefixes.iter().map(|p| p.parse().unwrap()).collect();
            peers.push(peer);
            references.push(reference);
        }
        let protector = Arc::new(Protector(AtomicUsize::new(0)));
        let client = Client::start(
            Config {
                secret_key: KeyMaterial::parse(&"42".repeat(32)).unwrap(),
                peers,
                addresses: vec!["10.44.0.2".parse().unwrap(), "fd44::2".parse().unwrap()],
                mtu: 1420,
            },
            Some(protector.clone()),
        )
        .await
        .unwrap();
        for addresses in [
            ["192.0.2.10:9", "198.51.100.7:9", "198.51.100.8:9"],
            [
                "[2001:db8:a::10]:9",
                "[2001:db8:b::7]:9",
                "[2001:db8:b::8]:9",
            ],
        ] {
            for (index, address) in addresses.into_iter().enumerate() {
                let address = address.parse().unwrap();
                let mut stream = client.connect(address).await.unwrap();
                assert_eq!(
                    stream.read_u8().await.unwrap(),
                    index as u8,
                    "TCP selected peer"
                );
                stream.write_all(b"TCP").await.unwrap();
                let mut payload = [0; 3];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"TCP");
                let session = client.open_udp(address).await.unwrap();
                session.send(b"UDP").await.unwrap();
                assert_eq!(
                    &session.recv().await.unwrap()[..],
                    &[index as u8, b'U', b'D', b'P']
                );
            }
        }
        assert_eq!(protector.0.load(Ordering::SeqCst), 2);
        client.shutdown().await;
        for task in tasks {
            task.abort();
            let _ = task.await;
        }
    })
    .await
    .expect("pinned multi-peer deadline");
}
