use serde_json::json;
use xray_config::parse_xray_json;
use xray_core_rs::Core;
fn profile(listen: &str) -> serde_json::Value {
    json!({"inbounds":[{"tag":"transparent","listen":listen,"port":15000,"protocol":"dokodemo-door",
        "settings":{"network":"tcp,udp","followRedirect":true},"streamSettings":{"sockopt":{"tproxy":"tproxy"}}}],
        "outbounds":[{"protocol":"freedom","tag":"direct"}]})
}
#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn tproxy_rejects_unsupported_platform_before_starting() {
    let mut core = Core::new(
        parse_xray_json(&profile("127.0.0.1").to_string())
            .unwrap()
            .config,
    )
    .unwrap();
    assert!(matches!(
        core.start().await,
        Err(xray_core_rs::CoreError::UnsupportedTproxyPlatform)
    ));
    assert!(core.inbound_addr(Some("transparent")).is_none());
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires scripts/check-tproxy-linux.sh in an isolated privileged Linux network namespace"]
async fn tproxy_original_destination_tcp_udp_ipv4_ipv6_and_shutdown() {
    use std::{os::unix::process::CommandExt, process::Command, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinSet,
    };
    assert_eq!(
        std::env::var("XRAY_TPROXY_ISOLATED_NETWORK").as_deref(),
        Ok("1")
    );
    let mut tasks = JoinSet::new();
    // The proxy records original targets and echoes protocol payloads. Keeping
    // the destination off the core's local UDP listener avoids binding the
    // fake-source reply socket over a local echo server's identical endpoint.
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    let observed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = observed.clone();
    tasks.spawn(async move {
        let mut children = JoinSet::new();
        loop { tokio::select! {
            accepted = proxy.accept() => {
                let (mut stream, _) = accepted.unwrap(); let count=count.clone();
                children.spawn(async move {
                    assert_eq!(stream.read_u8().await.unwrap(),0);
                    let mut uuid=[0;16];stream.read_exact(&mut uuid).await.unwrap();assert_eq!(uuid,[1;16]);
                    let addons=stream.read_u8().await.unwrap();let mut skip=vec![0;addons as usize];stream.read_exact(&mut skip).await.unwrap();
                    let command=stream.read_u8().await.unwrap();
                    if command==3 {
                        use xray_proxy::vless::{read_xudp_packet,encode_xudp_keep_packet};
                        stream.write_all(&[0,0]).await.unwrap();
                        let mut original=None;
                        while let Ok(packet)=read_xudp_packet(&mut stream).await {
                            if let Some(target)=packet.source {
                                assert_eq!(target.port,18080);
                                assert!(["127.0.0.2","127.0.0.3","fd42:7872:6179::2","fd42:7872:6179::3"].iter().any(|ip|xray_routing::TargetAddr::Ip(ip.parse().unwrap())==target.addr));
                                if let Some(previous)=&original { assert_eq!(previous,&target); }
                                else { count.fetch_add(1,std::sync::atomic::Ordering::SeqCst);original=Some(target); }
                            }
                            assert!(original.is_some());
                            let response=encode_xudp_keep_packet(original.as_ref(),&packet.payload).unwrap();
                            if stream.write_all(&response).await.is_err(){break;}
                        }
                        return;
                    }
                    assert!(matches!(command,1|2));
                    assert_eq!(stream.read_u16().await.unwrap(),18080);
                    let address=match stream.read_u8().await.unwrap() {
                        1=>{let mut ip=[0;4];stream.read_exact(&mut ip).await.unwrap();std::net::IpAddr::from(ip)},
                        3=>{let mut ip=[0;16];stream.read_exact(&mut ip).await.unwrap();std::net::IpAddr::from(ip)},
                        value=>panic!("unexpected VLESS address type {value}"),
                    };
                    assert!(["127.0.0.2","127.0.0.3","fd42:7872:6179::2","fd42:7872:6179::3"].iter().any(|ip|ip.parse::<std::net::IpAddr>().unwrap()==address));
                    count.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
                    stream.write_all(&[0,0]).await.unwrap();
                    if command==1 {
                        let mut buffer=[0;16384];
                        while let Ok(n)=stream.read(&mut buffer).await { if n==0 || stream.write_all(&buffer[..n]).await.is_err(){break;} }
                    } else {
                        while let Ok(length)=stream.read_u16().await {
                            let mut payload=vec![0;length as usize];if stream.read_exact(&mut payload).await.is_err(){break;}
                            stream.write_u16(length).await.unwrap();stream.write_all(&payload).await.unwrap();
                        }
                    }
                });
            },
            joined=children.join_next(),if !children.is_empty()=>{joined.unwrap().unwrap();},
        }}
    });
    let mut p = profile("0.0.0.0");
    p["outbounds"] = json!([{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"127.0.0.1","port":proxy_port,"users":[{"id":"01010101-0101-0101-0101-010101010101","encryption":"none"}]}]}}]);
    let mut v6 = profile("::")["inbounds"][0].clone();
    v6["tag"] = json!("transparent-v6");
    p["inbounds"].as_array_mut().unwrap().push(v6);
    let mut core = Core::new(parse_xray_json(&p.to_string()).unwrap().config).unwrap();
    core.start().await.unwrap();
    let output=tokio::task::spawn_blocking(||Command::new("python3").arg("-c").arg(r#"
import socket
for family,hosts in [(socket.AF_INET,['127.0.0.2','127.0.0.3']),(socket.AF_INET6,['fd42:7872:6179::2','fd42:7872:6179::3'])]:
    for host in hosts:
        with socket.socket(family,socket.SOCK_STREAM) as s:
            s.settimeout(5);s.connect((host,18080))
            for i in range(16):
                data=bytes([i])*16384;s.sendall(data);out=b''
                while len(out)<len(data):
                    b=s.recv(len(data)-len(out));assert b;out+=b
                assert out==data
            s.shutdown(socket.SHUT_WR);assert s.recv(1)==b''
    # Same client socket, same destination port, two destination IPs.
    with socket.socket(family,socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        for i in range(32):
            for host in hosts:
                data=(host+':'+str(i)).encode()*64
                s.sendto(data,(host,18080));out,source=s.recvfrom(65536)
                assert out==data,(host,i,len(out));assert source[0]==host and source[1]==18080,source
print('TPROXY TCP 1 MiB + 128 UDP datagrams: IPv4/IPv6 original destinations and reply sources verified')
"#).uid(65534).gid(65534).output().unwrap()).await.unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
    assert_eq!(observed.load(std::sync::atomic::Ordering::SeqCst), 8);
    tokio::time::timeout(Duration::from_secs(3), core.stop())
        .await
        .unwrap()
        .unwrap();
    assert!(core.inbound_addr(Some("transparent")).is_none());
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
