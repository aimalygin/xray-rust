use super::*;
use std::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

/// What the test server answers one query with.
#[derive(Clone, Default)]
struct Reply {
    rcode: u8,
    /// Set TC on UDP and leave the answers out of it.
    truncate_udp: bool,
    authoritative: bool,
    recursion_available: bool,
    answers: Vec<(u16, Vec<u8>)>,
}

impl Reply {
    fn answers(answers: Vec<(u16, Vec<u8>)>) -> Self {
        Self {
            recursion_available: true,
            answers,
            ..Self::default()
        }
    }
    fn rcode(rcode: u8) -> Self {
        Self {
            rcode,
            recursion_available: true,
            ..Self::default()
        }
    }
}

fn name(name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|label| !label.is_empty())
    {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire
}

fn srv(priority: u16, weight: u16, port: u16, target: &str) -> (u16, Vec<u8>) {
    let mut data = Vec::new();
    data.extend_from_slice(&priority.to_be_bytes());
    data.extend_from_slice(&weight.to_be_bytes());
    data.extend_from_slice(&port.to_be_bytes());
    data.extend_from_slice(&name(target));
    (TYPE_SRV, data)
}

fn txt(strings: &[&str]) -> (u16, Vec<u8>) {
    let mut data = Vec::new();
    for string in strings {
        data.push(string.len() as u8);
        data.extend_from_slice(string.as_bytes());
    }
    (TYPE_TXT, data)
}

fn cname(target: &str) -> (u16, Vec<u8>) {
    (5, name(target))
}

/// The question's name and type.
fn question(query: &[u8]) -> (String, u16) {
    let mut offset = 12;
    let name = read_dns_name(query, &mut offset).unwrap();
    (name, read_u16(query, offset).unwrap())
}

fn respond(query: &[u8], reply: &Reply, udp: bool) -> Vec<u8> {
    let mut offset = 12;
    read_dns_name(query, &mut offset).unwrap();
    let question_end = offset + 4;
    let truncated = udp && reply.truncate_udp;
    let answers: &[(u16, Vec<u8>)] = if truncated { &[] } else { &reply.answers };
    let mut flags: u16 = 0x8000 | 0x0100 | u16::from(reply.rcode);
    if reply.authoritative {
        flags |= 0x0400;
    }
    if reply.recursion_available {
        flags |= 0x0080;
    }
    if truncated {
        flags |= 0x0200;
    }
    let mut response = query[..2].to_vec();
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    for (kind, data) in answers {
        response.extend_from_slice(&[0xC0, 12]);
        response.extend_from_slice(&kind.to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(&(data.len() as u16).to_be_bytes());
        response.extend_from_slice(data);
    }
    response
}

type Answerer = Arc<dyn Fn(&str, u16) -> Option<Reply> + Send + Sync>;

/// A nameserver on one loopback port, over UDP and TCP, recording each
/// question as `(name, type, over TCP)`. `None` from `answer` stays silent.
struct Server {
    address: SocketAddr,
    asked: Arc<Mutex<Vec<(String, u16, bool)>>>,
}

async fn server(answer: impl Fn(&str, u16) -> Option<Reply> + Send + Sync + 'static) -> Server {
    let answer: Answerer = Arc::new(answer);
    let asked = Arc::new(Mutex::new(Vec::new()));
    let (udp, tcp) = loop {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
            break (udp, tcp);
        }
    };
    let address = udp.local_addr().unwrap();
    let (udp_answer, udp_asked) = (answer.clone(), asked.clone());
    tokio::spawn(async move {
        let mut buffer = vec![0; 2048];
        while let Ok((length, peer)) = udp.recv_from(&mut buffer).await {
            let query = buffer[..length].to_vec();
            let (name, kind) = question(&query);
            udp_asked.lock().unwrap().push((name.clone(), kind, false));
            if let Some(reply) = udp_answer(&name, kind) {
                let _ = udp.send_to(&respond(&query, &reply, true), peer).await;
            }
        }
    });
    let tcp_asked = asked.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            let (answer, asked) = (answer.clone(), tcp_asked.clone());
            tokio::spawn(async move {
                let length = usize::from(stream.read_u16().await.unwrap());
                let mut query = vec![0; length];
                stream.read_exact(&mut query).await.unwrap();
                let (name, kind) = question(&query);
                asked.lock().unwrap().push((name.clone(), kind, true));
                if let Some(reply) = answer(&name, kind) {
                    let response = respond(&query, &reply, false);
                    stream.write_u16(response.len() as u16).await.unwrap();
                    stream.write_all(&response).await.unwrap();
                }
            });
        }
    });
    Server { address, asked }
}

fn conf(servers: &[SocketAddr]) -> ResolvConf {
    ResolvConf {
        servers: servers.to_vec(),
        timeout: Duration::from_secs(2),
        ..ResolvConf::defaults()
    }
}

fn resolver() -> SystemRecordResolver {
    SystemRecordResolver::new(None)
}

fn record(target: &str, port: u16, priority: u16, weight: u16) -> SrvRecord {
    SrvRecord {
        target: target.into(),
        port,
        priority,
        weight,
    }
}

#[tokio::test]
async fn srv_records_come_back_sorted_by_priority() {
    let server = server(|_, _| {
        Some(Reply::answers(vec![
            srv(20, 0, 2, "second.example."),
            srv(10, 0, 1, "first.example."),
        ]))
    })
    .await;
    let records = resolver()
        .srv(&conf(&[server.address]), "xray", "tcp", "example.com")
        .await
        .unwrap();
    assert_eq!(
        records,
        [
            record("first.example", 1, 10, 0),
            record("second.example", 2, 20, 0)
        ]
    );
    assert_eq!(
        *server.asked.lock().unwrap(),
        [("_xray._tcp.example.com".to_owned(), TYPE_SRV, false)]
    );
}

/// With both service and protocol empty, Go asks for `name` itself.
#[tokio::test]
async fn an_empty_service_and_protocol_ask_for_the_name_itself() {
    let server = server(|_, _| Some(Reply::answers(vec![srv(0, 0, 7, "x.example.")]))).await;
    let resolver = resolver();
    let conf = conf(&[server.address]);
    resolver.srv(&conf, "", "", "example.com").await.unwrap();
    resolver.srv(&conf, "", "tcp", "example.com").await.unwrap();
    let asked: Vec<String> = server
        .asked
        .lock()
        .unwrap()
        .iter()
        .map(|(name, _, _)| name.clone())
        .collect();
    assert_eq!(asked, ["example.com", "_._tcp.example.com"]);
}

#[tokio::test]
async fn a_truncated_answer_is_asked_again_over_tcp() {
    let server = server(|_, _| {
        Some(Reply {
            truncate_udp: true,
            ..Reply::answers(vec![srv(1, 0, 443, "server.example.")])
        })
    })
    .await;
    let records = resolver()
        .srv(&conf(&[server.address]), "xray", "tcp", "example.com")
        .await
        .unwrap();
    assert_eq!(records, [record("server.example", 443, 1, 0)]);
    let transports: Vec<bool> = server
        .asked
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, tcp)| *tcp)
        .collect();
    assert_eq!(transports, [false, true]);
}

#[tokio::test]
async fn use_vc_asks_over_tcp_alone() {
    let server = server(|_, _| Some(Reply::answers(vec![txt(&["a:1"])]))).await;
    let conf = ResolvConf {
        use_tcp: true,
        ..conf(&[server.address])
    };
    assert_eq!(resolver().txt(&conf, "example.com").await.unwrap(), ["a:1"]);
    let transports: Vec<bool> = server
        .asked
        .lock()
        .unwrap()
        .iter()
        .map(|(_, _, tcp)| *tcp)
        .collect();
    assert_eq!(transports, [true]);
}

#[tokio::test]
async fn txt_records_join_their_strings_in_order() {
    let server = server(|_, _| {
        Some(Reply::answers(vec![
            cname("alias.example."),
            txt(&["192.0.2.1:", "8443"]),
            txt(&["second"]),
        ]))
    })
    .await;
    assert_eq!(
        resolver()
            .txt(&conf(&[server.address]), "example.com")
            .await
            .unwrap(),
        ["192.0.2.1:8443", "second"]
    );
}

/// A name that does not exist stops the servers but not the search list.
#[tokio::test]
async fn nxdomain_moves_to_the_next_name_of_the_search_list() {
    let first = server(|name, _| {
        Some(if name == "_x._tcp.svc.corp.example" {
            Reply::answers(vec![srv(0, 0, 1, "found.example.")])
        } else {
            Reply::rcode(3)
        })
    })
    .await;
    let second = server(|_, _| Some(Reply::answers(vec![srv(0, 0, 2, "never.example.")]))).await;
    let conf = ResolvConf {
        search: vec!["corp.example.".into()],
        ..conf(&[first.address, second.address])
    };
    let records = resolver().srv(&conf, "x", "tcp", "svc").await.unwrap();
    assert_eq!(records, [record("found.example", 1, 0, 0)]);
    let asked: Vec<String> = first
        .asked
        .lock()
        .unwrap()
        .iter()
        .map(|(name, _, _)| name.clone())
        .collect();
    assert_eq!(asked, ["_x._tcp.svc", "_x._tcp.svc.corp.example"]);
    assert!(second.asked.lock().unwrap().is_empty());
}

/// SERVFAIL, a lame referral and silence each move on to the next server.
#[tokio::test]
async fn failing_servers_move_on_to_the_next() {
    for failing in [Some(Reply::rcode(2)), Some(Reply::default()), None] {
        let first = server(move |_, _| failing.clone()).await;
        let second = server(|_, _| Some(Reply::answers(vec![txt(&["ok"])]))).await;
        let conf = ResolvConf {
            attempts: 1,
            timeout: Duration::from_millis(300),
            ..conf(&[first.address, second.address])
        };
        assert_eq!(resolver().txt(&conf, "example.com").await.unwrap(), ["ok"]);
        assert_eq!(first.asked.lock().unwrap().len(), 1);
    }
}

/// Each server is asked `attempts` times before the lookup fails.
#[tokio::test]
async fn every_server_is_asked_attempts_times() {
    let first = server(|_, _| Some(Reply::rcode(2))).await;
    let second = server(|_, _| Some(Reply::rcode(5))).await;
    let conf = ResolvConf {
        attempts: 3,
        ..conf(&[first.address, second.address])
    };
    assert!(resolver().txt(&conf, "example.com").await.is_err());
    assert_eq!(first.asked.lock().unwrap().len(), 3);
    assert_eq!(second.asked.lock().unwrap().len(), 3);
}

/// No record of the type asked for is no such host, as in Go.
#[tokio::test]
async fn no_record_of_the_type_is_no_such_host() {
    let server = server(|_, _| Some(Reply::answers(vec![cname("alias.example.")]))).await;
    let error = resolver()
        .srv(&conf(&[server.address]), "xray", "tcp", "example.com")
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(server.asked.lock().unwrap().len(), 1);
}

/// A target that is not a domain name fails the whole lookup, as Go's
/// `LookupSRV` returns an error with the records it kept; the root, which
/// says there is no service, is a valid target.
#[tokio::test]
async fn an_invalid_srv_target_fails_the_lookup() {
    let server = server(|name, _| {
        Some(Reply::answers(if name.starts_with("_bad") {
            vec![srv(0, 0, 1, "good.example."), srv(0, 0, 2, "bad!name.")]
        } else {
            vec![srv(0, 0, 1, ".")]
        }))
    })
    .await;
    let conf = conf(&[server.address]);
    let resolver = resolver();
    assert_eq!(
        resolver
            .srv(&conf, "bad", "tcp", "example.com")
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        resolver
            .srv(&conf, "root", "tcp", "example.com")
            .await
            .unwrap(),
        [record(".", 1, 0, 0)]
    );
}

/// A name Go refuses to send is never sent.
#[tokio::test]
async fn names_go_does_not_ask_for_are_not_asked() {
    let server = server(|_, _| Some(Reply::answers(vec![txt(&["x"])]))).await;
    let conf = conf(&[server.address]);
    for name in ["bad!name.example", "hidden.onion", "a..b"] {
        assert!(resolver().txt(&conf, name).await.is_err(), "{name}");
    }
    assert!(server.asked.lock().unwrap().is_empty());
}

#[test]
fn resolv_conf_is_read_as_go_reads_it() {
    let conf = ResolvConf::parse(
        "# comment\n; comment\nnameserver 192.0.2.1\nnameserver bad\nnameserver 2001:db8::1\n\
         nameserver 192.0.2.3\r\nnameserver 192.0.2.4\ndomain ignored.example\n\
         search a.example b.example. .\noptions ndots:20 timeout:0 attempts:x rotate use-vc trust-ad edns0\n",
        || unreachable!("the file has a search list"),
    );
    assert_eq!(
        conf,
        ResolvConf {
            servers: vec![
                "192.0.2.1:53".parse().unwrap(),
                "[2001:db8::1]:53".parse().unwrap(),
                "192.0.2.3:53".parse().unwrap(),
            ],
            search: vec!["a.example.".into(), "b.example.".into()],
            ndots: 15,
            timeout: Duration::from_secs(1),
            attempts: 1,
            rotate: true,
            use_tcp: true,
            trust_ad: true,
        }
    );
    let conf = ResolvConf::parse(
        "options ndots:3x timeout:9 attempts:4 usevc\ndomain corp.example\n",
        || unreachable!("the file has a domain"),
    );
    assert_eq!(conf.servers, default_servers());
    assert_eq!(conf.search, ["corp.example."]);
    assert_eq!(
        (conf.ndots, conf.timeout, conf.attempts),
        (3, Duration::from_secs(9), 4)
    );
    assert!(conf.use_tcp);
    assert!(ResolvConf::parse("options tcp", Vec::new).use_tcp);
    // Without a search list Go takes the host name's domain.
    assert_eq!(
        ResolvConf::parse("", || vec!["host.example.".into()]).search,
        ["host.example."]
    );
}

#[test]
fn a_missing_resolv_conf_asks_the_loopback() {
    let conf = ResolvConf::read(std::path::Path::new("/nonexistent/resolv.conf"));
    assert_eq!(conf.servers, default_servers());
    assert_eq!((conf.ndots, conf.attempts), (1, 2));
    assert_eq!(conf.timeout, Duration::from_secs(5));
}

#[test]
fn a_zoned_nameserver_keeps_its_zone() {
    let Some(SocketAddr::V6(address)) = parse_nameserver("fe80::1%7") else {
        panic!("a zoned address is a nameserver");
    };
    assert_eq!(address.scope_id(), 7);
    assert_eq!(address.port(), 53);
    assert_eq!(parse_nameserver("192.0.2.1%7"), None);
    assert_eq!(parse_nameserver("fe80::1%"), None);
}

#[test]
fn the_name_list_follows_ndots_and_the_search_list() {
    let conf = ResolvConf {
        search: vec!["corp.example.".into(), "lan.".into()],
        ..ResolvConf::defaults()
    };
    assert_eq!(
        conf.name_list("_x._tcp.example.com"),
        [
            "_x._tcp.example.com.",
            "_x._tcp.example.com.corp.example.",
            "_x._tcp.example.com.lan."
        ]
    );
    assert_eq!(conf.name_list("rooted.example."), ["rooted.example."]);
    let conf = ResolvConf { ndots: 3, ..conf };
    assert_eq!(
        conf.name_list("a.b"),
        ["a.b.corp.example.", "a.b.lan.", "a.b."]
    );
    // Go withholds an onion name itself, but not the names the search list
    // makes of it.
    assert!(conf.name_list("x.onion.").is_empty());
    assert_eq!(
        conf.name_list("x.onion"),
        ["x.onion.corp.example.", "x.onion.lan."]
    );
    assert!(conf.name_list(&"a".repeat(254)).is_empty());
}

#[test]
fn domain_names_are_judged_as_go_judges_them() {
    for valid in [
        ".",
        "example.com",
        "example.com.",
        "_xray._tcp.example.com",
        "a-b.c",
        "1.example",
        "x",
    ] {
        assert!(is_domain_name(valid), "{valid}");
    }
    for invalid in [
        "",
        "1.2.3.4",
        "-a.example",
        "a-.example",
        "a..b",
        "a.b-",
        "bad!name",
        "a b",
        &"a".repeat(64),
    ] {
        assert!(!is_domain_name(invalid), "{invalid}");
    }
    // 253 bytes, and 254 with the root's dot; one more is too long.
    let longest = vec!["a".repeat(63); 4].join(".")[..253].to_owned();
    assert!(is_domain_name(&longest));
    assert!(is_domain_name(&format!("{longest}.")));
    assert!(!is_domain_name(&format!("{longest}a")));
}

#[test]
fn queries_carry_recursion_ad_and_edns_as_go_sends_them() {
    let query = build_query(0x1234, "example.com.", TYPE_SRV, false).unwrap();
    assert_eq!(
        &query[..12],
        &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]
    );
    assert_eq!(question(&query), ("example.com".into(), TYPE_SRV));
    assert_eq!(
        &query[query.len() - 11..],
        &[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]
    );
    let query = build_query(1, "example.com", TYPE_TXT, true).unwrap();
    assert_eq!(&query[2..4], &[0x01, 0x20]);
}

#[test]
fn dtoi_reads_leading_digits() {
    assert_eq!(dtoi("12x"), 12);
    assert_eq!(dtoi("x"), 0);
    assert_eq!(dtoi(""), 0);
    assert_eq!(dtoi("99999999"), 0xFF_FFFF);
}

/// Within a priority, a record is drawn by weight and moved to the front,
/// then the rest are drawn from; zero weights keep their order.
#[test]
fn records_are_shuffled_by_weight_within_each_priority() {
    let mut records = vec![
        record("c", 3, 2, 0),
        record("a", 1, 1, 10),
        record("b", 2, 1, 30),
        record("d", 4, 2, 0),
    ];
    // Sorted: a(1,10) b(1,30) c(2,0) d(2,0). Drawing 15 of 40 lands on b.
    let mut draws = vec![15].into_iter();
    sort_by_priority_weight(&mut records, |sum| {
        assert_eq!(sum, 40);
        draws.next().unwrap()
    });
    let order: Vec<&str> = records
        .iter()
        .map(|record| record.target.as_str())
        .collect();
    assert_eq!(order, ["b", "a", "c", "d"]);
    let mut records = vec![record("a", 1, 1, 10), record("b", 2, 1, 30)];
    sort_by_priority_weight(&mut records, |_| 9);
    assert_eq!(records[0].target, "a");
}
