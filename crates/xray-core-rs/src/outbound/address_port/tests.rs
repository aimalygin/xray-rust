use super::*;
use std::sync::Mutex;
use xray_transport::SrvRecord;

/// Answers lookups from fixed records, recording what is asked.
#[derive(Default)]
struct Records {
    srv: Option<Vec<SrvRecord>>,
    txt: Option<Vec<String>>,
    asked: Mutex<Vec<String>>,
}

#[async_trait::async_trait]
impl RecordResolver for Records {
    async fn lookup_srv(
        &self,
        service: &str,
        proto: &str,
        name: &str,
    ) -> std::io::Result<Vec<SrvRecord>> {
        self.asked
            .lock()
            .unwrap()
            .push(format!("srv {service} {proto} {name}"));
        self.srv
            .clone()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
    }

    async fn lookup_txt(&self, name: &str) -> std::io::Result<Vec<String>> {
        self.asked.lock().unwrap().push(format!("txt {name}"));
        self.txt
            .clone()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
    }
}

fn srv(target: &str, port: u16) -> SrvRecord {
    SrvRecord {
        target: target.into(),
        port,
        priority: 0,
        weight: 0,
    }
}

fn server(domain: &str) -> Target {
    Target::new(
        RoutingTargetAddr::Domain(domain.into()),
        443,
        RoutingNetwork::Tcp,
    )
}

fn domain(name: &str, port: u16) -> Target {
    Target::new(
        RoutingTargetAddr::Domain(name.into()),
        port,
        RoutingNetwork::Tcp,
    )
}

#[tokio::test]
async fn srv_records_replace_the_address_the_port_or_both() {
    let records = Records {
        srv: Some(vec![srv("server.example", 8443), srv("later.example", 1)]),
        ..Records::default()
    };
    let name = "_xray._tcp.example.com";
    for (strategy, expected) in [
        (
            AddressPortStrategy::SrvPortAndAddress,
            domain("server.example", 8443),
        ),
        (AddressPortStrategy::SrvPortOnly, domain(name, 8443)),
        (
            AddressPortStrategy::SrvAddressOnly,
            domain("server.example", 443),
        ),
    ] {
        assert_eq!(
            redirect(strategy, &server(name), &records).await,
            Some(expected),
            "{strategy:?}"
        );
    }
    assert_eq!(
        *records.asked.lock().unwrap(),
        ["srv xray tcp example.com"; 3]
    );
}

/// Xray-core drops the first byte of the first two parts, whatever it is,
/// and needs three parts. An empty first or second part panics there; here
/// the configured server is dialed.
#[tokio::test]
async fn the_srv_name_is_cut_as_xray_core_cuts_it() {
    let records = Records {
        srv: Some(vec![srv("server.example", 1)]),
        ..Records::default()
    };
    let strategy = AddressPortStrategy::SrvPortAndAddress;
    assert!(
        redirect(strategy, &server("xray.tcp.example.com"), &records)
            .await
            .is_some()
    );
    assert!(redirect(strategy, &server("x.y.example"), &records)
        .await
        .is_some());
    for unusable in ["example.com", ".tcp.example.com", "_x..example"] {
        assert_eq!(redirect(strategy, &server(unusable), &records).await, None);
    }
    assert_eq!(
        *records.asked.lock().unwrap(),
        ["srv ray cp example.com", "srv   example"]
    );
}

/// The first record that reads as `host:port` with a valid port wins.
#[tokio::test]
async fn txt_records_give_the_first_host_and_port_that_read() {
    let records = Records {
        txt: Some(vec![
            "no port".into(),
            "host:x".into(),
            "host:65536".into(),
            "[2001:db8::1]:0443".into(),
            "later.example:1".into(),
        ]),
        ..Records::default()
    };
    let name = "txt.example";
    for (strategy, expected) in [
        (
            AddressPortStrategy::TxtPortAndAddress,
            Target::new(
                RoutingTargetAddr::Ip("2001:db8::1".parse().unwrap()),
                443,
                RoutingNetwork::Tcp,
            ),
        ),
        (AddressPortStrategy::TxtPortOnly, domain(name, 443)),
        (
            AddressPortStrategy::TxtAddressOnly,
            Target::new(
                RoutingTargetAddr::Ip("2001:db8::1".parse().unwrap()),
                443,
                RoutingNetwork::Tcp,
            ),
        ),
    ] {
        assert_eq!(
            redirect(strategy, &server(name), &records).await,
            Some(expected),
            "{strategy:?}"
        );
    }
    assert_eq!(*records.asked.lock().unwrap(), ["txt txt.example"; 3]);
}

/// No lookup for `none` or an IP server; a failed lookup or no usable
/// record dials the configured server.
#[tokio::test]
async fn the_configured_server_stays_without_a_usable_record() {
    let none = Records::default();
    let unusable = Records {
        txt: Some(vec!["host".into(), ":".into()]),
        srv: Some(Vec::new()),
        ..Records::default()
    };
    let ip = Target::new(
        RoutingTargetAddr::Ip("192.0.2.1".parse().unwrap()),
        443,
        RoutingNetwork::Tcp,
    );
    assert_eq!(
        redirect(AddressPortStrategy::None, &server("x.example"), &none).await,
        None
    );
    assert_eq!(
        redirect(AddressPortStrategy::TxtPortAndAddress, &ip, &none).await,
        None
    );
    assert!(none.asked.lock().unwrap().is_empty());
    for strategy in [
        AddressPortStrategy::TxtPortAndAddress,
        AddressPortStrategy::SrvPortAndAddress,
    ] {
        let name = server("_a._b.example");
        assert_eq!(redirect(strategy, &name, &none).await, None);
        assert_eq!(redirect(strategy, &name, &unusable).await, None);
    }
}

#[test]
fn host_and_port_split_as_go_splits_them() {
    for (text, expected) in [
        ("host:80", Some(("host", "80"))),
        ("192.0.2.1:80", Some(("192.0.2.1", "80"))),
        ("[2001:db8::1]:80", Some(("2001:db8::1", "80"))),
        (":80", Some(("", "80"))),
        ("host:", Some(("host", ""))),
        ("host", None),
        ("2001:db8::1:80", None),
        ("[2001:db8::1]", None),
        ("[2001:db8::1]x:80", None),
        ("[a]:80]", None),
        ("a]:80", None),
        ("a[:80", None),
        ("[a:80", None),
    ] {
        assert_eq!(split_host_port(text), expected, "{text}");
    }
}

#[test]
fn ports_read_as_xray_core_reads_them() {
    for (text, expected) in [
        ("443", Some(443)),
        ("0443", Some(443)),
        ("0", Some(0)),
        ("000", Some(0)),
        ("65535", Some(65535)),
        ("65536", None),
        ("99999999999", None),
        ("", None),
        ("+443", None),
        ("-1", None),
        ("4 4", None),
    ] {
        assert_eq!(parse_port(text), expected, "{text}");
    }
}

#[test]
fn addresses_read_as_xray_core_reads_them() {
    let ip = |text: &str| RoutingTargetAddr::Ip(text.parse().unwrap());
    for (text, expected) in [
        ("192.0.2.1", ip("192.0.2.1")),
        ("[2001:db8::1]", ip("2001:db8::1")),
        ("::ffff:192.0.2.1", ip("192.0.2.1")),
        (" 192.0.2.1 ", ip("192.0.2.1")),
        (
            "Server.Example",
            RoutingTargetAddr::Domain("Server.Example".into()),
        ),
        (
            " server.example",
            RoutingTargetAddr::Domain("server.example".into()),
        ),
        (
            "server.example.",
            RoutingTargetAddr::Domain("server.example.".into()),
        ),
    ] {
        assert_eq!(parse_address(text), expected, "{text}");
    }
}

/// The candidates come from the address and port the lookup gave, and from
/// the configured server when it gives none.
#[tokio::test]
async fn resolve_server_dials_what_the_lookup_gave() {
    struct Loopback;
    #[async_trait::async_trait]
    impl DnsResolver for Loopback {
        async fn resolve(&self, domain: &str, port: u16) -> Result<SocketAddr, TransportError> {
            match domain {
                "server.example" => Ok(SocketAddr::from(([127, 0, 0, 2], port))),
                "_xray._tcp.example.com" => Ok(SocketAddr::from(([127, 0, 0, 3], port))),
                _ => Err(TransportError::DnsNoData(domain.to_owned(), port)),
            }
        }
    }
    let records = Arc::new(Records {
        srv: Some(vec![srv("server.example", 8443)]),
        ..Records::default()
    });
    let dialer = TransportDialer::system()
        .unwrap()
        .with_record_resolver(records.clone());
    let name = server("_xray._tcp.example.com");
    assert_eq!(
        resolve_server(
            &name,
            AddressPortStrategy::SrvPortAndAddress,
            &Loopback,
            &dialer
        )
        .await
        .unwrap(),
        [SocketAddr::from(([127, 0, 0, 2], 8443))]
    );
    assert_eq!(
        resolve_server(
            &name,
            AddressPortStrategy::TxtPortAndAddress,
            &Loopback,
            &dialer
        )
        .await
        .unwrap(),
        [SocketAddr::from(([127, 0, 0, 3], 443))]
    );
    assert_eq!(
        resolve_server(&name, AddressPortStrategy::None, &Loopback, &dialer)
            .await
            .unwrap(),
        [SocketAddr::from(([127, 0, 0, 3], 443))]
    );
    assert_eq!(records.asked.lock().unwrap().len(), 2);
}
