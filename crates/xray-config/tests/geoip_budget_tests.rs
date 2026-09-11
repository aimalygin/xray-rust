use std::{
    fs,
    net::{IpAddr, Ipv6Addr},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use prost::Message;
use serde_json::json;
use xray_config::parse_xray_json_with_geodata_dirs;

// Loyalsoldier's 202609082347 snapshot has this many CIDRs in geoip:us.
// Generate documentation-only addresses instead of checking in that database.
const LARGE_COUNTRY_CIDRS: usize = 300_531;

#[test]
fn large_geoip_category_can_be_used_by_two_routing_rules() {
    let fixture = GeoIpFixture::new(LARGE_COUNTRY_CIDRS);
    let parsed =
        parse_xray_json_with_geodata_dirs(&routing_config(2), std::slice::from_ref(&fixture.dir))
            .expect("a US-sized category should fit both routing rules");

    assert_eq!(parsed.config.routing.rules.len(), 2);
    assert!(parsed.diagnostics.is_empty());
    for rule in &parsed.config.routing.rules {
        assert!(rule.matches_ip(Some(&IpAddr::V6(documentation_ip(0)))));
        assert!(rule.matches_ip(Some(&IpAddr::V6(documentation_ip(LARGE_COUNTRY_CIDRS - 1)))));
        assert!(!rule.matches_ip(Some(&IpAddr::V6(documentation_ip(LARGE_COUNTRY_CIDRS)))));
        assert!(!rule.matches_ip(Some(&IpAddr::V6("2001:db8::1".parse().unwrap()))));
    }
}

#[test]
fn repeated_large_geoip_categories_still_exhaust_the_config_budget() {
    let fixture = GeoIpFixture::new(LARGE_COUNTRY_CIDRS);
    let error =
        parse_xray_json_with_geodata_dirs(&routing_config(3), std::slice::from_ref(&fixture.dir))
            .expect_err("three US-sized expansions exceed the 750,000-IP budget");

    assert!(
        error.diagnostics.iter().any(|diagnostic| {
            diagnostic.path.as_deref() == Some("$.routing.rules[2].ip[0]")
                && diagnostic.message.contains("IP matchers")
                && diagnostic.message.contains("148938 slots remain")
        }),
        "{error:?}"
    );
}

#[test]
fn geoip_category_above_the_cidr_limit_is_rejected() {
    let fixture = GeoIpFixture::new(500_001);
    let error =
        parse_xray_json_with_geodata_dirs(&routing_config(1), std::slice::from_ref(&fixture.dir))
            .expect_err("the per-category CIDR ceiling must still be enforced");

    assert!(
        error.diagnostics.iter().any(|diagnostic| {
            diagnostic.path.as_deref() == Some("$.routing.rules[0].ip[0]")
                && diagnostic.message.contains("more than 500000 CIDRs")
        }),
        "{error:?}"
    );
}

fn routing_config(rule_count: usize) -> String {
    let inbounds = (0..rule_count)
        .map(|index| {
            json!({
                "tag": format!("in-{index}"), "protocol": "socks",
                "listen": "127.0.0.1", "port": 1080 + index
            })
        })
        .collect::<Vec<_>>();
    let rules = (0..rule_count)
        .map(|index| {
            json!({
                "type": "field", "inboundTag": [format!("in-{index}")],
                "ip": ["geoip:large"], "outboundTag": "direct"
            })
        })
        .collect::<Vec<_>>();
    json!({
        "inbounds": inbounds,
        "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        "routing": {"rules": rules}
    })
    .to_string()
}

fn documentation_ip(index: usize) -> Ipv6Addr {
    let mut address = [0u8; 16];
    address[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    // Leave holes so the compiled matcher cannot merge the whole category.
    address[8..].copy_from_slice(&(index as u64 * 2).to_be_bytes());
    Ipv6Addr::from(address)
}

struct GeoIpFixture {
    dir: PathBuf,
}

impl GeoIpFixture {
    fn new(cidr_count: usize) -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("xray-geoip-budget-{}-{stamp}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        let fixture = Self { dir };
        let body = Country {
            code: "LARGE".to_owned(),
            cidr: (0..cidr_count)
                .map(|index| Cidr {
                    ip: documentation_ip(index).octets().to_vec(),
                    prefix: 128,
                })
                .collect(),
        }
        .encode_to_vec();
        // GeoIPList.entry is a length-delimited protobuf field, as in the real snapshot.
        let mut data = vec![0x0a];
        let mut length = body.len() as u64;
        while length >= 0x80 {
            data.push(length as u8 | 0x80);
            length >>= 7;
        }
        data.push(length as u8);
        data.extend_from_slice(&body);
        fs::write(fixture.dir.join("geoip.dat"), data).unwrap();
        fixture
    }
}

impl Drop for GeoIpFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[derive(Clone, PartialEq, Message)]
struct Country {
    #[prost(string, tag = "1")]
    code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
}

#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes = "vec", tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}
