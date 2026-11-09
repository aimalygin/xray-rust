//! What Xray-core's own `connectip` package writes and reads
//! (`tools/masque-oracle`), checked against this one. `XRAY_MASQUE_VECTORS`
//! names a fresh, larger run.
use std::net::IpAddr;

use serde_json::Value;

use super::capsule::{self, AssignedAddress, Capsule, CapsuleParser, IpPrefix, IpRoute, Parsed};
use super::packet::{self, Destinations, IcmpError};
use super::session;

fn vectors() -> Value {
    let text = match std::env::var("XRAY_MASQUE_VECTORS") {
        Ok(path) => std::fs::read_to_string(path).unwrap(),
        Err(_) => {
            include_str!("../../../../tests/fixtures/masque/connectip-vectors.json").to_owned()
        }
    };
    serde_json::from_str(&text).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn prefix(text: &str) -> IpPrefix {
    let (addr, len) = text.split_once('/').unwrap();
    IpPrefix::new(addr.parse().unwrap(), len.parse().unwrap())
}

fn entries(case: &Value) -> Vec<AssignedAddress> {
    case.as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|entry| AssignedAddress {
            request_id: entry["requestId"].as_u64().unwrap(),
            prefix: prefix(entry["prefix"].as_str().unwrap()),
        })
        .collect()
}

fn routes(case: &Value) -> Vec<IpRoute> {
    case.as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|route| IpRoute {
            start: route["start"].as_str().unwrap().parse::<IpAddr>().unwrap(),
            end: route["end"].as_str().unwrap().parse::<IpAddr>().unwrap(),
            protocol: route["protocol"].as_u64().unwrap() as u8,
        })
        .collect()
}

#[test]
fn capsules_are_written_as_xray_writes_them() {
    let vectors = vectors();
    for case in vectors["encode"].as_array().unwrap() {
        let entries = entries(&case["entries"]);
        let bytes = match case["kind"].as_str().unwrap() {
            "request" => capsule::address_request(&entries),
            _ => capsule::address_assign(&entries),
        };
        assert_eq!(to_hex(&bytes), case["bytes"].as_str().unwrap(), "{case}");
    }
}

#[test]
fn capsules_are_read_as_xray_reads_them() {
    let vectors = vectors();
    for case in vectors["parse"].as_array().unwrap() {
        let kind = case["kind"].as_u64().unwrap();
        let value = hex(case["value"].as_str().unwrap());
        let mut stream = bytes::BytesMut::new();
        capsule::put_varint(&mut stream, kind);
        capsule::put_varint(&mut stream, value.len() as u64);
        stream.extend_from_slice(&value);
        let mut parser = CapsuleParser::default();
        parser.push(&stream[..]);
        match parser.next() {
            Err(error) => {
                assert!(case["error"].as_bool().unwrap_or(false), "{case}: {error}");
                assert_eq!(
                    error.limit,
                    case["limit"].as_bool().unwrap_or(false),
                    "{case}"
                );
            }
            Ok(Some(Parsed::Capsule(parsed))) => {
                assert!(
                    !case["error"].as_bool().unwrap_or(false),
                    "{case}: {parsed:?}"
                );
                match parsed {
                    Capsule::AddressAssign(got) | Capsule::AddressRequest(got) => {
                        assert_eq!(got, entries(&case["entries"]), "{case}")
                    }
                    Capsule::RouteAdvertisement(got) => {
                        assert_eq!(got, routes(&case["routes"]), "{case}")
                    }
                    Capsule::Datagram(_) => panic!("{case}"),
                }
            }
            other => panic!("{case}: {other:?}"),
        }
    }
}

#[test]
fn datagrams_are_composed_as_xray_composes_them() {
    let vectors = vectors();
    let (mut quic, mut capsules, mut bare) = (0, 0, 0);
    for case in vectors["compose"].as_array().unwrap() {
        let packet = hex(case["packet"].as_str().unwrap());
        let out = if case["capsule"].as_bool().unwrap() {
            // HTTP/2: a whole DATAGRAM capsule, bare without the context ID.
            let is_bare = case["bare"].as_bool().unwrap();
            if is_bare {
                bare += 1;
            } else {
                capsules += 1;
            }
            session::datagram_capsule(&packet, is_bare).map(|capsule| capsule.to_vec())
        } else {
            // HTTP/3 datagrams: the context ID, then the packet.
            quic += 1;
            let mut packet = packet;
            packet::prepare_outgoing(&mut packet).ok().map(|()| {
                let mut out = vec![0];
                out.extend_from_slice(&packet);
                out
            })
        };
        match out {
            Some(out) => assert_eq!(to_hex(&out), case["out"].as_str().unwrap(), "{case}"),
            None => assert!(case["dropped"].as_bool().unwrap_or(false), "{case}"),
        }
    }
    assert!(quic > 0 && capsules > 0 && bare > 0);
}

#[test]
fn capsule_datagrams_are_read_as_xray_reads_them() {
    let vectors = vectors();
    let everything = Destinations {
        assigned: vec![prefix("0.0.0.0/0"), prefix("::/0")],
        ..Destinations::default()
    };
    let (mut read, mut dropped) = (0, 0);
    for case in vectors["read"].as_array().unwrap() {
        let datagram = bytes::Bytes::from(hex(case["datagram"].as_str().unwrap()));
        let packet = session::datagram_packet(datagram, case["bare"].as_bool().unwrap())
            .filter(|packet| packet::check_incoming(packet, &everything).is_ok());
        match packet {
            Some(packet) => {
                read += 1;
                assert_eq!(to_hex(&packet), case["packet"].as_str().unwrap(), "{case}")
            }
            None => {
                dropped += 1;
                assert!(case["dropped"].as_bool().unwrap_or(false), "{case}")
            }
        }
    }
    assert!(read > 0 && dropped > 0);
}

#[test]
fn icmp_too_large_is_xrays_byte_for_byte() {
    let vectors = vectors();
    for case in vectors["icmp"].as_array().unwrap() {
        let packet = hex(case["packet"].as_str().unwrap());
        let mtu = case["mtu"].as_u64().unwrap() as usize;
        match packet::icmp_too_large(&packet, mtu) {
            Ok(icmp) => assert_eq!(to_hex(&icmp), case["out"].as_str().unwrap(), "{case}"),
            Err(IcmpError::MtuTooSmall(_)) => {
                assert!(case["tooSmall"].as_bool().unwrap_or(false), "{case}")
            }
            Err(IcmpError::Malformed(_)) => {
                assert!(case["error"].as_bool().unwrap_or(false), "{case}")
            }
        }
    }
}

#[test]
fn incoming_packets_are_admitted_as_xray_admits_them() {
    let vectors = vectors();
    for case in vectors["incoming"].as_array().unwrap() {
        let packet = hex(case["packet"].as_str().unwrap());
        let allowed = Destinations {
            assigned: case["assigned"]
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_default()
                .iter()
                .map(|p| prefix(p.as_str().unwrap()))
                .collect(),
            local_routes: routes(&case["routes"]),
            peer: case["peer"]
                .as_array()
                .map(|peer| peer.iter().map(|p| prefix(p.as_str().unwrap())).collect()),
        };
        assert_eq!(
            packet::check_incoming(&packet, &allowed).is_ok(),
            case["allowed"].as_bool().unwrap(),
            "{case}"
        );
    }
}
