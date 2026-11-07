use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

fn item() -> CustomItem {
    CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: Vec::new(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    }
}

fn expr(op: &str, args: Vec<CustomArg>) -> CustomExpr {
    CustomExpr {
        op: op.to_owned(),
        args,
    }
}

fn eval(op: &str, args: Vec<CustomArg>) -> Result<Value, EvalError> {
    evaluate_expr(&expr(op, args), &Context::default())
}

fn u(value: u64) -> CustomArg {
    CustomArg::U64(value)
}

fn b(bytes: &[u8]) -> CustomArg {
    CustomArg::Bytes(bytes.to_vec())
}

#[test]
fn random_bytes_keep_their_count_and_range() {
    let mut context = Context::default();
    let random = CustomItem {
        rand: 300,
        rand_range: (65, 70),
        capture: "r".to_owned(),
        ..item()
    };
    let bytes = evaluate_item(&random, &mut context).unwrap();
    assert_eq!(bytes.len(), 300);
    assert!(bytes.iter().all(|byte| (65..=70).contains(byte)));
    assert_eq!(context.vars["r"], bytes);
    // A single value, both ways round.
    let fixed = CustomItem {
        rand: 4,
        rand_range: (9, 9),
        ..item()
    };
    assert_eq!(evaluate_item(&fixed, &mut context).unwrap(), [9; 4]);
    // Any bytes of the right length match a random item.
    assert!(match_item(&random, &[0; 3], &mut context).unwrap());
    // One byte is a random item too, and both ends of a range come up.
    let narrow = CustomItem {
        rand: 1,
        rand_range: (8, 9),
        ..item()
    };
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..300 {
        let byte = evaluate_item(&narrow, &mut context).unwrap();
        assert_eq!(byte.len(), 1);
        seen.insert(byte[0]);
    }
    assert_eq!(seen, [8, 9].into());
}

#[test]
fn delays_draw_as_go_does() {
    assert_eq!(rand_between(5, 5), 5);
    assert_eq!(rand_between(5, 6), 5);
    assert_eq!(rand_between(6, 5), 5);
    for _ in 0..200 {
        // The upper end is never drawn.
        assert!((10..20).contains(&rand_between(10, 20)));
        assert!((-5..5).contains(&rand_between(-5, 5)));
    }
}

#[tokio::test(start_paused = true)]
async fn a_delay_sends_what_came_before_it_first() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let sequence = vec![
        CustomItem {
            packet: b"one".to_vec(),
            ..item()
        },
        CustomItem {
            delay: (50, 51),
            packet: b"two".to_vec(),
            ..item()
        },
    ];
    let config = HeaderCustomTcpConfig {
        clients: vec![sequence],
        servers: Vec::new(),
    };
    let handshake = tokio::spawn(async move {
        client_handshake(&mut client, &config, None, None)
            .await
            .unwrap();
        client
    });
    let mut first = [0; 3];
    server.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"one");
    let started = tokio::time::Instant::now();
    let mut second = [0; 3];
    server.read_exact(&mut second).await.unwrap();
    assert_eq!(&second, b"two");
    assert_eq!(started.elapsed(), Duration::from_millis(50));
    handshake.await.unwrap();
}

#[test]
fn ipv6_addresses_give_ports_but_no_ip4() {
    let context = Context::with_addresses(
        Some(SocketAddr::from((Ipv6Addr::LOCALHOST, 1000))),
        Some(SocketAddr::from((
            Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped(),
            2000,
        ))),
    );
    assert_eq!(context.metadata["local_port"], 1000);
    assert_eq!(context.metadata["dst_port_u16"], 1000);
    assert!(!context.metadata.contains_key("local_ip4_u32"));
    // An IPv4-mapped address counts as IPv4, as Go's To4 reads it.
    assert_eq!(context.metadata["remote_ip4_u32"], 0x0a00_0001);
    assert_eq!(context.metadata["src_ip4_u32"], 0x0a00_0001);
    assert!(Context::with_addresses(None, None).metadata.is_empty());
}

#[test]
fn arithmetic_refuses_what_go_refuses() {
    assert_eq!(
        eval("add", vec![u(u64::MAX - 1), u(1)]),
        Ok(Value::U64(u64::MAX))
    );
    assert_eq!(
        eval("add", vec![u(u64::MAX), u(1)]),
        Err(error("add overflow"))
    );
    assert_eq!(eval("sub", vec![u(1), u(2)]), Err(error("sub underflow")));
    assert_eq!(
        eval("shl", vec![u(1), u(64)]),
        Err(error("shift out of range"))
    );
    assert_eq!(
        eval("shr", vec![u(1), u(64)]),
        Err(error("shift out of range"))
    );
    assert_eq!(eval("shl", vec![u(3), u(63)]), Err(error("shl overflow")));
    assert_eq!(
        eval("xor16", vec![u(0x1_0000), u(0)]),
        Err(error("xor16 overflow"))
    );
    assert_eq!(
        eval("xor32", vec![u(0), u(0x1_0000_0000)]),
        Err(error("xor32 overflow"))
    );
    assert_eq!(eval("xor16", vec![u(1)]), Err(error("xor expects 2 args")));
    assert_eq!(
        eval("be16", vec![u(1), u(2)]),
        Err(error("be16 expects 1 arg"))
    );
    assert_eq!(
        eval("add", vec![b(b"x"), u(1)]),
        Err(error("expr value is not u64"))
    );
}

#[test]
fn byte_operations_refuse_what_go_refuses() {
    assert_eq!(
        eval("pad", vec![b(b"abc"), u(2), b(b"z")]),
        Err(error("pad target shorter than source"))
    );
    assert_eq!(
        eval("pad", vec![b(b"a"), u(4), b(b"")]),
        Err(error("pad fill must not be empty"))
    );
    assert_eq!(
        eval("pad", vec![b(b"a"), u(MAX_ITEM as u64 + 1), b(b"z")]),
        Err(error("pad target too large"))
    );
    assert_eq!(
        eval("truncate", vec![b(b"ab"), u(3)]),
        Err(error("truncate out of bounds"))
    );
    // An offset and length that wrap past u64 do not slice backwards.
    assert_eq!(
        eval("slice", vec![b(b"abc"), u(u64::MAX), u(2)]),
        Err(error("slice out of bounds"))
    );
    assert_eq!(
        eval("concat", vec![u(1)]),
        Err(error("expr value is not bytes"))
    );
    assert_eq!(
        eval("slice", vec![b(b"abc")]),
        Err(error("slice expects 3 args"))
    );
}

#[test]
fn measuring_follows_go() {
    let mut sizes = HashMap::new();
    let concat = CustomItem {
        transform: Some(expr("concat", vec![b(b"ab"), CustomArg::Reuse("x".into())])),
        capture: "y".to_owned(),
        ..item()
    };
    assert_eq!(
        measure_item(&concat, &mut sizes),
        Err(error("unknown variable: x"))
    );
    sizes.insert("x".to_owned(), 3);
    assert_eq!(measure_item(&concat, &mut sizes), Ok(5));
    assert_eq!(sizes["y"], 5);
    let sliced = CustomItem {
        transform: Some(expr(
            "slice",
            vec![b(b"abc"), u(0), CustomArg::Reuse("x".into())],
        )),
        ..item()
    };
    assert_eq!(
        measure_item(&sliced, &mut sizes),
        Err(error("slice length must be u64"))
    );
    let meta = CustomItem {
        transform: Some(expr(
            "concat",
            vec![CustomArg::Metadata("local_port".into())],
        )),
        ..item()
    };
    assert_eq!(
        measure_item(&meta, &mut sizes),
        Err(error("metadata not implemented: local_port"))
    );
    assert_eq!(measure_item(&item(), &mut sizes), Ok(0));
}

#[tokio::test]
async fn items_past_a_mebibyte_fail_sent_or_read() {
    // A capture that doubles at every step: 64 KiB, then up to 2 MiB.
    let mut client = vec![CustomItem {
        rand: 65536,
        capture: "v".to_owned(),
        ..item()
    }];
    for _ in 0..5 {
        client.push(CustomItem {
            transform: Some(expr(
                "concat",
                vec![CustomArg::Reuse("v".into()), CustomArg::Reuse("v".into())],
            )),
            capture: "v".to_owned(),
            ..item()
        });
    }
    let config = HeaderCustomTcpConfig {
        clients: vec![client],
        servers: vec![],
    };
    let (mut stream, _peer) = tokio::io::duplex(1 << 23);
    let error = client_handshake(&mut stream, &config, None, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds 1 MiB"), "{error}");
    // A server item measured one byte past it.
    let config = HeaderCustomTcpConfig {
        clients: vec![],
        servers: vec![vec![CustomItem {
            transform: Some(expr("truncate", vec![b(b"a"), u((1 << 20) + 1)])),
            ..item()
        }]],
    };
    let (mut stream, peer) = tokio::io::duplex(64);
    drop(peer);
    let error = client_handshake(&mut stream, &config, None, None)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exceeds 1 MiB"), "{error}");
}
