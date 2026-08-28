#![no_main]

use libfuzzer_sys::fuzz_target;
use xray_core_rs::{build_return_response, parse_dns_query, CompiledDnsOutboundPolicy};

fuzz_target!(|data: &[u8]| {
    let policy = CompiledDnsOutboundPolicy::default();
    let own_link = data.first().is_some_and(|byte| byte & 1 != 0);
    let r_code = data.get(1).copied().unwrap_or_default() as u16;
    let message = data.get(2..).unwrap_or_default();

    let _ = parse_dns_query(message);
    let _ = policy.decide_message(message, own_link);
    let _ = build_return_response(message, r_code);

    // Also drive the complete-query paths on every invocation so the bounded
    // RC smoke does not depend on mutating a raw seed into a valid DNS packet.
    let id = u16::from_be_bytes([
        data.get(2).copied().unwrap_or_default(),
        data.get(3).copied().unwrap_or_default(),
    ]);
    let qtype = u16::from_be_bytes([
        data.get(4).copied().unwrap_or_default(),
        data.get(5).copied().unwrap_or(1),
    ]);
    let mut label = data
        .get(6..)
        .unwrap_or_default()
        .iter()
        .take(63)
        .map(|byte| b'a' + byte % 26)
        .collect::<Vec<_>>();
    if label.is_empty() {
        label.push(b'a');
    }
    let mut valid = Vec::with_capacity(18 + label.len());
    valid.extend_from_slice(&id.to_be_bytes());
    valid.extend_from_slice(&0x0100_u16.to_be_bytes());
    valid.extend_from_slice(&1_u16.to_be_bytes());
    valid.extend_from_slice(&[0; 6]);
    valid.push(label.len() as u8);
    valid.extend_from_slice(&label);
    valid.push(0);
    valid.extend_from_slice(&qtype.to_be_bytes());
    valid.extend_from_slice(&1_u16.to_be_bytes());

    let _ = parse_dns_query(&valid);
    let _ = policy.decide_message(&valid, own_link);
    let _ = build_return_response(&valid, r_code & 0x0f);
});
