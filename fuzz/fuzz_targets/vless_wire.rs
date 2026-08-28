#![no_main]

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Builder;
use xray_proxy::vless::{
    encode_udp_packet, encode_xudp_keep_packet, read_udp_packet, read_xudp_packet,
    unpad_vision_block,
};

fuzz_target!(|data: &[u8]| {
    let mut user_id = [0_u8; 16];
    let copied = data.len().min(user_id.len());
    user_id[..copied].copy_from_slice(&data[..copied]);
    let wire = data.get(copied..).unwrap_or_default();

    let _ = unpad_vision_block(wire, &user_id);

    let runtime = Builder::new_current_thread()
        .build()
        .expect("construct fuzz runtime");
    runtime.block_on(async {
        let mut udp = wire;
        let _ = read_udp_packet(&mut udp).await;

        let mut xudp = wire;
        let _ = read_xudp_packet(&mut xudp).await;

        // Exercise successful framing on every bounded smoke invocation as
        // well as the malformed raw-input paths above.
        if let Ok(frame) = encode_udp_packet(wire) {
            let mut encoded = frame.as_slice();
            let _ = read_udp_packet(&mut encoded).await;
        }
        if let Ok(frame) = encode_xudp_keep_packet(None, wire) {
            let mut encoded = frame.as_slice();
            let _ = read_xudp_packet(&mut encoded).await;
        }
    });

    if wire.len() <= u16::MAX as usize {
        let command = data.first().copied().unwrap_or_default() % 3;
        let mut valid_vision = Vec::with_capacity(21 + wire.len());
        valid_vision.extend_from_slice(&user_id);
        valid_vision.push(command);
        valid_vision.extend_from_slice(&(wire.len() as u16).to_be_bytes());
        valid_vision.extend_from_slice(&0_u16.to_be_bytes());
        valid_vision.extend_from_slice(wire);
        let _ = unpad_vision_block(&valid_vision, &user_id);
    }
});
