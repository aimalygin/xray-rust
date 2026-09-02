#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use tokio::runtime::Builder;
use xray_tun::{TunConfig, TunEndpoint};

fuzz_target!(|data: &[u8]| {
    let mtu = usize::from(data.first().copied().unwrap_or_default()).max(1) * 32;
    let queue_depth = usize::from(data.get(1).copied().unwrap_or_default() % 8).max(1);
    let endpoint = TunEndpoint::new(TunConfig { mtu, queue_depth });
    let split = data.len() / 2;

    let runtime = Builder::new_current_thread()
        .build()
        .expect("construct fuzz runtime");
    runtime.block_on(async {
        let _ = endpoint
            .push_inbound(Bytes::copy_from_slice(&data[..split]))
            .await;
        let _ = endpoint
            .push_outbound(Bytes::copy_from_slice(&data[split..]))
            .await;
        let _ = endpoint.try_poll_inbound().await;
        let _ = endpoint.try_poll_outbound().await;
        let _ = endpoint.stats().await;

        endpoint.close();
        let _ = endpoint.push_inbound(Bytes::new()).await;
        let _ = endpoint.push_outbound(Bytes::new()).await;
    });
});
