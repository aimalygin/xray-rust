#![no_main]

use libfuzzer_sys::fuzz_target;
use tokio::io::AsyncReadExt;
use tokio::runtime::Builder;
use xray_transport::stream::xhttp_h1_test_only::PendingResponse;

const FUZZ_HEAD_LIMIT: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    let runtime = Builder::new_current_thread()
        .build()
        .expect("construct fuzz runtime");
    runtime.block_on(async {
        let mut raw_reader = data;
        if let Ok(pending) =
            PendingResponse::new(&mut raw_reader).with_response_head_limit(FUZZ_HEAD_LIMIT)
        {
            if let Ok(mut body) = pending.open().await {
                let mut decoded = Vec::new();
                let _ = body.read_to_end(&mut decoded).await;
            }
        }

        // Reach successful Content-Length and chunked decoding on every run.
        let payload = &data[..data.len().min(4096)];
        let mut fixed = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
            payload.len()
        )
        .into_bytes();
        fixed.extend_from_slice(payload);
        let mut fixed_reader = fixed.as_slice();
        if let Ok(mut body) = PendingResponse::new(&mut fixed_reader).open().await {
            let mut decoded = Vec::new();
            let _ = body.read_to_end(&mut decoded).await;
        }

        let mut chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        chunked.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
        chunked.extend_from_slice(payload);
        chunked.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut chunked_reader = chunked.as_slice();
        if let Ok(mut body) = PendingResponse::new(&mut chunked_reader).open().await {
            let mut decoded = Vec::new();
            let _ = body.read_to_end(&mut decoded).await;
        }
    });
});
