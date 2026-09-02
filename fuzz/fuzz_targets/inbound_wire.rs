#![no_main]

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Builder;
use xray_proxy::inbound::{
    encode_socks5_udp_datagram, parse_http_connect, parse_socks5_request_message,
    parse_socks5_udp_datagram,
};

fuzz_target!(|data: &[u8]| {
    let runtime = Builder::new_current_thread()
        .build()
        .expect("construct fuzz runtime");
    runtime.block_on(async {
        let mut socks_reader = data;
        let _ = parse_socks5_request_message(&mut socks_reader).await;

        let mut http_reader = data;
        let _ = parse_http_connect(&mut http_reader).await;

        if let Ok(datagram) = parse_socks5_udp_datagram(data) {
            let _ = encode_socks5_udp_datagram(&datagram.target, &datagram.payload);
        }

        // Reach successful domain parsing on every bounded campaign.
        let domain = data
            .iter()
            .take(63)
            .map(|byte| b'a' + byte % 26)
            .collect::<Vec<_>>();
        let domain = if domain.is_empty() {
            b"a".as_slice()
        } else {
            domain.as_slice()
        };

        let mut valid_socks = vec![5, 1, 0, 3, domain.len() as u8];
        valid_socks.extend_from_slice(domain);
        valid_socks.extend_from_slice(&443_u16.to_be_bytes());
        let mut valid_socks_reader = valid_socks.as_slice();
        if let Ok(request) = parse_socks5_request_message(&mut valid_socks_reader).await {
            let mut valid_datagram = vec![0, 0, 0, 3, domain.len() as u8];
            valid_datagram.extend_from_slice(domain);
            valid_datagram.extend_from_slice(&53_u16.to_be_bytes());
            valid_datagram.extend_from_slice(data);
            if let Ok(datagram) = parse_socks5_udp_datagram(&valid_datagram) {
                let _ = encode_socks5_udp_datagram(&datagram.target, &datagram.payload);
            }
            let _ = request;
        }

        let valid_http = format!(
            "CONNECT {}.test:443 HTTP/1.1\r\nHost: {}.test:443\r\n\r\n",
            String::from_utf8_lossy(domain),
            String::from_utf8_lossy(domain)
        );
        let mut valid_http_reader = valid_http.as_bytes();
        let _ = parse_http_connect(&mut valid_http_reader).await;
    });
});
