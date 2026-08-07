mod stream_http_headers_tests {
    use xray_transport::stream::{serialize_request, HeaderMap};

    #[test]
    fn host_and_user_agent_lead_then_case_sensitive_key_order() {
        let mut headers = HeaderMap::new();
        headers.set("Upgrade", "websocket");
        headers.set("Sec-Fetch-Mode", "websocket");
        headers.set("Sec-CH-UA-Mobile", "?0");
        headers.set("DNT", "1");
        headers.set("Connection", "Upgrade");
        headers.set("User-Agent", "TestAgent/1.0");

        let request = serialize_request("GET", "/chat", "example.com", &headers);

        assert_eq!(
            String::from_utf8(request).expect("the request must be UTF-8"),
            concat!(
                "GET /chat HTTP/1.1\r\n",
                "Host: example.com\r\n",
                "User-Agent: TestAgent/1.0\r\n",
                "Connection: Upgrade\r\n",
                "DNT: 1\r\n",
                "Sec-CH-UA-Mobile: ?0\r\n",
                "Sec-Fetch-Mode: websocket\r\n",
                "Upgrade: websocket\r\n",
                "\r\n",
            )
        );
    }

    #[test]
    fn key_order_is_case_sensitive_not_alphabetical() {
        // Go compares the literal map keys byte-wise, so every uppercase letter
        // sorts before every lowercase one. A case-insensitive sort would put
        // `Sec-ch-ua` first; Go puts it last.
        let mut headers = HeaderMap::new();
        headers.set("Sec-ch-ua", "lower");
        headers.set("Sec-CH-UA", "upper");

        let request = serialize_request("GET", "/", "h", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");
        let upper = text.find("Sec-CH-UA:").expect("upper key must be present");
        let lower = text.find("Sec-ch-ua:").expect("lower key must be present");

        assert!(upper < lower, "uppercase keys sort first:\n{text}");
    }

    #[test]
    fn a_header_set_twice_keeps_one_value() {
        let mut headers = HeaderMap::new();
        headers.set("X-Thing", "first");
        headers.set("X-Thing", "second");

        let request = serialize_request("GET", "/", "h", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");

        assert_eq!(text.matches("X-Thing:").count(), 1, "{text}");
        assert!(text.contains("X-Thing: second"), "{text}");
    }

    #[test]
    fn absent_user_agent_is_not_emitted() {
        let mut headers = HeaderMap::new();
        headers.set("Upgrade", "websocket");

        let request = serialize_request("GET", "/", "example.com", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");

        assert!(!text.contains("User-Agent"), "{text}");
        assert!(
            text.starts_with("GET / HTTP/1.1\r\nHost: example.com\r\n"),
            "{text}"
        );
    }
}
