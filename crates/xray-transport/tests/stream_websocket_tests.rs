mod stream_websocket_tests {
    use xray_transport::stream::{
        encode_client_frames, FrameDecoder, FrameEvent, MAX_FRAME_PAYLOAD,
    };

    fn unmask(payload: &mut [u8], key: [u8; 4]) {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }

    /// Builds a server-to-client frame: never masked, which is what the RFC
    /// requires of a server and what the decoder insists on.
    fn server_frame(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 | opcode } else { opcode }];
        let length = payload.len();
        if length < 126 {
            out.push(length as u8);
        } else if let Ok(length) = u16::try_from(length) {
            out.push(126);
            out.extend_from_slice(&length.to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(length as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn a_small_write_is_one_masked_binary_frame() {
        let frames = encode_client_frames(b"hello");

        assert_eq!(frames[0], 0x82, "FIN set, opcode 0x2 (binary)");
        assert_eq!(frames[1], 0x80 | 5, "mask bit set, 5-byte payload");

        let key = [frames[2], frames[3], frames[4], frames[5]];
        let mut payload = frames[6..].to_vec();
        unmask(&mut payload, key);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn an_eight_kib_write_becomes_two_fragments_of_4096() {
        let payload = vec![0x41u8; 8192];
        let frames = encode_client_frames(&payload);

        // First fragment: FIN clear, opcode binary, 126 -> 16-bit length.
        assert_eq!(frames[0], 0x02, "FIN clear on the first fragment");
        assert_eq!(frames[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([frames[2], frames[3]]), 4096);

        let second = 4 + 4 + 4096;
        assert_eq!(frames[second], 0x80, "FIN set, opcode 0x0 (continuation)");
        assert_eq!(frames[second + 1], 0x80 | 126);
        assert_eq!(
            u16::from_be_bytes([frames[second + 2], frames[second + 3]]),
            4096
        );
        assert_eq!(frames.len(), second + 4 + 4 + 4096);
    }

    #[test]
    fn the_fragment_size_matches_gorillas_write_buffer() {
        assert_eq!(MAX_FRAME_PAYLOAD, 4096);
    }

    #[test]
    fn each_frame_gets_a_fresh_mask_key() {
        let first = encode_client_frames(b"same");
        let second = encode_client_frames(b"same");

        assert_ne!(
            &first[2..6],
            &second[2..6],
            "a reused mask key would be a distinguishing signal"
        );
    }

    #[test]
    fn an_empty_write_still_produces_one_frame() {
        // gorilla's WriteMessage sends an empty binary message rather than
        // nothing at all, and the boundary is observable.
        let frames = encode_client_frames(b"");

        assert_eq!(frames[0], 0x82);
        assert_eq!(frames[1], 0x80, "mask bit set, zero-length payload");
        assert_eq!(frames.len(), 6, "header plus the mask key, no payload");
    }

    #[test]
    fn message_boundaries_do_not_reach_the_layer_above() {
        // To the VLESS layer this is a byte stream: two messages, a
        // fragmented one, and an empty one all read as one run of bytes.
        let mut decoder = FrameDecoder::new();
        let mut wire = server_frame(0x2, true, b"one");
        wire.extend(server_frame(0x2, false, b"two"));
        wire.extend(server_frame(0x0, true, b"three"));
        wire.extend(server_frame(0x2, true, b""));
        wire.extend(server_frame(0x1, true, b"four"));
        decoder.extend(&wire);

        let mut payload = Vec::new();
        while let Some(event) = decoder.next_event().expect("the frames must decode") {
            match event {
                FrameEvent::Payload(bytes) => payload.extend_from_slice(&bytes),
                other => panic!("unexpected {other:?}"),
            }
        }

        assert_eq!(payload, b"onetwothreefour");
    }

    #[test]
    fn a_ping_asks_for_a_pong_echoing_its_payload() {
        let mut decoder = FrameDecoder::new();
        decoder.extend(&server_frame(0x9, true, b"ping-payload"));

        let event = decoder
            .next_event()
            .expect("the ping must decode")
            .expect("a ping produces an event");

        match event {
            FrameEvent::Pong(payload) => assert_eq!(payload, b"ping-payload"),
            other => panic!("a ping must ask for a pong, got {other:?}"),
        }
    }

    #[test]
    fn a_pong_is_ignored_and_a_close_ends_the_stream() {
        let mut decoder = FrameDecoder::new();
        let mut wire = server_frame(0xa, true, b"unsolicited");
        wire.extend(server_frame(0x8, true, &1000u16.to_be_bytes()));
        decoder.extend(&wire);

        assert!(matches!(
            decoder
                .next_event()
                .expect("the frames must decode")
                .expect("close is an event"),
            FrameEvent::Close
        ));
    }

    #[test]
    fn a_masked_frame_from_the_server_is_a_protocol_error() {
        // RFC 6455 forbids it, and accepting one would mean a server could
        // hand us payload our unmasking would silently corrupt.
        let mut decoder = FrameDecoder::new();
        decoder.extend(&[0x82, 0x80 | 3, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00]);

        decoder
            .next_event()
            .expect_err("a masked server frame must be refused");
    }

    #[test]
    fn a_reserved_bit_is_a_protocol_error() {
        // No extension was negotiated, so RSV1 set means the peer is speaking
        // a protocol we did not agree to.
        let mut decoder = FrameDecoder::new();
        decoder.extend(&[0x40 | 0x82, 0x03, b'a', b'b', b'c']);

        decoder
            .next_event()
            .expect_err("a reserved bit must be refused");
    }

    #[test]
    fn a_frame_split_across_reads_is_held_until_complete() {
        let mut decoder = FrameDecoder::new();
        let wire = server_frame(0x2, true, b"split across reads");

        for chunk in wire.chunks(3) {
            decoder.extend(chunk);
        }

        let event = decoder
            .next_event()
            .expect("the frame must decode")
            .expect("a complete frame produces an event");
        match event {
            FrameEvent::Payload(payload) => assert_eq!(&payload[..], b"split across reads"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn a_partial_frame_yields_no_event_yet() {
        let mut decoder = FrameDecoder::new();
        decoder.extend(&[0x82, 0x05, b'h', b'i']);

        assert!(decoder
            .next_event()
            .expect("an incomplete frame is not an error")
            .is_none());
    }
}

/// The handshake and the framed stream, against a hand-rolled server.
mod stream_websocket_handshake_tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use xray_transport::stream::{
        accept_key_for, connect_websocket, encode_early_data, WebSocketConfig,
    };
    use xray_transport::TransportError;

    async fn loopback() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        (listener, addr)
    }

    fn config(path: &str) -> WebSocketConfig {
        WebSocketConfig {
            path: path.to_owned(),
            host: "example.com".to_owned(),
            headers: Vec::new(),
            early_data_bytes: 0,
            heartbeat_period_secs: 0,
        }
    }

    fn header_value(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    }

    /// Answers the handshake with a valid 101 derived from the client's key,
    /// then hands back the request and keeps the socket for the test.
    async fn accept_handshake(listener: &TcpListener) -> (TcpStream, String) {
        let (mut stream, _) = listener.accept().await.expect("a client must connect");
        let mut buffer = vec![0u8; 8192];
        let read = stream.read(&mut buffer).await.expect("a request arrives");
        buffer.truncate(read);
        let request = String::from_utf8(buffer).expect("the request must be UTF-8");

        let key = header_value(&request, "Sec-WebSocket-Key")
            .expect("the handshake must carry Sec-WebSocket-Key");
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept_key_for(&key)
        );
        stream
            .write_all(response.as_bytes())
            .await
            .expect("the response must go out");

        (stream, request)
    }

    #[test]
    fn the_accept_key_follows_rfc_6455() {
        // The RFC's own worked example.
        assert_eq!(
            accept_key_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn early_data_is_base64url_without_padding() {
        // Standard base64 of these bytes ends in '=' and uses '+' and '/';
        // Xray uses RawURLEncoding, so neither may appear.
        let encoded = encode_early_data(&[0xfb, 0xff, 0xfe]);

        assert!(!encoded.contains('='), "no padding: {encoded}");
        assert!(
            !encoded.contains('+') && !encoded.contains('/'),
            "url alphabet: {encoded}"
        );
        assert_eq!(encoded, "-__-");
    }

    #[tokio::test]
    async fn the_handshake_carries_the_rfc_6455_headers() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (stream, request) = accept_handshake(&listener).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(stream);
            request
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        connect_websocket(Box::new(stream), &config("/chat?x=1"))
            .await
            .expect("the handshake must succeed");

        let request = server.await.expect("server task");
        assert!(
            request.starts_with("GET /chat?x=1 HTTP/1.1\r\n"),
            "WebSocket sends a real query string, unescaped:\n{request}"
        );
        assert!(request.contains("\r\nHost: example.com\r\n"), "{request}");
        assert!(request.contains("\r\nUpgrade: websocket\r\n"), "{request}");
        assert!(request.contains("\r\nConnection: Upgrade\r\n"), "{request}");
        assert!(
            request.contains("\r\nSec-WebSocket-Version: 13\r\n"),
            "{request}"
        );
        assert!(request.contains("\r\nSec-WebSocket-Key: "), "{request}");
        assert!(
            !request.contains("Sec-WebSocket-Protocol"),
            "no early data was configured:\n{request}"
        );
        // The browser persona rides along here too.
        assert!(
            request.contains("\r\nSec-Fetch-Mode: websocket\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn the_handshake_reparses_and_escapes_the_configured_uri_path() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (stream, request) = accept_handshake(&listener).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            drop(stream);
            request
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        connect_websocket(Box::new(stream), &config("/日本%2f room?x=%zz#not-sent"))
            .await
            .expect("the handshake must succeed");

        let request = server.await.expect("server task");
        assert!(
            request.starts_with("GET /%E6%97%A5%E6%9C%AC%2f%20room?x=%zz HTTP/1.1\r\n"),
            "valid path escapes and raw query survive, while the fragment is omitted:\n{request}"
        );
    }

    #[tokio::test]
    async fn an_invalid_path_escape_is_rejected_before_a_request_is_written() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut byte = [0u8; 1];
            stream.read(&mut byte).await.expect("read")
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let result = connect_websocket(Box::new(stream), &config("/broken%zz")).await;
        assert!(
            matches!(result, Err(TransportError::WebSocketProtocol(_))),
            "a URL parse failure must abort the gorilla-compatible dial"
        );
        assert_eq!(server.await.expect("server task"), 0);
    }

    #[tokio::test]
    async fn a_wrong_accept_key_is_rejected() {
        let (listener, addr) = loopback().await;
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = vec![0u8; 8192];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                      Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n",
                )
                .await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        assert!(
            connect_websocket(Box::new(stream), &config("/chat"))
                .await
                .is_err(),
            "an accept key that does not derive from ours must be refused"
        );
    }

    #[tokio::test]
    async fn a_connection_token_list_is_accepted() {
        // Unlike httpupgrade, gorilla parses these as token lists, so a proxy
        // appending `keep-alive` does not break the handshake.
        let (listener, addr) = loopback().await;
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.expect("request");
            buffer.truncate(read);
            let request = String::from_utf8(buffer).expect("UTF-8");
            let key = header_value(&request, "Sec-WebSocket-Key").expect("key");
            let response = format!(
                "HTTP/1.1 101 Web Socket Protocol Handshake\r\n\
                 Upgrade: WebSocket, foo\r\nConnection: keep-alive, Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\r\n",
                accept_key_for(&key)
            );
            let _ = stream.write_all(response.as_bytes()).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        connect_websocket(Box::new(stream), &config("/chat"))
            .await
            .expect("token lists and a different reason phrase are both fine");
    }

    #[tokio::test]
    async fn a_first_write_within_the_budget_travels_in_the_handshake() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (mut stream, request) = accept_handshake(&listener).await;
            // Anything the client sends after the handshake would be a frame.
            let mut trailing = vec![0u8; 256];
            let read = tokio::time::timeout(Duration::from_millis(300), stream.read(&mut trailing))
                .await
                .map(|read| read.expect("read"))
                .unwrap_or(0);
            trailing.truncate(read);
            (request, trailing)
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut config = config("/chat");
        config.early_data_bytes = 16;

        let mut upgraded = connect_websocket(Box::new(stream), &config)
            .await
            .expect("the deferred dial must not fail before the first write");
        upgraded
            .write_all(b"0123456789abcdef")
            .await
            .expect("exactly 16 bytes, the inclusive boundary");

        let (request, trailing) = server.await.expect("server task");
        assert_eq!(
            header_value(&request, "Sec-WebSocket-Protocol").as_deref(),
            Some(encode_early_data(b"0123456789abcdef").as_str()),
            "the write must ride inside the handshake:\n{request}"
        );
        assert!(
            trailing.is_empty(),
            "no frame may be sent for data the handshake already carried, got {trailing:?}"
        );
    }

    #[tokio::test]
    async fn a_first_write_over_the_budget_disables_early_data() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (mut stream, request) = accept_handshake(&listener).await;
            let mut trailing = vec![0u8; 256];
            let read = tokio::time::timeout(Duration::from_millis(500), stream.read(&mut trailing))
                .await
                .map(|read| read.expect("read"))
                .unwrap_or(0);
            trailing.truncate(read);
            (request, trailing)
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut config = config("/chat");
        config.early_data_bytes = 16;

        let mut upgraded = connect_websocket(Box::new(stream), &config)
            .await
            .expect("deferred dial");
        upgraded
            .write_all(b"0123456789abcdefg")
            .await
            .expect("one byte past the budget");

        let (request, trailing) = server.await.expect("server task");
        assert!(
            !request.contains("Sec-WebSocket-Protocol"),
            "Xray omits the header outright rather than truncating:\n{request}"
        );
        assert_eq!(trailing[0], 0x82, "the payload goes out as a binary frame");
        assert_eq!(trailing[1], 0x80 | 17, "masked, 17 bytes");
    }

    #[tokio::test]
    async fn a_config_header_gorilla_owns_fails_the_dial() {
        // gorilla answers this with "duplicate header not allowed" rather than
        // overwriting, so the dial fails on Xray too.
        let (listener, addr) = loopback().await;
        tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut config = config("/chat");
        config.headers = vec![("Connection".to_owned(), "keep-alive".to_owned())];

        assert!(
            connect_websocket(Box::new(stream), &config).await.is_err(),
            "a config header gorilla writes itself must fail the dial"
        );
    }

    #[tokio::test]
    async fn payload_round_trips_as_frames() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_handshake(&listener).await;
            // One unmasked binary frame carrying "pong-me".
            let _ = stream.write_all(&[0x82, 0x07]).await;
            let _ = stream.write_all(b"pong-me").await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut upgraded = connect_websocket(Box::new(stream), &config("/chat"))
            .await
            .expect("handshake");

        let mut received = [0u8; 7];
        upgraded.read_exact(&mut received).await.expect("read");
        assert_eq!(&received, b"pong-me");

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn a_heartbeat_period_sends_an_empty_ping() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_handshake(&listener).await;
            let mut frame = [0u8; 8];
            let read = tokio::time::timeout(Duration::from_secs(4), stream.read(&mut frame))
                .await
                .expect("a ping must arrive within a few periods")
                .expect("read");
            frame[..read].to_vec()
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut config = config("/chat");
        config.heartbeat_period_secs = 1;
        let mut upgraded = connect_websocket(Box::new(stream), &config)
            .await
            .expect("handshake");

        // The keepalive rides the read path, which is where a relay parks.
        let mut sink = [0u8; 16];
        let _ = tokio::time::timeout(Duration::from_secs(3), upgraded.read(&mut sink)).await;

        let frame = server.await.expect("server task");
        assert_eq!(frame[0], 0x89, "FIN set, opcode 0x9 (ping)");
        assert_eq!(frame[1], 0x80, "masked, empty payload");
        assert_eq!(frame.len(), 6, "header plus the mask key: {frame:?}");
    }

    #[tokio::test]
    async fn shutdown_writes_a_close_frame_with_code_1000() {
        let (listener, addr) = loopback().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = accept_handshake(&listener).await;
            let mut frame = [0u8; 16];
            let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut frame))
                .await
                .expect("a close frame must arrive")
                .expect("read");
            frame[..read].to_vec()
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut upgraded = connect_websocket(Box::new(stream), &config("/chat"))
            .await
            .expect("handshake");
        upgraded.shutdown().await.expect("shutdown");

        let frame = server.await.expect("server task");
        assert_eq!(frame[0], 0x88, "FIN set, opcode 0x8 (close)");
        assert_eq!(frame[1], 0x80 | 2, "masked, two-byte payload");

        let key = [frame[2], frame[3], frame[4], frame[5]];
        let payload = [frame[6] ^ key[0], frame[7] ^ key[1]];
        assert_eq!(
            payload,
            1000u16.to_be_bytes(),
            "CloseNormalClosure, no reason"
        );
    }
}
