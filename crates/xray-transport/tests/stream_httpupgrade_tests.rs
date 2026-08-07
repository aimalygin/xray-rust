mod stream_httpupgrade_tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use xray_transport::stream::{connect_httpupgrade, HttpUpgradeConfig};
    use xray_transport::TransportError;

    async fn loopback() -> (TcpListener, std::net::SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener must bind");
        let addr = listener
            .local_addr()
            .expect("listener must report its address");
        (listener, addr)
    }

    /// Reads one request, answers with `response`, and hands the request back.
    fn serve_once(
        listener: TcpListener,
        response: &'static [u8],
    ) -> tokio::task::JoinHandle<Vec<u8>> {
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            let mut buffer = vec![0u8; 4096];
            let read = stream
                .read(&mut buffer)
                .await
                .expect("a request must arrive");
            buffer.truncate(read);
            let _ = stream.write_all(response).await;
            // Hold the socket open so the client's own read is not raced by a
            // reset; the test drops the handle when it is done.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            buffer
        })
    }

    fn config(path: &str) -> HttpUpgradeConfig {
        HttpUpgradeConfig {
            path: path.to_owned(),
            host: "example.com".to_owned(),
            headers: Vec::new(),
            wait_for_response: true,
        }
    }

    /// `BoxedTransportStream` is not `Debug`, so `expect_err` is unavailable;
    /// asserting on the variant is stronger anyway, because it tells a
    /// rejection apart from an I/O failure that happened to abort the dial.
    fn expect_rejected(
        result: Result<xray_transport::BoxedTransportStream, TransportError>,
        why: &str,
    ) {
        match result {
            Ok(_) => panic!("{why}"),
            Err(error) => assert!(
                matches!(error, TransportError::HttpUpgradeRejected(_)),
                "{why}, got: {error}"
            ),
        }
    }

    const ACCEPTED: &[u8] =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";

    #[tokio::test]
    async fn the_request_escapes_a_question_mark_in_the_path() {
        let (listener, addr) = loopback().await;
        let recorded = serve_once(listener, ACCEPTED);

        let stream = TcpStream::connect(addr)
            .await
            .expect("the loopback connect must succeed");
        connect_httpupgrade(Box::new(stream), &config("/ws?foo=bar"))
            .await
            .expect("the upgrade must succeed");

        let request = String::from_utf8(recorded.await.expect("the recorder must finish"))
            .expect("the request must be UTF-8");

        assert!(
            request.starts_with("GET /ws%3Ffoo=bar HTTP/1.1\r\n"),
            "Go escapes ? in URL.Path; WebSocket does not:\n{request}"
        );
        assert!(request.contains("\r\nHost: example.com\r\n"), "{request}");
        assert!(request.contains("\r\nConnection: Upgrade\r\n"), "{request}");
        assert!(request.contains("\r\nUpgrade: websocket\r\n"), "{request}");
        assert!(
            !request.contains("Sec-WebSocket"),
            "httpupgrade sends no RFC 6455 headers:\n{request}"
        );
    }

    #[tokio::test]
    async fn the_masquerade_block_rides_along() {
        // The transport shares Xray's browser persona: an httpupgrade request
        // is a browser's WebSocket request minus the RFC 6455 headers.
        let (listener, addr) = loopback().await;
        let recorded = serve_once(listener, ACCEPTED);

        let stream = TcpStream::connect(addr).await.expect("connect");
        connect_httpupgrade(Box::new(stream), &config("/ws"))
            .await
            .expect("the upgrade must succeed");

        let request = String::from_utf8(recorded.await.expect("recorder")).expect("UTF-8");

        assert!(
            request.contains("\r\nSec-Fetch-Mode: websocket\r\n"),
            "{request}"
        );
        assert!(request.contains("\r\nSec-CH-UA: "), "{request}");
        assert!(
            request.contains("\r\nUser-Agent: Mozilla/5.0 "),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_status_without_the_reason_phrase_is_rejected() {
        let (listener, addr) = loopback().await;
        let _recorded = serve_once(
            listener,
            b"HTTP/1.1 101\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
        );

        let stream = TcpStream::connect(addr).await.expect("connect");
        expect_rejected(
            connect_httpupgrade(Box::new(stream), &config("/ws")).await,
            "Xray compares the status as an exact string",
        );
    }

    #[tokio::test]
    async fn a_connection_token_list_is_rejected() {
        let (listener, addr) = loopback().await;
        let _recorded = serve_once(
            listener,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, keep-alive\r\nUpgrade: websocket\r\n\r\n",
        );

        let stream = TcpStream::connect(addr).await.expect("connect");
        expect_rejected(
            connect_httpupgrade(Box::new(stream), &config("/ws")).await,
            "httpupgrade compares Connection exactly, unlike WebSocket",
        );
    }

    #[tokio::test]
    async fn bytes_after_the_response_reach_the_first_read() {
        let (listener, addr) = loopback().await;
        let _recorded = serve_once(
            listener,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nHELLO",
        );

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut upgraded = connect_httpupgrade(Box::new(stream), &config("/ws"))
            .await
            .expect("the upgrade must succeed");

        let mut buffer = [0u8; 5];
        upgraded
            .read_exact(&mut buffer)
            .await
            .expect("payload sent with the response must not be lost");
        assert_eq!(&buffer, b"HELLO");
    }

    #[tokio::test]
    async fn early_data_skips_the_wait_for_the_response() {
        // With `ed` set, Xray returns the connection without reading the 101,
        // so the first payload write goes out right behind the request.
        let (listener, addr) = loopback().await;
        let recorded = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            let mut buffer = vec![0u8; 4096];
            let read = stream.read(&mut buffer).await.expect("a request arrives");
            buffer.truncate(read);
            // Deliberately never answer: a waiting dial would hang here.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            buffer
        });

        let stream = TcpStream::connect(addr).await.expect("connect");
        let mut config = config("/ws");
        config.wait_for_response = false;

        let upgraded = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connect_httpupgrade(Box::new(stream), &config),
        )
        .await
        .expect("the dial must not wait for a response")
        .expect("the upgrade must succeed");
        drop(upgraded);

        let request = String::from_utf8(recorded.await.expect("recorder")).expect("UTF-8");
        assert!(request.starts_with("GET /ws HTTP/1.1\r\n"), "{request}");
    }
}
