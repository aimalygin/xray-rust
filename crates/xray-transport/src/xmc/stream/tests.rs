use super::*;
use crate::xmc::{proto::frame, testing::server_frame};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const SECRET: [u8; 16] = *b"0123456789abcdef";

/// A stream as a login leaves it, and the server's end with its ciphers.
fn pair() -> (XmcStream, Conn<DuplexStream>) {
    let (client, server) = tokio::io::duplex(1 << 20);
    let mut conn = Conn::new(Box::new(client) as BoxedTransportStream);
    conn.read_cipher = Some(Cfb8::new(&SECRET, true));
    conn.write_cipher = Some(Cfb8::new(&SECRET, false));
    let mut server = Conn::new(server);
    server.read_cipher = Some(Cfb8::new(&SECRET, true));
    server.write_cipher = Some(Cfb8::new(&SECRET, false));
    (XmcStream::new(conn).unwrap(), server)
}

#[tokio::test]
async fn writes_go_out_in_24_kib_custom_payloads() {
    let (mut stream, mut server) = pair();
    let data: Vec<u8> = (0..60 * 1024).map(|i| (i % 251) as u8).collect();
    stream.write_all(&data).await.unwrap();
    stream.flush().await.unwrap();
    let mut received = Vec::new();
    for want in [24 * 1024, 24 * 1024, 12 * 1024] {
        let (id, payload) = server.read_packet().await.unwrap();
        assert_eq!(id, 0x02);
        let mut fields = Fields(&payload);
        assert_eq!(fields.string().unwrap(), b"xmc:data");
        assert_eq!(fields.rest().len(), want);
        received.extend_from_slice(fields.rest());
    }
    assert_eq!(received, data);
}

#[tokio::test]
async fn only_the_xmc_channel_reaches_the_reader() {
    let (mut stream, mut server) = pair();
    let wire = [
        server_frame(0x01, Some("minecraft:brand"), b"vanilla"),
        server_frame(0x01, Some("xmc:data"), b""),
        // A packet the client has no use for.
        server_frame(0x07, None, b"tags"),
        // The serverbound payload ID, which the client does not read.
        server_frame(0x02, Some("xmc:data"), b"wrong"),
        server_frame(0x01, Some("xmc:data"), b"first"),
        server_frame(0x01, Some("xmc:data"), b"second"),
    ]
    .concat();
    server.write_all(&wire).await.unwrap();
    let mut first = [0u8; 3];
    stream.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"fir");
    let mut rest = vec![0u8; 8];
    stream.read_exact(&mut rest).await.unwrap();
    assert_eq!(rest, b"stsecond");
}

#[tokio::test]
async fn keep_alives_are_echoed_while_reading() {
    let (mut stream, mut server) = pair();
    let reader = tokio::spawn(async move {
        let mut data = [0u8; 5];
        stream.read_exact(&mut data).await.unwrap();
        (stream, data)
    });
    let id = 0x0102_0304_0506_0708_i64;
    server
        .write_all(&server_frame(0x04, None, &id.to_be_bytes()))
        .await
        .unwrap();
    let (echo, data) = server.read_packet().await.unwrap();
    assert_eq!((echo, data), (0x04, id.to_be_bytes().to_vec()));
    server
        .write_all(&server_frame(0x01, Some("xmc:data"), b"after"))
        .await
        .unwrap();
    let (mut stream, data) = reader.await.unwrap();
    assert_eq!(&data, b"after");
    // The cipher stays in step after the echo.
    stream.write_all(b"next").await.unwrap();
    let (id, payload) = server.read_packet().await.unwrap();
    assert_eq!(id, 0x02);
    assert_eq!(Fields(&payload).rest()[9..], *b"next");
}

#[tokio::test]
async fn the_stream_ends_between_packets_only() {
    let (mut stream, mut server) = pair();
    server
        .write_all(&server_frame(0x01, Some("xmc:data"), b"whole"))
        .await
        .unwrap();
    drop(server);
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    assert_eq!(out, b"whole");

    let (mut stream, mut server) = pair();
    let frame = server_frame(0x01, Some("xmc:data"), b"cut");
    server.write_all(&frame[..frame.len() - 1]).await.unwrap();
    drop(server);
    let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn malformed_packets_fail_the_read() {
    for wire in [
        // A zero-length frame.
        vec![0x00],
        // Longer than a frame may be.
        vec![0x86, 0x80, 0x02],
        // A non-canonical length.
        vec![0x81, 0x00, 0x01],
        // A keep-alive without its eight bytes.
        frame(0x04, &[1, 2, 3]).unwrap(),
        // A payload whose channel overruns the packet.
        frame(0x01, &[9, b'x']).unwrap(),
    ] {
        let (mut stream, mut server) = pair();
        server.write_all(&wire).await.unwrap();
        drop(server);
        let error = stream.read_to_end(&mut Vec::new()).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{wire:?}");
    }
}

#[tokio::test]
async fn bytes_read_past_the_login_are_kept() {
    let (client, server) = tokio::io::duplex(1 << 16);
    let mut server = Conn::new(server);
    server.write_cipher = Some(Cfb8::new(&SECRET, false));
    // The last padding record, then a payload in the same read.
    server
        .write_all(
            &[
                &[3u8, 0, 0][..],
                &server_frame(0x01, Some("xmc:data"), b"early"),
            ]
            .concat(),
        )
        .await
        .unwrap();
    let mut conn = Conn::new(Box::new(client) as BoxedTransportStream);
    conn.read_cipher = Some(Cfb8::new(&SECRET, true));
    conn.write_cipher = Some(Cfb8::new(&SECRET, false));
    let mut record = [0u8; 3];
    conn.read_exact(&mut record).await.unwrap();
    assert_eq!(record, [3, 0, 0]);
    let mut stream = XmcStream::new(conn).unwrap();
    let mut early = [0u8; 5];
    stream.read_exact(&mut early).await.unwrap();
    assert_eq!(&early, b"early");
}

/// The dialer logs in before anything else, with the socket's peer in the
/// handshake, and runs the `header-custom` handshake inside the login. Real
/// sockets need real time: a paused clock would jump to the login's deadline
/// while a read waits on the socket.
#[tokio::test]
async fn the_dialer_logs_in_outside_the_header_custom_handshake() {
    use crate::header_custom::{CustomItem, HeaderCustomTcpConfig};
    use crate::xmc::{
        testing::{profile, Server},
        XmcConfig,
    };
    use crate::{ConnectorConfig, TransportDialer};
    use std::sync::Arc;
    use xray_routing::{Network, Target, TargetAddr};
    let packet = |bytes: &[u8]| CustomItem {
        delay: (0, 0),
        rand: 0,
        rand_range: (0, 255),
        packet: bytes.to_vec(),
        capture: String::new(),
        reuse: String::new(),
        transform: None,
    };
    let profiles = vec![profile("Steve", 1)];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_profiles = profiles.clone();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut conn = Conn::new(socket);
        let seen = Server::new("synthetic", server_profiles)
            .accept(&mut conn)
            .await
            .unwrap();
        let payload = |packet: (i32, Vec<u8>)| {
            assert_eq!(packet.0, 0x02);
            Fields(&packet.1).rest()[9..].to_vec()
        };
        let hello = payload(conn.read_packet().await.unwrap());
        conn.write_all(&server_frame(0x01, Some("xmc:data"), b"OK"))
            .await
            .unwrap();
        let data = payload(conn.read_packet().await.unwrap());
        (seen, hello, data)
    });
    let dialer = TransportDialer::system()
        .unwrap()
        .with_tcp_header_custom(Arc::new(HeaderCustomTcpConfig {
            clients: vec![vec![packet(b"HI")]],
            servers: vec![vec![packet(b"OK")]],
        }))
        .with_tcp_xmc(Arc::new(XmcConfig::new("", profiles, "synthetic").unwrap()));
    let target = Target::new(TargetAddr::Ip(address.ip()), address.port(), Network::Tcp);
    let exchange = async {
        let mut client = dialer
            .connect_resolved(&ConnectorConfig::Tcp, &target, &[address], None)
            .await
            .unwrap();
        client.write_all(b"data").await.unwrap();
        client.flush().await.unwrap();
        server.await.unwrap()
    };
    let (seen, hello, data) = tokio::time::timeout(Duration::from_secs(30), exchange)
        .await
        .expect("the login and the exchange finish");
    assert_eq!(seen.address, b"127.0.0.1");
    assert_eq!(seen.port, address.port());
    assert_eq!(
        (hello.as_slice(), data.as_slice()),
        (&b"HI"[..], &b"data"[..])
    );
}

/// A carrier that, like Tokio's sockets, keeps one waker per direction and
/// takes writes only once its gate opens.
#[derive(Default)]
struct Gate {
    open: bool,
    write_waker: Option<std::task::Waker>,
    written: usize,
}

struct GatedCarrier(std::sync::Arc<std::sync::Mutex<Gate>>);

impl AsyncRead for GatedCarrier {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for GatedCarrier {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut gate = self.0.lock().unwrap();
        if !gate.open {
            gate.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        gate.written += buf.len();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl TransportStream for GatedCarrier {
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(self, cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, input)
    }
}

/// A reader that drains the frames a blocked writer left takes the writer's
/// place in the carrier's one write waker, so it must wake the writer.
#[tokio::test]
async fn a_drain_from_the_read_side_wakes_the_writer_it_displaced() {
    let gate = std::sync::Arc::new(std::sync::Mutex::new(Gate::default()));
    let mut conn = Conn::new(Box::new(GatedCarrier(gate.clone())) as BoxedTransportStream);
    conn.read_cipher = Some(Cfb8::new(&SECRET, true));
    conn.write_cipher = Some(Cfb8::new(&SECRET, false));
    let (mut reader, mut writer) = tokio::io::split(XmcStream::new(conn).unwrap());
    let writer = tokio::spawn(async move {
        writer.write_all(&[7; 100]).await.unwrap();
        writer.flush().await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let _reader = tokio::spawn(async move {
        let _ = reader.read(&mut [0; 16]).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    // The carrier wakes whichever task asked last: the reader.
    let waker = {
        let mut gate = gate.lock().unwrap();
        gate.open = true;
        gate.write_waker.take().unwrap()
    };
    waker.wake();
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("the writer was never woken")
        .unwrap();
    // One frame: its length, the packet ID, the channel and the bytes.
    assert_eq!(gate.lock().unwrap().written, 1 + 1 + 9 + 100);
}

/// A peer that stops reading and keeps sending keep-alives: the answers
/// that cannot go out stop the reading instead of piling up, and the stream
/// goes on once the peer reads again.
#[tokio::test]
async fn unread_keep_alive_answers_stop_the_reading() {
    const KEEP_ALIVES: usize = 20_000;
    let test = async {
        let (mut stream, mut server) = pair();
        // More than the carrier holds: the rest waits in `out`, as the
        // answers will behind it.
        assert_eq!(stream.write(&vec![0u8; 2 << 20]).await.unwrap(), 2 << 20);
        let waiting = stream.out.len() - stream.written;
        assert!(waiting > 0);
        for id in 0..KEEP_ALIVES as i64 {
            server
                .write_all(&server_frame(0x04, None, &id.to_be_bytes()))
                .await
                .unwrap();
        }
        let mut byte = [0u8; 1];
        let mut read = ReadBuf::new(&mut byte);
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut stream)
            .poll_read(&mut cx, &mut read)
            .is_pending());
        let answers = stream.out.len() - stream.written - waiting;
        assert!(
            answers <= MAX_UNSENT_ANSWERS + 16,
            "{answers} bytes of answers wait"
        );

        let reader = tokio::spawn(async move {
            let mut data = [0u8; 5];
            stream.read_exact(&mut data).await.unwrap();
            stream.flush().await.unwrap();
            (stream, data)
        });
        server
            .write_all(&server_frame(0x01, Some("xmc:data"), b"after"))
            .await
            .unwrap();
        let mut echoed = 0;
        while echoed < KEEP_ALIVES {
            if server.read_packet().await.unwrap().0 == 0x04 {
                echoed += 1;
            }
        }
        let (_stream, data) = reader.await.unwrap();
        assert_eq!(&data, b"after");
    };
    tokio::time::timeout(Duration::from_secs(30), test)
        .await
        .unwrap();
}
