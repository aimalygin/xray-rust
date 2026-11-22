use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::tls_stream::ClientTlsStream;
use crate::TransportStream;

/// What a penetrating TLS session runs over: REALITY's own socket, or the
/// carrier the dialer produced.
pub(crate) trait Carrier: AsyncRead + AsyncWrite + Send + Unpin {
    /// Whether the carrier's reads are a bare TCP socket's.
    #[cfg(target_os = "linux")]
    fn raw_read(&mut self) -> crate::RawRead<'_>;
}

impl Carrier for TcpStream {
    #[cfg(target_os = "linux")]
    fn raw_read(&mut self) -> crate::RawRead<'_> {
        crate::RawRead::Socket(self)
    }
}

impl Carrier for crate::BoxedTransportStream {
    #[cfg(target_os = "linux")]
    fn raw_read(&mut self) -> crate::RawRead<'_> {
        TransportStream::raw_read(&mut **self)
    }
}

impl Carrier for crate::fragment::FragmentStream {
    // Its reads also drive the fragments it still owes the peer.
    #[cfg(target_os = "linux")]
    fn raw_read(&mut self) -> crate::RawRead<'_> {
        crate::RawRead::Never
    }
}

enum PenetratingTlsState<S> {
    Tls(Option<Box<ClientTlsStream<S>>>),
    /// The read side switched to Vision direct mode while the write side may
    /// still owe the peer TLS records.
    ///
    /// Vision switches each direction independently — Xray-core swaps only its
    /// reader on `VisionCommand::Direct` downlink and keeps decrypting our
    /// uplink until we send `Direct` ourselves — so the session has to stay
    /// alive here. Raw bytes come straight off the carrier instead.
    ReadDirect {
        stream: Box<ClientTlsStream<S>>,
        pending_plaintext: BytesMut,
    },
}

/// A TLS session that Vision may unwrap into direct mode, over the carrier
/// the unwrapped directions then use.
///
/// REALITY runs over its own TCP socket; plain TLS runs over whatever carrier
/// the dialer produced, which under a chained outbound is another proxy
/// stream. Either way it is the connection Xray-core's Vision reads and
/// writes once a direction switches to direct mode (`tls.Conn.NetConn()`).
///
/// The session reads its carrier one TLS record at a time
/// ([`ClientTlsStream::connect_record_aligned`]), so when the read side goes
/// direct the session holds nothing but plaintext it has already decrypted,
/// and the cleartext that follows the peer's last record is still in the
/// carrier.
pub(crate) struct PenetratingTlsStream<S = TcpStream> {
    state: PenetratingTlsState<S>,
}

impl<S> PenetratingTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// `stream` must come from [`ClientTlsStream::connect_record_aligned`]:
    /// a session that read its carrier freely may already hold what follows
    /// the peer's last record.
    pub(crate) fn new(stream: ClientTlsStream<S>) -> Self {
        Self {
            state: PenetratingTlsState::Tls(Some(Box::new(stream))),
        }
    }

    fn ensure_read_direct(&mut self) -> io::Result<()> {
        let PenetratingTlsState::Tls(tls) = &mut self.state else {
            return Ok(());
        };
        let mut tls = tls
            .take()
            .ok_or_else(|| io::Error::other("TLS stream was already taken"))?;
        // The peer goes direct after a whole record. Inside one, the session
        // holds bytes that the direct read could no longer return.
        if tls.inside_record() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Vision direct read inside a TLS record",
            ));
        }
        let mut pending_plaintext = BytesMut::new();
        tls.take_decrypted(&mut pending_plaintext)?;
        // Nothing feeds the session once reads bypass it.
        tls.release_record_alignment();

        self.state = PenetratingTlsState::ReadDirect {
            stream: tls,
            pending_plaintext,
        };
        Ok(())
    }

    fn poll_read_direct_mode(
        &mut self,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.ensure_read_direct()?;
        let PenetratingTlsState::ReadDirect {
            stream,
            pending_plaintext,
        } = &mut self.state
        else {
            unreachable!("ensure_read_direct transitions TLS state to read-direct");
        };

        if !pending_plaintext.is_empty() {
            let len = output.remaining().min(pending_plaintext.len());
            output.put_slice(&pending_plaintext.split_to(len));
            return Poll::Ready(Ok(()));
        }

        Pin::new(stream.carrier_mut()).poll_read(cx, output)
    }

    /// The session in either state, or the error every operation reports
    /// once a failed switch to direct reads has dropped it.
    fn stream_mut(&mut self) -> io::Result<&mut ClientTlsStream<S>> {
        match &mut self.state {
            PenetratingTlsState::Tls(Some(stream))
            | PenetratingTlsState::ReadDirect { stream, .. } => Ok(stream),
            PenetratingTlsState::Tls(None) => Err(io::Error::other("TLS stream was already taken")),
        }
    }
}

impl<S> AsyncRead for PenetratingTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match &mut this.state {
            PenetratingTlsState::Tls(Some(stream)) => Pin::new(stream).poll_read(cx, output),
            PenetratingTlsState::Tls(None) => {
                Poll::Ready(Err(io::Error::other("TLS stream was already taken")))
            }
            PenetratingTlsState::ReadDirect { .. } => this.poll_read_direct_mode(cx, output),
        }
    }
}

// A direct read must not turn the uplink into cleartext: the peer still
// decrypts our writes until Vision switches this direction, so every write
// here goes through the session in either state.
impl<S> AsyncWrite for PenetratingTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().stream_mut()?).poll_write(cx, input)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().stream_mut()?).poll_write_vectored(cx, inputs)
    }

    fn is_write_vectored(&self) -> bool {
        match &self.state {
            PenetratingTlsState::Tls(Some(stream))
            | PenetratingTlsState::ReadDirect { stream, .. } => stream.is_write_vectored(),
            PenetratingTlsState::Tls(None) => false,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().stream_mut()?).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().stream_mut()?).poll_shutdown(cx)
    }
}

impl<S> TransportStream for PenetratingTlsStream<S>
where
    S: Carrier,
{
    fn release_record_alignment(&mut self) {
        if let PenetratingTlsState::Tls(Some(stream)) = &mut self.state {
            stream.release_record_alignment();
        }
    }

    /// The carrier's socket, once the plaintext the session had already
    /// decrypted when the read side went direct has been read. The session
    /// stays for the write side, which Vision switches on its own.
    #[cfg(target_os = "linux")]
    fn raw_read_direct(&mut self) -> crate::RawRead<'_> {
        if self.ensure_read_direct().is_err() {
            // The next direct read reports the failure.
            return crate::RawRead::NotYet;
        }
        match &mut self.state {
            PenetratingTlsState::ReadDirect {
                stream,
                pending_plaintext,
            } if pending_plaintext.is_empty() => stream.carrier_mut().raw_read(),
            _ => crate::RawRead::NotYet,
        }
    }

    fn negotiated_alpn(&self) -> Option<&[u8]> {
        match &self.state {
            PenetratingTlsState::Tls(Some(stream))
            | PenetratingTlsState::ReadDirect { stream, .. } => stream.alpn_protocol(),
            PenetratingTlsState::Tls(None) => None,
        }
    }

    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_direct_mode(cx, output)
    }

    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().stream_mut()?.carrier_mut()).poll_write(cx, input)
    }

    fn poll_flush_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().stream_mut()?.carrier_mut()).poll_flush(cx)
    }

    fn poll_shutdown_direct(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().stream_mut()?.carrier_mut()).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::sync::Arc;

    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    async fn connect_test_stream() -> (
        PenetratingTlsStream,
        tokio_rustls::server::TlsStream<TcpStream>,
    ) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["server.test".to_owned()])
                .expect("generate self-signed certificate");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).expect("add test root");
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring provider should support default TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("server certificate config");

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind TLS listener");
        let addr = listener.local_addr().expect("listener addr");
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept TLS client");
            acceptor.accept(stream).await.expect("accept TLS")
        });

        let client = TcpStream::connect(addr).await.expect("connect TLS client");
        let server_name = ServerName::try_from("server.test").expect("server name");
        let client = ClientTlsStream::connect_record_aligned(
            Arc::new(client_config),
            server_name,
            client,
            None,
        )
        .await
        .expect("client TLS connect");
        let server = server.await.expect("server task");

        (PenetratingTlsStream::new(client), server)
    }

    async fn write_direct(stream: &mut PenetratingTlsStream, bytes: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            let written =
                poll_fn(|cx| Pin::new(&mut *stream).poll_write_direct(cx, &bytes[offset..]))
                    .await?;
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "direct write returned zero",
                ));
            }
            offset += written;
        }
        poll_fn(|cx| Pin::new(&mut *stream).poll_flush_direct(cx)).await
    }

    async fn read_direct_exact(
        stream: &mut PenetratingTlsStream,
        output: &mut [u8],
    ) -> io::Result<()> {
        let mut offset = 0;
        while offset < output.len() {
            let mut read_buf = ReadBuf::new(&mut output[offset..]);
            poll_fn(|cx| Pin::new(&mut *stream).poll_read_direct(cx, &mut read_buf)).await?;
            let read = read_buf.filled().len();
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "direct read ended early",
                ));
            }
            offset += read;
        }
        Ok(())
    }

    #[tokio::test]
    async fn direct_write_bypasses_tls_after_switch() {
        let (mut client, mut server) = connect_test_stream().await;

        client.write_all(b"tls").await.expect("write TLS plaintext");
        client.flush().await.expect("flush TLS plaintext");
        let mut tls_plaintext = [0; 3];
        server
            .read_exact(&mut tls_plaintext)
            .await
            .expect("read TLS plaintext");
        assert_eq!(&tls_plaintext, b"tls");

        write_direct(&mut client, b"raw")
            .await
            .expect("write direct bytes");
        let (mut raw_server, _) = server.into_inner();
        let mut raw = [0; 3];
        raw_server
            .read_exact(&mut raw)
            .await
            .expect("read raw bytes");

        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn direct_write_keeps_tls_read_available_until_direct_read() {
        let (mut client, mut server) = connect_test_stream().await;

        write_direct(&mut client, b"raw")
            .await
            .expect("write direct bytes");

        server
            .write_all(b"tls reply")
            .await
            .expect("write TLS reply");
        server.flush().await.expect("flush TLS reply");

        let mut reply = [0; 9];
        client
            .read_exact(&mut reply)
            .await
            .expect("read TLS reply after direct write");
        assert_eq!(&reply, b"tls reply");

        let (mut raw_server, _) = server.into_inner();
        let mut raw = [0; 3];
        raw_server
            .read_exact(&mut raw)
            .await
            .expect("read raw bytes");
        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn direct_read_keeps_tls_write_available_until_direct_write() {
        let (mut client, mut server) = connect_test_stream().await;

        server
            .write_all(b"tls frame")
            .await
            .expect("write TLS plaintext");
        server.flush().await.expect("flush TLS plaintext");
        let mut tls_frame = [0; 9];
        client
            .read_exact(&mut tls_frame)
            .await
            .expect("read TLS plaintext before switching direct");
        assert_eq!(&tls_frame, b"tls frame");

        // Vision switches each direction independently: the peer swaps only
        // its writer when it sends Direct downlink and keeps reading the
        // uplink through TLS until we send Direct ourselves.
        let (raw_server, _) = server.get_mut();
        raw_server
            .write_all(b"raw")
            .await
            .expect("write raw downlink");
        raw_server.flush().await.expect("flush raw downlink");

        let mut raw = [0; 3];
        read_direct_exact(&mut client, &mut raw)
            .await
            .expect("read direct bytes");
        assert_eq!(&raw, b"raw");

        client
            .write_all(b"tls")
            .await
            .expect("write TLS plaintext after direct read");
        client.flush().await.expect("flush TLS plaintext");

        let mut plaintext = [0; 3];
        server
            .read_exact(&mut plaintext)
            .await
            .expect("read TLS plaintext after direct read");
        assert_eq!(&plaintext, b"tls");
    }

    #[tokio::test]
    async fn direct_read_drains_buffered_tls_plaintext_before_raw_socket() {
        let (mut client, mut server) = connect_test_stream().await;

        server
            .write_all(b"tlsbuffered")
            .await
            .expect("write TLS plaintext");
        server.flush().await.expect("flush TLS plaintext");
        let mut tls_prefix = [0; 3];
        client
            .read_exact(&mut tls_prefix)
            .await
            .expect("read TLS prefix");
        assert_eq!(&tls_prefix, b"tls");

        let (mut raw_server, _) = server.into_inner();
        raw_server
            .write_all(b"raw")
            .await
            .expect("write raw response");
        raw_server.flush().await.expect("flush raw response");

        let mut direct = [0; 11];
        read_direct_exact(&mut client, &mut direct)
            .await
            .expect("read buffered plaintext and raw bytes");

        assert_eq!(&direct, b"bufferedraw");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn raw_read_direct_offers_the_socket_once_decrypted_plaintext_is_read() {
        let (mut client, mut server) = connect_test_stream().await;
        assert!(matches!(client.raw_read(), crate::RawRead::Never));

        server
            .write_all(b"tlsbuffered")
            .await
            .expect("write TLS plaintext");
        server.flush().await.expect("flush TLS plaintext");
        let mut tls_prefix = [0; 3];
        client
            .read_exact(&mut tls_prefix)
            .await
            .expect("read TLS prefix");

        // The session already decrypted the rest of that record.
        assert!(matches!(client.raw_read_direct(), crate::RawRead::NotYet));
        let mut buffered = [0; 8];
        read_direct_exact(&mut client, &mut buffered)
            .await
            .expect("read buffered plaintext");
        assert_eq!(&buffered, b"buffered");

        let (mut raw_server, _) = server.into_inner();
        raw_server
            .write_all(b"raw")
            .await
            .expect("write raw response");
        let crate::RawRead::Socket(socket) = client.raw_read_direct() else {
            panic!("a drained direct read is the carrier's socket");
        };
        let mut raw = [0; 3];
        let mut read = 0;
        while read < raw.len() {
            socket.readable().await.expect("socket readable");
            match socket.try_read(&mut raw[read..]) {
                Ok(len) => read += len,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("read raw bytes: {error}"),
            }
        }
        assert_eq!(&raw, b"raw");
    }

    #[tokio::test]
    async fn direct_read_preserves_raw_bytes_after_tls_record() {
        let (mut client, mut server) = connect_test_stream().await;

        server
            .write_all(b"tls frame")
            .await
            .expect("write TLS plaintext");
        server.flush().await.expect("flush TLS plaintext");

        let (mut raw_server, _) = server.into_inner();
        raw_server
            .write_all(b"raw")
            .await
            .expect("write raw response");
        raw_server.flush().await.expect("flush raw response");

        let mut tls_frame = [0; 8192];
        let read = client
            .read(&mut tls_frame)
            .await
            .expect("read TLS plaintext before switching direct");
        assert_eq!(&tls_frame[..read], b"tls frame");

        let mut raw = [0; 3];
        read_direct_exact(&mut client, &mut raw)
            .await
            .expect("read raw bytes after TLS record");

        assert_eq!(&raw, b"raw");
    }

    /// The cleartext after the last record may look like a record. A read
    /// loop that kept going while its caller had room would hand it to the
    /// session, which fails to decrypt it.
    #[tokio::test]
    async fn direct_read_preserves_raw_bytes_shaped_like_a_tls_record() {
        let (mut client, mut server) = connect_test_stream().await;
        let raw_record = [&[0x17, 0x03, 0x03, 0x00, 0x13][..], b"not a TLS record..."].concat();

        server
            .write_all(b"tls frame")
            .await
            .expect("write TLS plaintext");
        server.flush().await.expect("flush TLS plaintext");
        let (mut raw_server, _) = server.into_inner();
        raw_server
            .write_all(&raw_record)
            .await
            .expect("write raw response");
        raw_server.flush().await.expect("flush raw response");

        // A read with room to spare, which must not reach into the raw bytes.
        let mut tls_frame = [0; 8192];
        let read = client
            .read(&mut tls_frame)
            .await
            .expect("read TLS plaintext before switching direct");
        assert_eq!(&tls_frame[..read], b"tls frame");

        let mut raw = vec![0; raw_record.len()];
        read_direct_exact(&mut client, &mut raw)
            .await
            .expect("read raw bytes after TLS record");
        assert_eq!(raw, raw_record);
    }

    /// The peer switches after a whole record. If the session already holds
    /// part of one, a direct read could not return those bytes, and says so
    /// instead of returning the stream with a hole in it.
    #[tokio::test]
    async fn direct_read_inside_a_tls_record_is_an_error() {
        let (mut client, server) = connect_test_stream().await;
        let (mut raw_server, _) = server.into_inner();
        // A record header that announces 32 bytes, and 4 of them.
        raw_server
            .write_all(&[0x17, 0x03, 0x03, 0x00, 0x20, 1, 2, 3, 4])
            .await
            .expect("write a partial record");
        raw_server.flush().await.expect("flush a partial record");

        let inside_record = |client: &PenetratingTlsStream| match &client.state {
            PenetratingTlsState::Tls(Some(stream)) => stream.inside_record(),
            _ => panic!("the session is still in TLS mode"),
        };
        while !inside_record(&client) {
            let mut scratch = [0; 16];
            let mut output = ReadBuf::new(&mut scratch);
            let polled =
                poll_fn(|cx| Poll::Ready(Pin::new(&mut client).poll_read(cx, &mut output))).await;
            assert!(polled.is_pending(), "a partial record yields no plaintext");
            tokio::task::yield_now().await;
        }

        let mut raw = [0; 4];
        let error = read_direct_exact(&mut client, &mut raw)
            .await
            .expect_err("a direct read inside a record");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // The session is gone for good, as after any failed switch.
        let error = read_direct_exact(&mut client, &mut raw)
            .await
            .expect_err("the stream stays failed");
        assert_eq!(error.to_string(), "TLS stream was already taken");
    }
}
