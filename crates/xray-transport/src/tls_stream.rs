//! The async client side of a rustls session over a Tokio carrier.
//!
//! This crate drives `rustls::ClientConnection` itself. Vision unwraps a TLS
//! session in the middle of a connection, so what matters is exactly which
//! carrier bytes the session has taken, and that is decided by the loop that
//! feeds it: one that keeps reading after a record has produced plaintext
//! hands rustls the cleartext that follows the peer's last record. Owning the
//! loop makes that a property of this file rather than of a dependency's
//! release.

use std::future::poll_fn;
use std::io::{self, BufRead as _, IoSlice, Read, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{ready, Context, Poll};

use bytes::BytesMut;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::TransportStream;

const TLS_RECORD_HEADER_LEN: usize = 5;

/// Every byte read from the server, until whoever holds the other end takes
/// the buffer. REALITY's ML-DSA-65 check reads the ServerHello out of it.
pub(crate) type ServerReadLog = Arc<Mutex<Option<Vec<u8>>>>;

/// A TLS client session and the carrier it runs over.
pub(crate) struct ClientTlsStream<IO> {
    io: IO,
    session: ClientConnection,
    /// The peer closed its side of the session, so reads report end of file
    /// without asking the session again.
    read_closed: bool,
    /// Our `close_notify` is queued or sent.
    write_closed: bool,
    /// Present while carrier reads stop at TLS record boundaries.
    records: Option<RecordMeter>,
    server_read_log: Option<ServerReadLog>,
}

impl<IO> ClientTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Completes a handshake with `server_name` over `io`.
    pub(crate) async fn connect(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        io: IO,
    ) -> io::Result<Self> {
        Self::handshake(config, server_name, io, None, None).await
    }

    /// [`connect`](Self::connect) for a session that Vision may unwrap.
    ///
    /// No carrier read crosses the end of the TLS record it is in, so the
    /// session never holds a byte that is not part of a record, and the bytes
    /// after the peer's last record are still in the carrier when a direct
    /// read asks for them. [`release_record_alignment`] lifts the limit.
    /// `server_read_log`, when given, receives every byte read until its
    /// holder takes the buffer or the alignment is released.
    ///
    /// [`release_record_alignment`]: Self::release_record_alignment
    pub(crate) async fn connect_record_aligned(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        io: IO,
        server_read_log: Option<ServerReadLog>,
    ) -> io::Result<Self> {
        Self::handshake(
            config,
            server_name,
            io,
            Some(RecordMeter::new()),
            server_read_log,
        )
        .await
    }

    async fn handshake(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        io: IO,
        records: Option<RecordMeter>,
        server_read_log: Option<ServerReadLog>,
    ) -> io::Result<Self> {
        let session = ClientConnection::new(config, server_name).map_err(io::Error::other)?;
        let mut stream = Self {
            io,
            session,
            read_closed: false,
            write_closed: false,
            records,
            server_read_log,
        };
        let mut need_flush = false;
        poll_fn(|cx| stream.poll_handshake(cx, &mut need_flush)).await?;
        Ok(stream)
    }

    fn poll_handshake(
        &mut self,
        cx: &mut Context<'_>,
        need_flush: &mut bool,
    ) -> Poll<io::Result<()>> {
        while self.session.is_handshaking() {
            let mut progressed = false;
            let mut blocked = false;

            while self.session.wants_write() {
                match self.write_io(cx) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    Poll::Ready(Ok(_)) => {
                        progressed = true;
                        *need_flush = true;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        blocked = true;
                        break;
                    }
                }
            }

            if *need_flush {
                match Pin::new(&mut self.io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => *need_flush = false,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => blocked = true,
                }
            }

            let mut eof = false;
            while !eof && self.session.wants_read() {
                match self.read_io(cx) {
                    Poll::Ready(Ok(0)) => eof = true,
                    Poll::Ready(Ok(_)) => progressed = true,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => {
                        blocked = true;
                        break;
                    }
                }
            }

            if !self.session.is_handshaking() {
                break;
            }
            if eof {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake eof",
                )));
            }
            // Every direction that could not move registered the waker.
            if blocked && !progressed {
                return Poll::Pending;
            }
        }

        // What is left of our last flight.
        ready!(self.poll_write_queued(cx))?;
        Pin::new(&mut self.io).poll_flush(cx)
    }

    /// Reads carrier bytes into the session once and has it process them.
    /// `Ok(0)` is the carrier's end of file, or a session that already saw
    /// the peer's `close_notify` and reads nothing more.
    fn read_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut reader = CarrierReader {
            io: &mut self.io,
            cx,
            records: self.records.as_mut(),
            server_read_log: &mut self.server_read_log,
        };
        let read = match self.session.read_tls(&mut reader) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
        };

        if let Err(error) = self.session.process_new_packets() {
            // The session queued the alert that describes the failure: try
            // to send it, without letting that outrank the failure itself.
            let _ = self.write_io(cx);
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }

        Poll::Ready(Ok(read))
    }

    /// Hands the carrier the records the session has queued, as one vectored
    /// write. `Ok(0)` is a carrier that took nothing.
    fn write_io(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let mut writer = CarrierWriter {
            io: &mut self.io,
            cx,
        };
        match self.session.write_tls(&mut writer) {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            result => Poll::Ready(result),
        }
    }

    /// Writes every queued record to the carrier.
    fn poll_write_queued(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.session.wants_write() {
            if ready!(self.write_io(cx))? == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
        }
        Poll::Ready(Ok(()))
    }

    /// [`poll_write_queued`](Self::poll_write_queued) for the write paths,
    /// which report what the session accepted rather than wait for the
    /// carrier: `Ok(false)` when the carrier would block with records left.
    fn write_queued_or_block(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        match self.poll_write_queued(cx) {
            Poll::Ready(Ok(())) => Ok(true),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Ok(false),
        }
    }
}

impl<IO> ClientTlsStream<IO> {
    /// The carrier under the session.
    pub(crate) fn carrier_mut(&mut self) -> &mut IO {
        &mut self.io
    }

    /// The application protocol the handshake negotiated.
    pub(crate) fn alpn_protocol(&self) -> Option<&[u8]> {
        self.session.alpn_protocol()
    }

    /// Lets carrier reads take as much as the session asks for, and drops the
    /// read log. For a session that will never be unwrapped.
    pub(crate) fn release_record_alignment(&mut self) {
        self.records = None;
        self.server_read_log = None;
    }

    /// Whether the session holds the start of a record whose end is still in
    /// the carrier. Always `false` once the alignment is released, when
    /// nothing tracks it.
    pub(crate) fn inside_record(&self) -> bool {
        self.records
            .as_ref()
            .is_some_and(|records| !records.at_boundary())
    }

    /// Moves the plaintext the session has decrypted and not yet returned
    /// into `output`.
    pub(crate) fn take_decrypted(&mut self, output: &mut BytesMut) -> io::Result<()> {
        loop {
            let chunk = match self.session.reader().into_first_chunk() {
                Ok(chunk) => chunk,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            };
            if chunk.is_empty() {
                return Ok(());
            }
            let len = chunk.len();
            output.extend_from_slice(chunk);
            self.session.reader().consume(len);
        }
    }
}

impl<IO> AsyncRead for ClientTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Returns plaintext from at most one record, and reads the carrier only
    /// while the session has none to return: a read never goes past the
    /// record that satisfied it, however much room `output` has.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_closed {
            return Poll::Ready(Ok(()));
        }

        let mut io_pending = false;
        while this.session.wants_read() {
            match this.read_io(cx) {
                Poll::Ready(Ok(0)) => break,
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(error)) => {
                    if error.kind() == io::ErrorKind::ConnectionAborted {
                        this.read_closed = true;
                    }
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => {
                    io_pending = true;
                    break;
                }
            }
        }

        let taken = match this.session.reader().into_first_chunk() {
            // The peer's `close_notify`, with nothing left to return.
            Ok([]) => {
                this.read_closed = true;
                return Poll::Ready(Ok(()));
            }
            Ok(chunk) => {
                let len = chunk.len().min(output.remaining());
                output.put_slice(&chunk[..len]);
                len
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if !io_pending {
                    // The session wants no read and has no plaintext, so no
                    // carrier registered the waker.
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            Err(error) => {
                if error.kind() == io::ErrorKind::ConnectionAborted {
                    this.read_closed = true;
                }
                return Poll::Ready(Err(error));
            }
        };
        this.session.reader().consume(taken);
        Poll::Ready(Ok(()))
    }
}

impl<IO> AsyncWrite for ClientTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    /// Accepts what the session's send buffer has room for and passes the
    /// records on. A write the session accepted is reported even when the
    /// carrier has not taken its records yet: `poll_flush` sends them.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut written = 0;
        while written != input.len() {
            written += this.session.writer().write(&input[written..])?;
            if !this.write_queued_or_block(cx)? {
                return if written == 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(written))
                };
            }
        }
        Poll::Ready(Ok(written))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        inputs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if inputs.iter().all(|input| input.is_empty()) {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();
        loop {
            let written = this.session.writer().write_vectored(inputs)?;
            let sent = this.write_queued_or_block(cx)?;
            if written != 0 {
                return Poll::Ready(Ok(written));
            }
            if !sent {
                return Poll::Pending;
            }
            // The send buffer was full and has drained: offer the input again.
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.session.writer().flush()?;
        ready!(this.poll_write_queued(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    /// Sends `close_notify`, then shuts the carrier down.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_closed {
            this.session.send_close_notify();
            this.write_closed = true;
        }
        ready!(this.poll_write_queued(cx))?;

        Poll::Ready(match ready!(Pin::new(&mut this.io).poll_shutdown(cx)) {
            // A carrier that is already gone has nothing left to shut down.
            Err(error) if error.kind() == io::ErrorKind::NotConnected => Ok(()),
            result => result,
        })
    }
}

/// TLS that Vision never unwraps: the session under an HTTP-based stream
/// transport, where Vision requires VLESS encryption and its Direct command
/// removes only that layer, and the sessions `TlsConnector` dials for DNS and
/// probes. Direct I/O therefore stays inside the session. The raw transport's
/// TLS, which Vision does unwrap, is a `PenetratingTlsStream`.
impl<IO> TransportStream for ClientTlsStream<IO>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin,
{
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

/// Follows the TLS record framing of the bytes read from the carrier, so
/// that a read can be told where the record it is in ends.
struct RecordMeter {
    header: [u8; TLS_RECORD_HEADER_LEN],
    header_len: usize,
    payload_remaining: usize,
}

impl RecordMeter {
    fn new() -> Self {
        Self {
            header: [0; TLS_RECORD_HEADER_LEN],
            header_len: 0,
            payload_remaining: 0,
        }
    }

    /// Whether every record seen so far is complete.
    fn at_boundary(&self) -> bool {
        self.header_len == 0
    }

    /// How much of `requested` the next read may take: the rest of the record
    /// header, or of the record's payload once its length is known.
    fn next_limit(&self, requested: usize) -> usize {
        if self.header_len < self.header.len() {
            requested.min(self.header.len() - self.header_len)
        } else {
            requested.min(self.payload_remaining)
        }
    }

    /// Accounts for bytes read within [`next_limit`](Self::next_limit).
    fn observe(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        if self.header_len < self.header.len() {
            let len = (self.header.len() - self.header_len).min(bytes.len());
            self.header[self.header_len..self.header_len + len].copy_from_slice(&bytes[..len]);
            self.header_len += len;
            if self.header_len == self.header.len() {
                self.payload_remaining =
                    u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                if self.payload_remaining == 0 {
                    self.header_len = 0;
                }
            }
            return;
        }

        self.payload_remaining = self.payload_remaining.saturating_sub(bytes.len());
        if self.payload_remaining == 0 {
            self.header_len = 0;
        }
    }
}

/// The carrier as the blocking reader `read_tls` takes: a pending carrier is
/// `WouldBlock`.
struct CarrierReader<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
    records: Option<&'a mut RecordMeter>,
    server_read_log: &'a mut Option<ServerReadLog>,
}

impl<IO> Read for CarrierReader<'_, '_, IO>
where
    IO: AsyncRead + Unpin,
{
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let limit = match &self.records {
            Some(records) => records.next_limit(output.len()),
            None => output.len(),
        };
        // The session's buffer is initialized, so the carrier reads straight
        // into it: a record-bounded read costs no copy.
        let mut output = ReadBuf::new(&mut output[..limit]);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut output) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Err(error),
            Poll::Pending => return Err(io::ErrorKind::WouldBlock.into()),
        }

        let filled = output.filled();
        if let Some(records) = &mut self.records {
            records.observe(filled);
        }
        if let Some(server_read_log) = &*self.server_read_log {
            if !filled.is_empty() {
                let mut log = server_read_log
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                match log.as_mut() {
                    Some(log) => log.extend_from_slice(filled),
                    // The verifier took the log; stop paying for the lock on
                    // every later read.
                    None => {
                        drop(log);
                        *self.server_read_log = None;
                    }
                }
            }
        }
        Ok(filled.len())
    }
}

/// The carrier as the blocking writer `write_tls` takes.
struct CarrierWriter<'a, 'b, IO> {
    io: &'a mut IO,
    cx: &'a mut Context<'b>,
}

impl<IO> CarrierWriter<'_, '_, IO>
where
    IO: AsyncWrite + Unpin,
{
    fn poll_with<T>(
        &mut self,
        poll: impl FnOnce(Pin<&mut IO>, &mut Context<'_>) -> Poll<io::Result<T>>,
    ) -> io::Result<T> {
        match poll(Pin::new(&mut *self.io), self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

impl<IO> Write for CarrierWriter<'_, '_, IO>
where
    IO: AsyncWrite + Unpin,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.poll_with(|io, cx| io.poll_write(cx, input))
    }

    // rustls hands its queued records over as one vectored write; keep that
    // a single carrier write rather than one per record.
    fn write_vectored(&mut self, inputs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.poll_with(|io, cx| io.poll_write_vectored(cx, inputs))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.poll_with(|io, cx| io.poll_flush(cx))
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig, SupportedProtocolVersion};
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const SERVER_NAME: &str = "server.test";
    const TLS12_AND_TLS13: &[&SupportedProtocolVersion] =
        &[&rustls::version::TLS13, &rustls::version::TLS12];
    const TLS12: &[&SupportedProtocolVersion] = &[&rustls::version::TLS12];

    type ServerTlsStream = tokio_rustls::server::TlsStream<DuplexStream>;

    struct Certificate {
        der: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    }

    fn certificate() -> Certificate {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![SERVER_NAME.to_owned()])
                .expect("generate self-signed certificate");
        Certificate {
            der: cert.der().clone(),
            key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
        }
    }

    fn client_config(
        trusted: &CertificateDer<'static>,
        versions: &[&'static SupportedProtocolVersion],
        alpn: &[&[u8]],
    ) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(trusted.clone()).expect("add test root");
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(versions)
                .expect("ring provider supports the test versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        Arc::new(config)
    }

    fn server_config(certificate: Certificate, alpn: &[&[u8]]) -> Arc<ServerConfig> {
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring provider supports the default versions")
                .with_no_client_auth()
                .with_single_cert(vec![certificate.der], certificate.key)
                .expect("server certificate config");
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        Arc::new(config)
    }

    fn server_name() -> ServerName<'static> {
        ServerName::try_from(SERVER_NAME).expect("server name")
    }

    /// A client and a server config that trust each other.
    fn configs(
        versions: &[&'static SupportedProtocolVersion],
    ) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
        let certificate = certificate();
        (
            client_config(&certificate.der, versions, &[]),
            server_config(certificate, &[]),
        )
    }

    /// Both ends of a session over an in-memory pipe that holds `pipe` bytes
    /// in each direction.
    async fn connect_pair(
        versions: &[&'static SupportedProtocolVersion],
        pipe: usize,
    ) -> (ClientTlsStream<DuplexStream>, ServerTlsStream) {
        let (client, server) = configs(versions);
        let (client_io, server_io) = duplex(pipe);
        let server = tokio::spawn(TlsAcceptor::from(server).accept(server_io));
        let client = ClientTlsStream::connect(client, server_name(), client_io)
            .await
            .expect("client handshake");
        let server = server
            .await
            .expect("server task")
            .expect("server handshake");
        (client, server)
    }

    /// A carrier that remembers what every read asked for and got.
    struct TracedCarrier {
        io: DuplexStream,
        reads: Arc<Mutex<Vec<TracedRead>>>,
    }

    struct TracedRead {
        requested: usize,
        bytes: Vec<u8>,
    }

    impl AsyncRead for TracedCarrier {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            output: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let requested = output.remaining();
            let before = output.filled().len();
            ready!(Pin::new(&mut this.io).poll_read(cx, output))?;
            this.reads.lock().unwrap().push(TracedRead {
                requested,
                bytes: output.filled()[before..].to_vec(),
            });
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TracedCarrier {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            input: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().io).poll_write(cx, input)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    /// A record-aligned client over a traced carrier, its server, and the
    /// trace. The pipe holds the whole of anything a test sends.
    async fn connect_traced(
        server_read_log: Option<ServerReadLog>,
    ) -> (
        ClientTlsStream<TracedCarrier>,
        ServerTlsStream,
        Arc<Mutex<Vec<TracedRead>>>,
    ) {
        let (client, server) = configs(TLS12_AND_TLS13);
        let (client_io, server_io) = duplex(256 * 1024);
        let reads = Arc::new(Mutex::new(Vec::new()));
        let carrier = TracedCarrier {
            io: client_io,
            reads: reads.clone(),
        };
        let server = tokio::spawn(TlsAcceptor::from(server).accept(server_io));
        let client = ClientTlsStream::connect_record_aligned(
            client,
            server_name(),
            carrier,
            server_read_log,
        )
        .await
        .expect("client handshake");
        let server = server
            .await
            .expect("server task")
            .expect("server handshake");
        (client, server, reads)
    }

    fn traced_bytes(reads: &Mutex<Vec<TracedRead>>) -> Vec<u8> {
        reads
            .lock()
            .unwrap()
            .iter()
            .flat_map(|read| read.bytes.iter().copied())
            .collect()
    }

    /// The offsets in `stream` where a record's header ends and where the
    /// record ends, and the number of whole records. Panics unless `stream`
    /// is whole records.
    fn record_edges(stream: &[u8]) -> (Vec<usize>, usize) {
        let mut edges = Vec::new();
        let mut records = 0;
        let mut offset = 0;
        while offset < stream.len() {
            let header = stream
                .get(offset..offset + TLS_RECORD_HEADER_LEN)
                .expect("the carrier bytes end inside a record header");
            let payload = u16::from_be_bytes([header[3], header[4]]) as usize;
            edges.push(offset + TLS_RECORD_HEADER_LEN);
            offset += TLS_RECORD_HEADER_LEN + payload;
            assert!(
                offset <= stream.len(),
                "the carrier bytes end inside a record"
            );
            edges.push(offset);
            records += 1;
        }
        (edges, records)
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index * 31 + 7) as u8).collect()
    }

    /// The pipe is far smaller than a handshake flight or a record, so every
    /// read and write path meets a carrier that is not ready.
    async fn round_trip_through_a_narrow_pipe(versions: &[&'static SupportedProtocolVersion]) {
        let (client, server) = configs(versions);
        let (client_io, server_io) = duplex(61);
        let uplink = pattern(300_000);
        let downlink: Vec<u8> = pattern(300_000).into_iter().rev().collect();
        // The server runs on its own: a TLS 1.3 server still has its session
        // tickets to push through the pipe when its handshake returns.
        let server = tokio::spawn({
            let downlink = downlink.clone();
            let uplink_len = uplink.len();
            async move {
                let server = TlsAcceptor::from(server)
                    .accept(server_io)
                    .await
                    .expect("server handshake");
                let (mut read, mut write) = tokio::io::split(server);
                let mut received = vec![0; uplink_len];
                let (sent, read) = tokio::join!(
                    async {
                        write.write_all(&downlink).await?;
                        write.flush().await
                    },
                    read.read_exact(&mut received),
                );
                sent.expect("server write");
                read.expect("server read");
                received
            }
        });

        let client = ClientTlsStream::connect(client, server_name(), client_io)
            .await
            .expect("client handshake");
        let (mut read, mut write) = tokio::io::split(client);
        let mut received_downlink = vec![0; downlink.len()];
        let (sent, read) = tokio::join!(
            async {
                write.write_all(&uplink).await?;
                write.flush().await
            },
            read.read_exact(&mut received_downlink),
        );

        sent.expect("client write");
        read.expect("client read");
        assert_eq!(received_downlink, downlink);
        assert_eq!(server.await.expect("server task"), uplink);
    }

    #[tokio::test]
    async fn tls13_round_trips_through_a_narrow_pipe() {
        round_trip_through_a_narrow_pipe(TLS12_AND_TLS13).await;
    }

    #[tokio::test]
    async fn tls12_round_trips_through_a_narrow_pipe() {
        round_trip_through_a_narrow_pipe(TLS12).await;
    }

    #[tokio::test]
    async fn the_negotiated_alpn_is_reported() {
        let certificate = certificate();
        let client = client_config(&certificate.der, TLS12_AND_TLS13, &[b"h2", b"http/1.1"]);
        let server = server_config(certificate, &[b"http/1.1"]);
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(TlsAcceptor::from(server).accept(server_io));

        let client = ClientTlsStream::connect(client, server_name(), client_io)
            .await
            .expect("client handshake");

        assert_eq!(client.alpn_protocol(), Some(&b"http/1.1"[..]));
        server
            .await
            .expect("server task")
            .expect("server handshake");
    }

    #[tokio::test]
    async fn a_certificate_the_client_rejects_fails_the_handshake_with_an_alert() {
        let presented = certificate();
        let trusted = certificate();
        let client = client_config(&trusted.der, TLS12_AND_TLS13, &[]);
        let server = server_config(presented, &[]);
        let (client_io, server_io) = duplex(64 * 1024);
        let server = tokio::spawn(TlsAcceptor::from(server).accept(server_io));

        let error = ClientTlsStream::connect(client, server_name(), client_io)
            .await
            .err()
            .expect("the client rejects the certificate");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            error
                .get_ref()
                .and_then(|source| source.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::InvalidCertificate(_))
        ));
        // The client's last write told the server why.
        let server_error = server
            .await
            .expect("server task")
            .err()
            .expect("the server handshake fails");
        assert!(matches!(
            server_error
                .get_ref()
                .and_then(|source| source.downcast_ref::<rustls::Error>()),
            Some(rustls::Error::AlertReceived(_))
        ));
    }

    #[tokio::test]
    async fn a_carrier_that_ends_mid_handshake_is_an_unexpected_eof() {
        let (client, _server) = configs(TLS12_AND_TLS13);
        let (client_io, mut server_io) = duplex(64 * 1024);
        let server = tokio::spawn(async move {
            // Take the ClientHello and hang up.
            let mut hello = [0; 5];
            server_io.read_exact(&mut hello).await.expect("read hello");
        });

        let error = ClientTlsStream::connect(client, server_name(), client_io)
            .await
            .err()
            .expect("the handshake cannot finish");

        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        server.await.expect("server task");
    }

    #[tokio::test]
    async fn shutdown_sends_close_notify_before_closing_the_carrier() {
        let (mut client, mut server) = connect_pair(TLS12_AND_TLS13, 64 * 1024).await;

        client.write_all(b"last words").await.expect("write");
        client.shutdown().await.expect("shutdown");

        // rustls reports the end of a session that was not closed with
        // `close_notify` as an error, so a clean end of file is the alert.
        let mut received = Vec::new();
        server
            .read_to_end(&mut received)
            .await
            .expect("the server sees a clean end of the session");
        assert_eq!(received, b"last words");
    }

    #[tokio::test]
    async fn the_peers_close_notify_is_end_of_file() {
        let (mut client, mut server) = connect_pair(TLS12_AND_TLS13, 64 * 1024).await;

        server.write_all(b"goodbye").await.expect("write");
        server.shutdown().await.expect("server shutdown");

        let mut received = Vec::new();
        client
            .read_to_end(&mut received)
            .await
            .expect("clean end of file");
        assert_eq!(received, b"goodbye");
        // And stays so.
        assert_eq!(client.read(&mut [0; 8]).await.expect("read again"), 0);
        // Our side is still open for writing.
        client.write_all(b"ack").await.expect("write after EOF");
        client.flush().await.expect("flush after EOF");
    }

    #[tokio::test]
    async fn a_carrier_that_ends_without_close_notify_is_an_unexpected_eof() {
        let (mut client, mut server) = connect_pair(TLS12_AND_TLS13, 64 * 1024).await;

        server.write_all(b"cut").await.expect("write");
        server.flush().await.expect("flush");
        let (server_io, _) = server.into_inner();
        drop(server_io);

        let mut received = [0; 3];
        client
            .read_exact(&mut received)
            .await
            .expect("data before the cut");
        assert_eq!(&received, b"cut");
        let error = client
            .read(&mut [0; 8])
            .await
            .expect_err("a truncated session");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn a_vectored_write_takes_every_slice() {
        let (mut client, mut server) = connect_pair(TLS12_AND_TLS13, 64 * 1024).await;
        assert!(client.is_write_vectored());

        let written = client
            .write_vectored(&[
                IoSlice::new(b"one "),
                IoSlice::new(b""),
                IoSlice::new(b"two "),
                IoSlice::new(b"three"),
            ])
            .await
            .expect("vectored write");
        client.flush().await.expect("flush");

        assert_eq!(written, 13);
        let mut received = [0; 13];
        server.read_exact(&mut received).await.expect("read");
        assert_eq!(&received, b"one two three");
        assert_eq!(
            client
                .write_vectored(&[IoSlice::new(b""), IoSlice::new(b"")])
                .await
                .expect("empty vectored write"),
            0
        );
    }

    #[tokio::test]
    async fn a_read_returns_one_record_however_much_room_it_has() {
        let (mut client, mut server) = connect_pair(TLS12_AND_TLS13, 64 * 1024).await;

        // Two records, both in the pipe before the client reads.
        server.write_all(b"one").await.expect("write");
        server.flush().await.expect("flush");
        server.write_all(b"two").await.expect("write");
        server.flush().await.expect("flush");

        let mut output = [0; 1024];
        let read = client.read(&mut output).await.expect("first read");
        assert_eq!(&output[..read], b"one");
        let read = client.read(&mut output).await.expect("second read");
        assert_eq!(&output[..read], b"two");
    }

    #[tokio::test]
    async fn a_record_aligned_read_leaves_the_next_record_in_the_carrier() {
        let (mut client, mut server, reads) = connect_traced(None).await;

        server.write_all(b"one").await.expect("write");
        server.flush().await.expect("flush");
        server.write_all(b"two").await.expect("write");
        server.flush().await.expect("flush");

        let mut output = [0; 1024];
        let read = client.read(&mut output).await.expect("first read");
        assert_eq!(&output[..read], b"one");
        // Whole records and nothing more: `record_edges` panics otherwise.
        let (_, records_after_one) = record_edges(&traced_bytes(&reads));
        assert!(!client.inside_record());

        let read = client.read(&mut output).await.expect("second read");
        assert_eq!(&output[..read], b"two");
        let (_, records_after_two) = record_edges(&traced_bytes(&reads));
        assert_eq!(records_after_two, records_after_one + 1);
    }

    #[tokio::test]
    async fn record_aligned_reads_never_cross_a_record_edge() {
        let (mut client, mut server, reads) = connect_traced(None).await;

        // One byte, a record's worth, and a write that takes three records,
        // all in the pipe at once.
        let payload = pattern(1 + 5_000 + 40_000);
        for part in [&payload[..1], &payload[1..5_001], &payload[5_001..]] {
            server.write_all(part).await.expect("write");
            server.flush().await.expect("flush");
        }
        let mut received = vec![0; payload.len()];
        client.read_exact(&mut received).await.expect("read");
        assert_eq!(received, payload);

        let stream = traced_bytes(&reads);
        let (edges, _) = record_edges(&stream);
        let mut offset = 0;
        for read in reads.lock().unwrap().iter() {
            let next_edge = *edges
                .iter()
                .find(|edge| **edge > offset)
                .expect("a read past the last record");
            assert!(
                offset + read.requested <= next_edge,
                "a read at {offset} asked for {} bytes, past the edge at {next_edge}",
                read.requested
            );
            offset += read.bytes.len();
        }
        assert_eq!(offset, stream.len());
    }

    #[tokio::test]
    async fn releasing_the_alignment_lets_reads_ask_for_more_than_a_record() {
        let (mut client, mut server, reads) = connect_traced(None).await;
        let mut output = [0; 16];
        server.write_all(b"aligned").await.expect("write");
        server.flush().await.expect("flush");
        let read = client.read(&mut output).await.expect("aligned read");
        assert_eq!(&output[..read], b"aligned");

        client.release_record_alignment();
        let aligned_reads = reads.lock().unwrap().len();
        server.write_all(b"free").await.expect("write");
        server.flush().await.expect("flush");
        let read = client.read(&mut output).await.expect("free read");

        assert_eq!(&output[..read], b"free");
        assert!(!client.inside_record());
        let reads = reads.lock().unwrap();
        let first_free = &reads[aligned_reads];
        assert!(
            first_free.requested > TLS_RECORD_HEADER_LEN,
            "the first read after the release asked for {} bytes",
            first_free.requested
        );
        // And took the whole record in one read.
        assert!(first_free.bytes.len() > TLS_RECORD_HEADER_LEN);
    }

    #[tokio::test]
    async fn the_read_log_holds_every_carrier_byte_until_it_is_taken() {
        let log: ServerReadLog = Arc::new(Mutex::new(Some(Vec::new())));
        let (mut client, mut server, reads) = connect_traced(Some(log.clone())).await;
        let mut output = [0; 16];

        server.write_all(b"logged").await.expect("write");
        server.flush().await.expect("flush");
        let read = client.read(&mut output).await.expect("read");
        assert_eq!(&output[..read], b"logged");
        let logged = log.lock().unwrap().take().expect("the log");
        assert_eq!(logged, traced_bytes(&reads));
        // The server's first record is its ServerHello.
        assert_eq!(&logged[..3], &[0x16, 0x03, 0x03]);

        // Once the log is taken, the next read drops the stream's handle.
        server.write_all(b"unlogged").await.expect("write");
        server.flush().await.expect("flush");
        let read = client.read(&mut output).await.expect("read");
        assert_eq!(&output[..read], b"unlogged");
        assert_eq!(Arc::strong_count(&log), 1);
        assert!(log.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn releasing_the_alignment_drops_the_read_log() {
        let log: ServerReadLog = Arc::new(Mutex::new(Some(Vec::new())));
        let (mut client, _server, _reads) = connect_traced(Some(log.clone())).await;

        client.release_record_alignment();

        assert_eq!(Arc::strong_count(&log), 1);
    }

    #[tokio::test]
    async fn decrypted_plaintext_can_be_taken_out_of_the_session() {
        let (mut client, mut server) = connect_pair(TLS12_AND_TLS13, 64 * 1024).await;
        server.write_all(b"head and tail").await.expect("write");
        server.flush().await.expect("flush");
        let mut head = [0; 4];
        client.read_exact(&mut head).await.expect("read the head");

        let mut rest = BytesMut::new();
        client.take_decrypted(&mut rest).expect("take the rest");

        assert_eq!(&head, b"head");
        assert_eq!(&rest[..], b" and tail");
        // Nothing is left, and that is not an error.
        client.take_decrypted(&mut rest).expect("take nothing");
        assert_eq!(&rest[..], b" and tail");
    }

    #[test]
    fn the_meter_follows_headers_and_payloads_split_any_way() {
        let mut meter = RecordMeter::new();
        assert!(meter.at_boundary());
        assert_eq!(meter.next_limit(4096), 5);

        meter.observe(&[0x17, 0x03]);
        assert!(!meter.at_boundary());
        assert_eq!(meter.next_limit(4096), 3);
        meter.observe(&[0x03, 0x00, 0x0a]);
        assert_eq!(meter.next_limit(4096), 10);
        assert_eq!(meter.next_limit(4), 4);
        meter.observe(&[0; 4]);
        assert_eq!(meter.next_limit(4096), 6);
        meter.observe(&[0; 6]);
        assert!(meter.at_boundary());
        assert_eq!(meter.next_limit(4096), 5);

        // An empty record is over with its header.
        meter.observe(&[0x17, 0x03, 0x03, 0x00, 0x00]);
        assert!(meter.at_boundary());
        // An empty read is no progress.
        meter.observe(&[]);
        assert!(meter.at_boundary());
    }
}
