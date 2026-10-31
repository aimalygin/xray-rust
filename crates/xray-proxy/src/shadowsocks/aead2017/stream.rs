use super::{Method, Records, MAX_PAYLOAD_LENGTH, MAX_WRITE_PAYLOAD, TAG_LENGTH};
use crate::shadowsocks::address;
use rand::RngCore;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use xray_routing::{Network, Target};
use zeroize::{Zeroize, Zeroizing};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// One bounded client stream with no background tasks. As in Xray-core's
/// `WriteTCPRequest`, the request is the salt followed by a record carrying
/// only the target address; payload records follow. The response is the
/// server's salt and a record stream bound to it. A successful write owns its
/// complete plaintext; cancellation cannot duplicate a nonce or a record.
pub struct ClientStream<S> {
    inner: S,
    method: Arc<Method>,
    writer: Records,
    reader: Option<Records>,
    pending: Zeroizing<Vec<u8>>,
    pending_pos: usize,
    body: crate::record_buffer::RecordBuffer,
    plain_len: usize,
    plain_pos: usize,
    phase: Phase,
    failed: bool,
    eof: bool,
    write_closed: bool,
}

#[derive(Clone, Copy)]
enum Phase {
    Salt,
    Length,
    Payload,
    Plain,
}

impl<S> ClientStream<S> {
    pub fn new(inner: S, method: Arc<Method>, target: &Target) -> io::Result<Self> {
        let mut salt = Zeroizing::new(vec![0; method.cipher.key_len()]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| invalid("Shadowsocks random source failed"))?;
        Self::with_salt(inner, method, target, &salt)
    }

    fn with_salt(inner: S, method: Arc<Method>, target: &Target, salt: &[u8]) -> io::Result<Self> {
        if target.network != Network::Tcp || salt.len() != method.cipher.key_len() {
            return Err(invalid("invalid Shadowsocks AEAD stream request"));
        }
        let mut header = Zeroizing::new(address::encode(target)?);
        let mut writer = Records::new(&method, salt);
        let mut pending = Zeroizing::new(Vec::with_capacity(
            salt.len() + 2 + 2 * TAG_LENGTH + header.len() + TAG_LENGTH,
        ));
        pending.extend_from_slice(salt);
        let start = pending.len();
        pending.extend_from_slice(&(header.len() as u16).to_be_bytes());
        writer.seal_from(&mut pending, start)?;
        writer.seal(&mut header)?;
        pending.extend_from_slice(&header);
        Ok(Self {
            inner,
            method: method.clone(),
            writer,
            reader: None,
            pending,
            pending_pos: 0,
            body: crate::record_buffer::RecordBuffer::new(method.cipher.key_len(), 2 + TAG_LENGTH),
            plain_len: 0,
            plain_pos: 0,
            phase: Phase::Salt,
            failed: false,
            eof: false,
            write_closed: false,
        })
    }

    fn require_body(&mut self, length: usize, phase: Phase) {
        // Plaintext is erased as it is delivered, including partial reads.
        // Other phases can still contain a decrypted length.
        if !matches!(self.phase, Phase::Plain) {
            self.body.frame().zeroize();
        }
        self.body.advance(length);
        self.plain_len = 0;
        self.plain_pos = 0;
        self.phase = phase;
    }

    fn process_body(&mut self) -> io::Result<()> {
        match self.phase {
            Phase::Salt => {
                self.reader = Some(Records::new(&self.method, self.body.frame()));
                self.require_body(2 + TAG_LENGTH, Phase::Length);
            }
            Phase::Length => {
                self.reader.as_mut().unwrap().open(self.body.frame())?;
                let length =
                    u16::from_be_bytes(self.body.frame()[..2].try_into().unwrap()) as usize;
                if length == 0 {
                    // Xray's reader ends the stream at an empty record and
                    // never reads past it (`common/crypto/auth.go`).
                    self.body.frame().zeroize();
                    self.eof = true;
                    return Ok(());
                }
                if length > MAX_PAYLOAD_LENGTH {
                    return Err(invalid("Shadowsocks AEAD record exceeds 0x3FFF"));
                }
                self.require_body(length + TAG_LENGTH, Phase::Payload);
            }
            Phase::Payload => {
                self.plain_len = self.reader.as_mut().unwrap().open(self.body.frame())?;
                self.plain_pos = 0;
                self.phase = Phase::Plain;
            }
            Phase::Plain => unreachable!(),
        }
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> ClientStream<S> {
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_pos..]))
            {
                Ok(0) => {
                    self.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Ok(n) => self.pending_pos += n,
                Err(e) => {
                    self.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
        // Pending holds only ciphertext and the public salt. Keep the
        // allocation; the Zeroizing owner wipes its capacity on drop.
        self.pending.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(invalid("Shadowsocks AEAD stream failed")));
        }
        if out.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        // Advance buffered writes without letting their backpressure block
        // an already available response.
        if let Poll::Ready(result) = this.drain(cx) {
            result?;
        }
        for _ in 0..16 {
            if matches!(this.phase, Phase::Plain) {
                if this.plain_pos < this.plain_len {
                    let n = out.remaining().min(this.plain_len - this.plain_pos);
                    out.put_slice(&this.body.frame()[this.plain_pos..this.plain_pos + n]);
                    crate::erase::erase(&mut this.body.frame()[this.plain_pos..this.plain_pos + n]);
                    this.plain_pos += n;
                    return Poll::Ready(Ok(()));
                }
                this.require_body(2 + TAG_LENGTH, Phase::Length);
            }
            match ready!(this.body.poll_frame(&mut this.inner, cx)) {
                Ok(true) => {}
                Ok(false) if matches!(this.phase, Phase::Length) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                result => {
                    this.failed = true;
                    return Poll::Ready(Err(result
                        .err()
                        .unwrap_or_else(|| io::ErrorKind::UnexpectedEof.into())));
                }
            }
            if let Err(e) = this.process_body() {
                this.failed = true;
                return Poll::Ready(Err(e));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed || this.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.drain(cx))?;
        // Never emit an empty record: Xray's reader treats it as end of stream.
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = input.len().min(MAX_WRITE_PAYLOAD);
        this.pending.reserve_exact(2 + TAG_LENGTH + n + TAG_LENGTH);
        this.pending.extend_from_slice(&(n as u16).to_be_bytes());
        let result = this.writer.seal(&mut this.pending).and_then(|_| {
            let start = this.pending.len();
            this.pending.extend_from_slice(&input[..n]);
            this.writer.seal_from(&mut this.pending, start)
        });
        if let Err(e) = result {
            this.pending.as_mut_slice().zeroize();
            this.pending.clear();
            this.failed = true;
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.drain(cx))?;
        let result = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        if result.is_err() {
            this.failed = true;
        }
        Poll::Ready(result)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        let this = self.get_mut();
        this.write_closed = true;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{fixtures, method, unhex};
    use super::*;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_routing::TargetAddr;

    fn target() -> Target {
        Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Tcp)
    }

    #[tokio::test]
    async fn request_records_and_chunking_match_pinned_go() {
        for case in fixtures() {
            let request = unhex(case["request"].as_str().unwrap());
            let salt = &request[..case["saltLength"].as_u64().unwrap() as usize];
            let mut stream =
                ClientStream::with_salt(tokio::io::sink(), method(&case), &target(), salt).unwrap();
            assert_eq!(*stream.pending, request, "{}", case["method"]);
            stream.write_all(b"after-header").await.unwrap();
            assert_eq!(*stream.pending, unhex(case["nextRecord"].as_str().unwrap()));
            stream.flush().await.unwrap();
            // Capture one 20000-byte write the way Xray's writer splits it.
            let (inner, mut peer) = tokio::io::duplex(1 << 16);
            let mut stream =
                ClientStream::with_salt(inner, method(&case), &target(), salt).unwrap();
            stream.write_all(b"after-header").await.unwrap();
            stream.write_all(&[0x5a; 20000]).await.unwrap();
            stream.flush().await.unwrap();
            drop(stream);
            let mut wire = Vec::new();
            peer.read_to_end(&mut wire).await.unwrap();
            let large = &wire[request.len() + 12 + 2 + 2 * TAG_LENGTH..];
            assert_eq!(
                large.len() as u64,
                case["largeWriteLength"].as_u64().unwrap()
            );
            assert_eq!(
                Sha256::digest(large).to_vec(),
                unhex(case["largeWriteSha256"].as_str().unwrap())
            );
        }
    }

    #[tokio::test]
    async fn go_response_ends_at_empty_record_without_reading_further() {
        for case in fixtures() {
            let (inner, mut peer) = tokio::io::duplex(1 << 16);
            let mut stream = ClientStream::new(inner, method(&case), &target()).unwrap();
            stream.flush().await.unwrap();
            let response = unhex(case["response"].as_str().unwrap());
            // Byte-at-a-time delivery exercises every partial-frame state.
            for byte in &response {
                peer.write_all(&[*byte]).await.unwrap();
            }
            let mut out = Vec::new();
            stream.read_to_end(&mut out).await.unwrap();
            assert_eq!(out, b"server payload");
            assert_eq!(stream.read(&mut [0; 8]).await.unwrap(), 0);
        }
    }

    fn response(method: &Method, records: &[&[u8]]) -> Vec<u8> {
        let salt = vec![0x72; method.cipher.key_len()];
        let mut cipher = Records::new(method, &salt);
        let mut wire = salt;
        for record in records {
            let mut length = (record.len() as u16).to_be_bytes().to_vec();
            cipher.seal(&mut length).unwrap();
            wire.extend(length);
            let mut body = record.to_vec();
            cipher.seal(&mut body).unwrap();
            wire.extend(body);
        }
        wire
    }

    #[tokio::test]
    async fn response_faults_fail_closed_and_clean_eof_is_accepted() {
        for case in fixtures() {
            let method = method(&case);
            let big = vec![1; MAX_PAYLOAD_LENGTH];
            for scenario in 0..6 {
                let mut wire = match scenario {
                    4 => response(&method, &[&big, &[2; MAX_PAYLOAD_LENGTH + 1]]),
                    _ => response(&method, &[b"server payload", &big]),
                };
                match scenario {
                    1 => {
                        let last = wire.len() - 1;
                        wire[last] ^= 1;
                    }
                    2 => {
                        wire.pop();
                    }
                    3 => wire[0] ^= 1,
                    5 => wire.truncate(method.cipher.key_len() - 1),
                    _ => {}
                }
                let (inner, mut peer) = tokio::io::duplex(1 << 16);
                let mut stream = ClientStream::with_salt(
                    inner,
                    method.clone(),
                    &target(),
                    &vec![4; method.cipher.key_len()],
                )
                .unwrap();
                stream.flush().await.unwrap();
                let (_, read) = tokio::join!(
                    async {
                        peer.write_all(&wire).await.unwrap();
                        peer.shutdown().await.unwrap();
                    },
                    async {
                        let mut out = Vec::new();
                        stream.read_to_end(&mut out).await.map(|_| out)
                    }
                );
                if scenario == 0 {
                    let out = read.unwrap();
                    assert_eq!(&out[..14], b"server payload");
                    assert_eq!(out.len(), 14 + MAX_PAYLOAD_LENGTH);
                } else {
                    assert!(read.is_err(), "scenario {scenario}");
                    assert!(stream.read(&mut [0; 8]).await.is_err());
                }
            }
        }
    }

    #[tokio::test]
    async fn pending_frame_is_reused_and_empty_writes_emit_nothing() {
        let case = &fixtures()[0];
        let mut stream = ClientStream::new(tokio::io::sink(), method(case), &target()).unwrap();
        stream.flush().await.unwrap();
        stream.write_all(&[7; MAX_WRITE_PAYLOAD]).await.unwrap();
        assert_eq!(stream.pending.len(), 2 + 2 * TAG_LENGTH + MAX_WRITE_PAYLOAD);
        assert_eq!(stream.pending.len(), 8192);
        let pointer = stream.pending.as_ptr();
        for size in [1, 1200, MAX_WRITE_PAYLOAD, 32] {
            stream.flush().await.unwrap();
            stream.write_all(&vec![8; size]).await.unwrap();
            assert_eq!(stream.pending.as_ptr(), pointer);
        }
        stream.flush().await.unwrap();
        assert_eq!(stream.write(&[]).await.unwrap(), 0);
        assert!(stream.pending.is_empty());
        let udp = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Udp);
        assert!(ClientStream::new(tokio::io::sink(), method(case), &udp).is_err());
    }
}
