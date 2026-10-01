use super::{
    crypto::{self, Records},
    *,
};
use rand::RngCore;
use std::{
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// One bounded stream, with no background tasks. A successful write owns its
/// complete plaintext; cancellation cannot duplicate a nonce or a partial record.
pub struct ClientStream<S> {
    inner: S,
    method: Arc<Method>,
    request_salt: Zeroizing<Vec<u8>>,
    writer: Records,
    reader: Option<Records>,
    pending: Zeroizing<Vec<u8>>,
    pending_pos: usize,
    body: Zeroizing<Vec<u8>>,
    body_pos: usize,
    plain_pos: usize,
    phase: Phase,
    failed: bool,
    eof: bool,
    write_closed: bool,
}
#[derive(Clone, Copy)]
enum Phase {
    Header,
    Length,
    Payload,
    Plain,
}
impl<S> ClientStream<S> {
    pub fn new(inner: S, method: Arc<Method>, target: &Target) -> io::Result<Self> {
        let mut salt = Zeroizing::new(vec![0; method.cipher.key_len()]);
        rand::rngs::OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| invalid("Shadowsocks 2022 random source failed"))?;
        let padding = (rand::random::<u16>() as usize % 900) + 1;
        Self::with_entropy(inner, method, target, &salt, now()?, padding, &[])
    }
    fn with_entropy(
        inner: S,
        method: Arc<Method>,
        target: &Target,
        salt: &[u8],
        timestamp: u64,
        padding: usize,
        payload: &[u8],
    ) -> io::Result<Self> {
        let mut variable = Zeroizing::new(encode_address(target)?);
        if target.network != Network::Tcp
            || (padding == 0 && payload.is_empty())
            || padding > 900
            || salt.len() != method.cipher.key_len()
        {
            return Err(invalid("invalid Shadowsocks 2022 stream request"));
        }
        variable.extend_from_slice(&(padding as u16).to_be_bytes());
        let padded_len = variable.len() + padding;
        variable.resize(padded_len, 0);
        variable.extend_from_slice(payload);
        if variable.len() > MAX_RECORD_LENGTH {
            return Err(invalid("Shadowsocks 2022 initial payload too large"));
        }
        let mut fixed = Zeroizing::new(vec![0]);
        fixed.extend_from_slice(&timestamp.to_be_bytes());
        fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
        let mut pending = Zeroizing::new(salt.to_vec());
        for keys in method.keys.windows(2) {
            let key = crypto::derive("shadowsocks 2022 identity subkey", &keys[0], salt);
            let mut identity = crypto::identity_hash(&keys[1]);
            crypto::block(&key[..method.cipher.key_len()], &mut identity, false);
            pending.extend_from_slice(&*identity);
        }
        let mut writer = Records::new(&method, salt);
        writer.seal(&mut fixed)?;
        writer.seal(&mut variable)?;
        pending.extend_from_slice(&fixed);
        pending.extend_from_slice(&variable);
        let header_len = method.cipher.key_len() * 2 + 11 + TAG_LENGTH;
        Ok(Self {
            inner,
            method,
            request_salt: Zeroizing::new(salt.to_vec()),
            writer,
            reader: None,
            pending,
            pending_pos: 0,
            body: Zeroizing::new(vec![0; header_len]),
            body_pos: 0,
            plain_pos: 0,
            phase: Phase::Header,
            failed: false,
            eof: false,
            write_closed: false,
        })
    }
    fn require_body(&mut self, length: usize, phase: Phase) {
        // Plaintext is erased as it is delivered, including partial reads.
        // Other phases can still contain a decrypted header/length.
        if !matches!(self.phase, Phase::Plain) {
            self.body.as_mut_slice().zeroize();
        }
        self.body.clear();
        self.body.resize(length, 0);
        self.body_pos = 0;
        self.plain_pos = 0;
        self.phase = phase;
    }
    fn process_body(&mut self) -> io::Result<()> {
        match self.phase {
            Phase::Header => {
                let key_len = self.method.cipher.key_len();
                let mut reader = Records::new(&self.method, &self.body[..key_len]);
                self.body.drain(..key_len);
                reader.open(&mut self.body)?;
                let mut header = Cursor(&self.body);
                if header.u8()? != 1 {
                    return Err(invalid("invalid Shadowsocks 2022 response type"));
                }
                check_time(header.u64()?, now()?)?;
                // Strict equality, not the locked peer's erroneous <= comparison.
                if header.take(key_len)? != self.request_salt.as_slice() {
                    return Err(invalid("Shadowsocks 2022 response salt mismatch"));
                }
                let length = header.u16()? as usize;
                self.request_salt.zeroize();
                self.reader = Some(reader);
                self.require_body(length + TAG_LENGTH, Phase::Payload);
            }
            Phase::Length => {
                self.reader.as_mut().unwrap().open(&mut self.body)?;
                let length = u16::from_be_bytes(self.body[..2].try_into().unwrap()) as usize;
                self.require_body(length + TAG_LENGTH, Phase::Payload);
            }
            Phase::Payload => {
                self.reader.as_mut().unwrap().open(&mut self.body)?;
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
        // A successfully encoded pending frame contains only wire ciphertext
        // and public headers. Keep its allocation for the next write; the
        // Zeroizing owner still wipes the full capacity when dropped.
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
            return Poll::Ready(Err(invalid("Shadowsocks 2022 stream failed")));
        }
        if out.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        ready!(this.drain(cx))?;
        for _ in 0..16 {
            if matches!(this.phase, Phase::Plain) {
                if this.plain_pos < this.body.len() {
                    let n = out.remaining().min(this.body.len() - this.plain_pos);
                    out.put_slice(&this.body[this.plain_pos..this.plain_pos + n]);
                    this.body[this.plain_pos..this.plain_pos + n].zeroize();
                    this.plain_pos += n;
                    return Poll::Ready(Ok(()));
                }
                this.require_body(2 + TAG_LENGTH, Phase::Length);
            }
            while this.body_pos < this.body.len() {
                let mut buf = ReadBuf::new(&mut this.body[this.body_pos..]);
                if let Err(e) = ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf)) {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
                let n = buf.filled().len();
                if n == 0 {
                    if matches!(this.phase, Phase::Length) && this.body_pos == 0 {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.failed = true;
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                this.body_pos += n;
            }
            if let Err(e) = this.process_body() {
                this.failed = true;
                return Poll::Ready(Err(e));
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
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = input.len().min(8192);
        // Reuse the owned pending frame. No plaintext temporary, growth during
        // encryption, larger records, or eager per-connection buffer allocation.
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
    use super::super::tests::{fixtures, unhex};
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn ss2022_reuses_pending_frame_after_partial_and_full_records() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let target = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Tcp);
            let mut stream = ClientStream::new(tokio::io::sink(), method, &target).unwrap();
            stream.flush().await.unwrap();
            stream.write_all(&[7; 8192]).await.unwrap();
            let pointer = stream.pending.as_ptr();
            let capacity = stream.pending.capacity();
            assert!(capacity <= 8192 + 2 + 2 * TAG_LENGTH);
            for size in [1, 1200, 8192, 0, 32, 8192] {
                stream.flush().await.unwrap();
                stream.write_all(&vec![8; size]).await.unwrap();
                assert_eq!(stream.pending.as_ptr(), pointer);
                assert_eq!(stream.pending.capacity(), capacity);
            }
        }
    }
    #[tokio::test]
    async fn ss2022_request_and_records_match_pinned_go_including_identity_chains() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let salt = unhex(case["salt"].as_str().unwrap());
            let target = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Tcp);
            let mut stream = ClientStream::with_entropy(
                tokio::io::sink(),
                method,
                &target,
                &salt,
                1700000000,
                0,
                &unhex(case["payload"].as_str().unwrap()),
            )
            .unwrap();
            assert_eq!(
                *stream.pending,
                unhex(case["request"].as_str().unwrap()),
                "{}",
                case["method"]
            );
            stream.write_all(b"after-header").await.unwrap();
            assert_eq!(*stream.pending, unhex(case["nextRecord"].as_str().unwrap()));
        }
    }
    fn response(method: &Method, request_salt: &[u8], payload: &[u8], timestamp: u64) -> Vec<u8> {
        let salt = vec![0x72; method.cipher.key_len()];
        let mut cipher = Records::new(method, &salt);
        let mut header = vec![1];
        header.extend_from_slice(&timestamp.to_be_bytes());
        header.extend_from_slice(request_salt);
        header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        cipher.seal(&mut header).unwrap();
        let mut body = payload.to_vec();
        cipher.seal(&mut body).unwrap();
        let mut wire = salt;
        wire.extend(header);
        wire.extend(body);
        wire
    }
    #[tokio::test]
    async fn ss2022_response_fragments_cancellation_binding_and_authentication() {
        for case in fixtures() {
            let method = Arc::new(
                Method::new(
                    case["method"].as_str().unwrap(),
                    case["password"].as_str().unwrap(),
                )
                .unwrap(),
            );
            let target = Target::new(
                TargetAddr::Ip("192.0.2.8".parse().unwrap()),
                443,
                Network::Tcp,
            );
            let salt = vec![0x55; method.cipher.key_len()];
            for scenario in 0..5 {
                let mut response_salt = salt.clone();
                if scenario == 1 {
                    response_salt[0] -= 1;
                }
                let time = now().unwrap();
                let mut wire = response(
                    &method,
                    &response_salt,
                    b"server payload",
                    if scenario == 2 { time - 31 } else { time },
                );
                if scenario == 3 {
                    let last = wire.len() - 1;
                    wire[last] ^= 1;
                }
                if scenario == 4 {
                    wire.pop();
                }
                let (client, mut peer) = tokio::io::duplex(4096);
                let mut stream = ClientStream::with_entropy(
                    client,
                    method.clone(),
                    &target,
                    &salt,
                    time,
                    1,
                    &[],
                )
                .unwrap();
                stream.flush().await.unwrap();
                peer.write_all(&wire[..1]).await.unwrap();
                let mut read = [0; 14];
                assert!(tokio::time::timeout(
                    std::time::Duration::from_millis(1),
                    stream.read_exact(&mut read)
                )
                .await
                .is_err());
                peer.write_all(&wire[1..]).await.unwrap();
                peer.shutdown().await.unwrap();
                if scenario == 0 {
                    stream.read_exact(&mut read).await.unwrap();
                    assert_eq!(&read, b"server payload");
                    assert_eq!(stream.read(&mut read).await.unwrap(), 0);
                } else {
                    assert!(stream.read_exact(&mut read).await.is_err());
                    assert!(stream.read(&mut read).await.is_err());
                }
            }
        }
    }
    #[tokio::test]
    async fn ss2022_partial_flush_resumes_without_record_reencryption() {
        let method =
            Arc::new(Method::new("2022-blake3-aes-128-gcm", &STANDARD.encode([1; 16])).unwrap());
        let target = Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Tcp);
        let (client, mut peer) = tokio::io::duplex(1);
        let mut stream =
            ClientStream::with_entropy(client, method, &target, &[4; 16], now().unwrap(), 1, &[])
                .unwrap();
        let expected = stream.pending.to_vec();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), stream.flush())
                .await
                .is_err()
        );
        let (write, bytes) = tokio::join!(stream.flush(), async {
            let mut bytes = vec![0; expected.len()];
            peer.read_exact(&mut bytes).await.unwrap();
            bytes
        });
        write.unwrap();
        assert_eq!(bytes, expected);
    }
}
