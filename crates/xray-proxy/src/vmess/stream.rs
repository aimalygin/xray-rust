use super::{records::Records, *};
use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_READ_RECORDS: usize = 4;
const BULK_READ_THRESHOLD: usize = 64 * 1024;
const BULK_READ_AHEAD: usize = 16 * 1024;

/// Bounded client records with owned pending writes and resumable reads.
/// For a UDP target, each nonempty write and read is exactly one datagram;
/// reads require room for the complete datagram and never truncate it.
pub struct ClientStream<S> {
    inner: S,
    read: ReadState,
    write: WriteState,
}
#[derive(Clone, Copy)]
enum Phase {
    HeaderLength,
    Header,
    Length,
    Payload,
    Plain,
}
pub(super) struct ReadState {
    keys: Option<SessionKeys>,
    reader: Records,
    options: Options,
    packet: bool,
    body: crate::record_buffer::RecordBuffer,
    plain_len: usize,
    plain_pos: usize,
    bulk_read_remaining: usize,
    phase: Phase,
    padding: usize,
    failed: bool,
    read_error: Option<io::Error>,
    eof: bool,
}
pub(super) struct WriteState {
    writer: Records,
    options: Options,
    packet: bool,
    pending: Zeroizing<Vec<u8>>,
    pending_pos: usize,
    failed: bool,
    closing: bool,
}
impl<S> ClientStream<S> {
    pub fn new(inner: S, account: &Account, target: &Target) -> io::Result<Self> {
        Self::build(inner, account, Some(target))
    }
    /// Command 3 omits the destination; Mux frames carry each child's target.
    pub fn new_mux(inner: S, account: &Account) -> io::Result<Self> {
        Self::build(inner, account, None)
    }
    fn build(inner: S, account: &Account, target: Option<&Target>) -> io::Result<Self> {
        let mut entropy = Zeroizing::new([0; 33]);
        random(entropy.as_mut())?;
        let mut auth = [0; 4];
        random(&mut auth)?;
        let mut nonce = [0; 8];
        random(&mut nonce)?;
        let mut padding = [0; 15];
        random(&mut padding)?;
        let padding_len = (rand::random::<u8>() % 16) as usize;
        let keys = SessionKeys::from_entropy(&entropy);
        let pending = keys.request(
            account,
            target,
            now()?,
            &auth,
            &nonce,
            &padding[..padding_len],
        )?;
        let auth_length = account
            .options
            .authenticated_length
            .then_some((&*keys.request_key, &*keys.request_iv));
        let writer = Records::new(
            account.cipher,
            &keys.request_key,
            &keys.request_iv,
            auth_length,
        );
        // This pin uses request key/IV for authenticated response lengths too.
        let reader = Records::new(
            account.cipher,
            &keys.response_key,
            &keys.response_iv,
            auth_length,
        );
        let packet = target.is_some_and(|t| t.network == Network::Udp);
        Ok(Self {
            inner,
            read: ReadState {
                keys: Some(keys),
                reader,
                options: account.options,
                packet,
                body: crate::record_buffer::RecordBuffer::new(
                    18,
                    if account.options.authenticated_length {
                        18
                    } else {
                        2
                    },
                ),
                plain_len: 0,
                plain_pos: 0,
                bulk_read_remaining: BULK_READ_THRESHOLD,
                phase: Phase::HeaderLength,
                padding: 0,
                failed: false,
                read_error: None,
                eof: false,
            },
            write: WriteState {
                writer,
                options: account.options,
                packet,
                pending,
                pending_pos: 0,
                failed: false,
                closing: false,
            },
        })
    }
    fn failed(&self) -> bool {
        self.read.failed || self.write.failed
    }
    /// Move the existing codec states and buffers into independently owned halves.
    /// The owner must cancel the peer on error; write shutdown remains a half-close.
    pub fn into_split(
        self,
    ) -> (
        super::ClientReadHalf<tokio::io::ReadHalf<S>>,
        super::ClientWriteHalf<tokio::io::WriteHalf<S>>,
    )
    where
        S: AsyncRead + AsyncWrite,
    {
        self.into_split_with(tokio::io::split)
    }

    /// Use a carrier-specific owned split (for example, native TCP halves).
    pub fn into_split_with<R: AsyncRead, W: AsyncWrite>(
        mut self,
        split: impl FnOnce(S) -> (R, W),
    ) -> (super::ClientReadHalf<R>, super::ClientWriteHalf<W>) {
        if self.failed() {
            self.read.failed = true;
            self.write.failed = true;
        }
        let (read, write) = split(self.inner);
        (
            super::ClientReadHalf {
                inner: read,
                state: self.read,
            },
            super::ClientWriteHalf {
                inner: write,
                state: self.write,
            },
        )
    }
}
impl ReadState {
    fn expect(&mut self, n: usize, phase: Phase) {
        // Plaintext is erased as it is delivered, including partial reads.
        // Other phases can still contain a decrypted header/length.
        if !matches!(self.phase, Phase::Plain) {
            self.body.frame().zeroize();
        }
        self.body.advance(n);
        self.plain_len = 0;
        self.plain_pos = 0;
        self.phase = phase;
    }
    fn process(&mut self) -> io::Result<()> {
        match self.phase {
            Phase::HeaderLength => {
                let keys = self.keys.as_ref().unwrap();
                let (cipher, nonce) = crypto::header_aead(
                    &*keys.response_key,
                    &*keys.response_iv,
                    &[b"AEAD Resp Header Len Key"],
                    &[b"AEAD Resp Header Len IV"],
                );
                cipher.open(&nonce, &[], self.body.frame())?;
                let size = u16::from_be_bytes(self.body.frame()[..2].try_into().unwrap()) as usize;
                if !(4..=259).contains(&size) {
                    return Err(invalid("invalid VMess response header length"));
                }
                self.expect(size + 16, Phase::Header);
            }
            Phase::Header => {
                let keys = self.keys.take().unwrap();
                let (cipher, nonce) = crypto::header_aead(
                    &*keys.response_key,
                    &*keys.response_iv,
                    &[b"AEAD Resp Header Key"],
                    &[b"AEAD Resp Header IV"],
                );
                let body = self.body.frame();
                let length = cipher.open(&nonce, &[], body)?;
                if length != 4
                    || body[0] != keys.response_marker
                    // Xray replies with zero; sing-vmess echoes the negotiated
                    // request options. Neither changes the response codec.
                    || ![0, self.options.wire()].contains(&body[1])
                    || body[2..length] != [0, 0]
                {
                    return Err(invalid("VMess response binding or options rejected"));
                }
                self.expect(self.reader.size_bytes(), Phase::Length);
            }
            Phase::Length => {
                let (size, padding) = self.reader.decode_length(self.body.frame())?;
                self.padding = padding;
                self.expect(size, Phase::Payload);
            }
            Phase::Payload => {
                // Authenticate even an empty termination record; unauthenticated
                // length/padding alone must not cause successful EOF.
                self.plain_len = self.reader.open_slice(self.body.frame(), self.padding)?;
                if self.plain_len == 0 {
                    self.eof = true;
                } else {
                    if !self.packet && self.bulk_read_remaining != 0 {
                        self.bulk_read_remaining =
                            self.bulk_read_remaining.saturating_sub(self.plain_len);
                        if self.bulk_read_remaining == 0 {
                            self.body.set_read_ahead(BULK_READ_AHEAD);
                        }
                    }
                    self.phase = Phase::Plain;
                    self.plain_pos = 0;
                }
            }
            Phase::Plain => unreachable!(),
        }
        Ok(())
    }
}
impl ReadState {
    fn poll_read_one<S: AsyncRead + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        byte_budget: usize,
    ) -> Poll<io::Result<()>> {
        let this = self;
        if this.failed {
            return Poll::Ready(Err(invalid("VMess stream failed")));
        }
        if out.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        loop {
            if matches!(this.phase, Phase::Plain) {
                let remaining = this.plain_len - this.plain_pos;
                if remaining != 0 {
                    if this.packet && out.remaining() < remaining {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "VMess datagram receive buffer too small",
                        )));
                    }
                    let n = out.remaining().min(remaining).min(byte_budget);
                    out.put_slice(&this.body.frame()[this.plain_pos..this.plain_pos + n]);
                    crate::erase::erase(&mut this.body.frame()[this.plain_pos..this.plain_pos + n]);
                    this.plain_pos += n;
                    return Poll::Ready(Ok(()));
                }
                this.expect(this.reader.size_bytes(), Phase::Length);
            }
            match ready!(this.body.poll_frame(&mut *inner, cx)) {
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
            if let Err(e) = this.process() {
                this.failed = true;
                return Poll::Ready(Err(e));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
        }
    }
    pub(super) fn poll_read<S: AsyncRead + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        mut prepare: impl FnMut(&mut S, &mut Context<'_>) -> io::Result<()>,
    ) -> Poll<io::Result<()>> {
        if let Some(error) = self.read_error.take() {
            return Poll::Ready(Err(error));
        }
        let started = out.filled().len();
        // Bound bytes as well as record count: peers may send records larger
        // than our 8 KiB writer. Four ordinary payloads stay below 32 KiB,
        // so the adaptive relay does not grow past that allocation for TCP.
        let byte_budget = if self.packet {
            usize::MAX
        } else {
            MAX_READ_RECORDS * self.reader.max_payload()
        };
        // Bound work per poll so a continuously readable socket cannot starve
        // the reverse direction. UDP must keep exactly one datagram per read.
        for _ in 0..MAX_READ_RECORDS {
            let before = out.filled().len();
            let result = if self.failed || out.remaining() == 0 || self.eof {
                self.poll_read_one(inner, cx, out, byte_budget - (before - started))
            } else if let Err(error) = prepare(inner, cx) {
                self.failed = true;
                Poll::Ready(Err(error))
            } else {
                self.poll_read_one(inner, cx, out, byte_budget - (before - started))
            };
            match result {
                Poll::Pending if out.filled().len() == started => return Poll::Pending,
                Poll::Pending => return Poll::Ready(Ok(())),
                Poll::Ready(Err(error)) if out.filled().len() != started => {
                    // Already authenticated bytes belong to this successful
                    // read. Preserve the next record's failure for the next
                    // call instead of reporting an error with a filled buffer.
                    self.read_error = Some(error);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    if self.packet
                        || out.remaining() == 0
                        || out.filled().len() == before
                        || out.filled().len() - started == byte_budget
                    {
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl WriteState {
    pub(super) fn drain<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.pending_pos < self.pending.len() {
            match ready!(Pin::new(&mut *inner).poll_write(cx, &self.pending[self.pending_pos..])) {
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
    pub(super) fn poll_write<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
        data: &[u8],
        eager: bool,
    ) -> Poll<io::Result<usize>> {
        let this = self;
        if this.failed || this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.packet && data.len() > this.writer.max_payload() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess datagram exceeds record limit",
            )));
        }
        ready!(this.drain(inner, cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let result = if this.packet {
            this.writer
                .seal_into(data, &mut this.pending)
                .map(|()| data.len())
        } else {
            this.writer.seal_pair_into(data, &mut this.pending)
        };
        match result {
            Ok(n) => {
                // A reader cannot flush an independent writer. Finish a
                // complete write promptly, including small RPCs. If this
                // write accepted only part of the input, the next poll drains
                // the record before encrypting more, as in the combined path.
                if eager && n == data.len() {
                    if let Poll::Ready(Err(error)) = this.drain(inner, cx) {
                        return Poll::Ready(Err(error));
                    }
                }
                Poll::Ready(Ok(n))
            }
            Err(e) => {
                this.pending.as_mut_slice().zeroize();
                this.pending.clear();
                this.failed = true;
                Poll::Ready(Err(e))
            }
        }
    }
    pub(super) fn poll_flush<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self;
        if this.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        ready!(this.drain(inner, cx))?;
        let result = ready!(Pin::new(&mut *inner).poll_flush(cx));
        if result.is_err() {
            this.failed = true;
        }
        Poll::Ready(result)
    }
    pub(super) fn poll_shutdown<S: AsyncWrite + Unpin>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        ready!(self.poll_flush(inner, cx))?;
        let this = self;
        if !this.closing {
            this.closing = true;
            if !this.options.no_termination_signal {
                if let Err(e) = this.writer.seal_into(&[], &mut this.pending) {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
        ready!(this.drain(inner, cx))?;
        ready!(Pin::new(&mut *inner).poll_flush(cx))?;
        Pin::new(&mut *inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClientStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.write.failed {
            this.read.failed = true;
        }
        this.read.poll_read(&mut this.inner, cx, out, |inner, cx| {
            // Preserve the combined stream's opportunistic write progress.
            match this.write.drain(inner, cx) {
                Poll::Ready(result) => result,
                Poll::Pending => Ok(()),
            }
        })
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.read.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        this.write.poll_write(&mut this.inner, cx, data, false)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        this.write.poll_flush(&mut this.inner, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        this.write.poll_shutdown(&mut this.inner, cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, task::Waker};

    #[derive(Default)]
    struct Wire {
        incoming: VecDeque<u8>,
        outgoing: Vec<u8>,
        write_quota: usize,
        closed: bool,
    }
    impl AsyncRead for Wire {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.incoming.is_empty() && !self.closed {
                return Poll::Pending;
            }
            while out.remaining() > 0 {
                let Some(byte) = self.incoming.pop_front() else {
                    break;
                };
                out.put_slice(&[byte]);
            }
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Wire {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.write_quota == 0 {
                return Poll::Pending;
            }
            let n = data.len().min(self.write_quota);
            self.outgoing.extend_from_slice(&data[..n]);
            self.write_quota -= n;
            Poll::Ready(Ok(n))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    fn client(cipher: Cipher, auth: bool, network: Network) -> ClientStream<Wire> {
        ClientStream::new(
            Wire {
                write_quota: usize::MAX,
                ..Wire::default()
            },
            &Account::new(
                &[7; 16],
                cipher,
                Options {
                    authenticated_length: auth,
                    no_termination_signal: false,
                },
            ),
            &Target::new(TargetAddr::Domain("example.test".into()), 443, network),
        )
        .unwrap()
    }
    fn response_header<S>(client: &ClientStream<S>, size: u16, marker: u8) -> Vec<u8> {
        response_header_options(client, size, marker, 0)
    }
    fn response_header_options<S>(
        client: &ClientStream<S>,
        size: u16,
        marker: u8,
        options: u8,
    ) -> Vec<u8> {
        let keys = client.read.keys.as_ref().unwrap();
        let (aead, nonce) = crypto::header_aead(
            &*keys.response_key,
            &*keys.response_iv,
            &[b"AEAD Resp Header Len Key"],
            &[b"AEAD Resp Header Len IV"],
        );
        let mut wire = size.to_be_bytes().to_vec();
        aead.seal(&nonce, &[], &mut wire).unwrap();
        let (aead, nonce) = crypto::header_aead(
            &*keys.response_key,
            &*keys.response_iv,
            &[b"AEAD Resp Header Key"],
            &[b"AEAD Resp Header IV"],
        );
        let mut header = vec![marker, options, 0, 0];
        aead.seal(&nonce, &[], &mut header).unwrap();
        wire.extend(header);
        wire
    }
    fn response_records<S>(client: &ClientStream<S>, cipher: Cipher) -> Records {
        let keys = client.read.keys.as_ref().unwrap();
        Records::new(
            cipher,
            &keys.response_key,
            &keys.response_iv,
            client
                .read
                .options
                .authenticated_length
                .then_some((&*keys.request_key, &*keys.request_iv)),
        )
    }
    fn poll_read(client: &mut ClientStream<Wire>, output: &mut [u8]) -> Poll<io::Result<usize>> {
        let mut buffer = ReadBuf::new(output);
        Pin::new(client)
            .poll_read(&mut Context::from_waker(Waker::noop()), &mut buffer)
            .map(|r| r.map(|()| buffer.filled().len()))
    }

    #[test]
    fn vmess_large_peer_records_obey_tcp_byte_budget_and_keep_udp_whole() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                for network in [Network::Tcp, Network::Udp] {
                    let mut client = client(cipher, auth, network);
                    let mut records = response_records(&client, cipher);
                    let mut wire = response_header(
                        &client,
                        4,
                        client.read.keys.as_ref().unwrap().response_marker,
                    );
                    let payload = vec![0x73; 48 * 1024];
                    wire.extend_from_slice(&records.seal_peer_record(&payload));
                    wire.extend_from_slice(&records.seal(&[]).unwrap());
                    client.inner.incoming.extend(wire);
                    let mut out = vec![0xaa; 64 * 1024];
                    let first = if network == Network::Tcp {
                        MAX_READ_RECORDS * client.read.reader.max_payload()
                    } else {
                        payload.len()
                    };
                    assert!(
                        matches!(poll_read(&mut client, &mut out), Poll::Ready(Ok(n)) if n == first)
                    );
                    assert_eq!(&out[..first], &payload[..first]);
                    assert!(out[first..].iter().all(|&b| b == 0xaa));
                    assert!(client.read.body.frame()[..first].iter().all(|&b| b == 0));
                    if first < payload.len() {
                        assert!(
                            matches!(poll_read(&mut client, &mut out), Poll::Ready(Ok(n)) if n == payload.len() - first)
                        );
                        assert_eq!(&out[..payload.len() - first], &payload[first..]);
                    }
                    assert!(matches!(
                        poll_read(&mut client, &mut out),
                        Poll::Ready(Ok(0))
                    ));
                }
            }
        }
    }

    #[test]
    fn vmess_read_ahead_activates_only_after_authenticated_tcp_bulk() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                for network in [Network::Tcp, Network::Udp] {
                    let mut client = client(cipher, auth, network);
                    let mut records = response_records(&client, cipher);
                    let mut wire = response_header(
                        &client,
                        4,
                        client.read.keys.as_ref().unwrap().response_marker,
                    );
                    wire.extend_from_slice(&records.seal(&[7; 4096]).unwrap());
                    client.inner.incoming.extend(wire);
                    let mut out = [0; 4096];
                    assert!(matches!(
                        poll_read(&mut client, &mut out),
                        Poll::Ready(Ok(4096))
                    ));
                    assert_eq!(out, [7; 4096]);
                    assert!(client.read.bulk_read_remaining > 0);
                    for _ in 1..17 {
                        client
                            .inner
                            .incoming
                            .extend(records.seal(&[8; 4096]).unwrap().iter());
                        assert!(matches!(
                            poll_read(&mut client, &mut out),
                            Poll::Ready(Ok(4096))
                        ));
                        assert_eq!(out, [8; 4096]);
                    }
                    assert_eq!(
                        client.read.bulk_read_remaining,
                        if network == Network::Udp {
                            BULK_READ_THRESHOLD
                        } else {
                            0
                        }
                    );
                    assert!(poll_read(&mut client, &mut out).is_pending());
                }
            }
        }
    }

    #[test]
    fn vmess_tcp_batches_available_records_with_a_fairness_bound() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let mut records = response_records(&client, cipher);
                let mut wire = response_header(
                    &client,
                    4,
                    client.read.keys.as_ref().unwrap().response_marker,
                );
                for index in 0..=MAX_READ_RECORDS {
                    wire.extend_from_slice(&records.seal(&[index as u8; 64]).unwrap());
                }
                client.inner.incoming.extend(wire);
                let mut out = [0xaa; (MAX_READ_RECORDS + 1) * 64];
                assert!(matches!(
                    poll_read(&mut client, &mut out),
                    Poll::Ready(Ok(n)) if n == MAX_READ_RECORDS * 64
                ));
                for index in 0..MAX_READ_RECORDS {
                    assert_eq!(&out[index * 64..(index + 1) * 64], &[index as u8; 64]);
                }
                assert!(out[MAX_READ_RECORDS * 64..]
                    .iter()
                    .all(|&byte| byte == 0xaa));
                assert!(client.read.body.frame()[..64].iter().all(|&byte| byte == 0));
                assert!(matches!(
                    poll_read(&mut client, &mut out),
                    Poll::Ready(Ok(64))
                ));
                assert_eq!(&out[..64], &[MAX_READ_RECORDS as u8; 64]);
                assert!(poll_read(&mut client, &mut out).is_pending());
            }
        }
    }

    #[test]
    fn vmess_batch_returns_progress_before_a_partial_record_and_preserves_eof_error() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let mut records = response_records(&client, cipher);
                let mut wire = response_header(
                    &client,
                    4,
                    client.read.keys.as_ref().unwrap().response_marker,
                );
                wire.extend_from_slice(&records.seal(b"first").unwrap());
                let second = records.seal(b"second").unwrap();
                wire.extend_from_slice(&second[..1]);
                client.inner.incoming.extend(wire);
                let mut out = [0xaa; 32];
                assert!(matches!(
                    poll_read(&mut client, &mut out),
                    Poll::Ready(Ok(5))
                ));
                assert_eq!(&out[..5], b"first");
                assert!(poll_read(&mut client, &mut out).is_pending());
                client.inner.incoming.extend(&second[1..]);
                client.inner.incoming.push_back(0); // Truncated following length.
                client.inner.closed = true;
                assert!(matches!(
                    poll_read(&mut client, &mut out),
                    Poll::Ready(Ok(6))
                ));
                assert_eq!(&out[..6], b"second");
                out.fill(0xaa);
                assert!(
                    matches!(poll_read(&mut client, &mut out), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
                );
                assert_eq!(out, [0xaa; 32]);
                assert!(client.failed());
            }
        }
    }

    #[test]
    fn vmess_read_ahead_authenticates_each_record_before_exposing_plaintext() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let mut records = response_records(&client, cipher);
                let mut wire = response_header(
                    &client,
                    4,
                    client.read.keys.as_ref().unwrap().response_marker,
                );
                wire.extend_from_slice(&records.seal(b"first").unwrap());
                let mut bad = records.seal(b"second").unwrap();
                bad[records.size_bytes()] ^= 1;
                wire.extend_from_slice(&bad);
                client.inner.incoming.extend(wire);
                let mut out = [0xaa; 32];
                assert!(matches!(
                    poll_read(&mut client, &mut out[..2]),
                    Poll::Ready(Ok(2))
                ));
                assert_eq!(&out[..2], b"fi");
                assert!(client.read.body.frame()[..2].iter().all(|&b| b == 0));
                assert!(matches!(
                    poll_read(&mut client, &mut out),
                    Poll::Ready(Ok(3))
                ));
                assert_eq!(&out[..3], b"rst");
                out.fill(0xaa);
                assert!(matches!(
                    poll_read(&mut client, &mut out),
                    Poll::Ready(Err(_))
                ));
                assert_eq!(out, [0xaa; 32]);
                assert!(client.failed());
            }
        }
    }

    #[test]
    fn vmess_response_progresses_while_outgoing_record_is_blocked() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let mut records = response_records(&client, cipher);
                let mut wire = response_header(
                    &client,
                    4,
                    client.read.keys.as_ref().unwrap().response_marker,
                );
                wire.extend_from_slice(&records.seal(b"response").unwrap());
                let mut cx = Context::from_waker(Waker::noop());
                assert!(matches!(
                    Pin::new(&mut client).poll_write(&mut cx, b"request"),
                    Poll::Ready(Ok(7))
                ));
                let request = client.write.pending.clone();
                let sent = client.inner.outgoing.len();
                client.inner.write_quota = 1;
                client.inner.incoming.extend(wire);
                let mut output = [0; 32];
                assert!(matches!(
                    poll_read(&mut client, &mut output),
                    Poll::Ready(Ok(8))
                ));
                assert_eq!(&output[..8], b"response");
                assert_eq!(client.write.pending_pos, 1);
                client.inner.write_quota = usize::MAX;
                assert!(matches!(
                    Pin::new(&mut client).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(&client.inner.outgoing[sent..], request.as_slice());
            }
        }
    }

    #[test]
    fn vmess_response_reads_resume_at_every_header_and_record_boundary() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                // A fresh session at each split also exercises randomized IVs,
                // SHAKE padding and response-marker binding.
                for split in 0..180 {
                    let mut client = client(cipher, auth, Network::Tcp);
                    let mut records = response_records(&client, cipher);
                    let mut wire = response_header(
                        &client,
                        4,
                        client.read.keys.as_ref().unwrap().response_marker,
                    );
                    wire.extend_from_slice(&records.seal(b"response").unwrap());
                    if split >= wire.len() {
                        continue;
                    }
                    client.inner.incoming.extend(&wire[..split]);
                    let mut output = [0; 32];
                    assert!(poll_read(&mut client, &mut output).is_pending());
                    client.inner.incoming.extend(&wire[split..]);
                    assert!(matches!(
                        poll_read(&mut client, &mut output),
                        Poll::Ready(Ok(8))
                    ));
                    assert_eq!(&output[..8], b"response");
                    client
                        .inner
                        .incoming
                        .extend(records.seal(&[]).unwrap().iter());
                    assert!(matches!(
                        poll_read(&mut client, &mut output),
                        Poll::Ready(Ok(0))
                    ));
                }
            }
        }
    }

    #[test]
    fn vmess_forged_headers_records_and_termination_poison_both_directions() {
        for case in 0..7 {
            let mut client = client(Cipher::Aes128Gcm, true, Network::Tcp);
            let marker = client.read.keys.as_ref().unwrap().response_marker;
            let mut wire = response_header(
                &client,
                if case == 0 { 260 } else { 4 },
                if case == 1 { marker ^ 1 } else { marker },
            );
            let mut records = response_records(&client, Cipher::Aes128Gcm);
            let mut record = records
                .seal(if case == 5 { &[] } else { b"secret payload" })
                .unwrap();
            match case {
                2 => wire[0] ^= 1,        // authenticated header length
                3 => wire[18] ^= 1,       // authenticated header body
                4 => record[0] ^= 1,      // authenticated record length
                5 | 6 => record[18] ^= 1, // encrypted EOF or data
                _ => {}
            }
            wire.extend_from_slice(&record);
            client.inner.incoming.extend(wire);
            let mut output = [0; 32];
            assert!(matches!(
                poll_read(&mut client, &mut output),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                poll_read(&mut client, &mut output),
                Poll::Ready(Err(_))
            ));
            assert!(matches!(
                Pin::new(&mut client).poll_write(&mut Context::from_waker(Waker::noop()), b"retry"),
                Poll::Ready(Err(_))
            ));
        }
    }

    #[test]
    fn vmess_udp_reads_preserve_whole_datagrams_and_reject_oversize_writes() {
        let mut client = client(Cipher::ChaCha20Poly1305, false, Network::Udp);
        let mut records = response_records(&client, Cipher::ChaCha20Poly1305);
        let mut wire = response_header(
            &client,
            4,
            client.read.keys.as_ref().unwrap().response_marker,
        );
        wire.extend_from_slice(&records.seal(b"one datagram").unwrap());
        wire.extend_from_slice(&records.seal(b"two").unwrap());
        client.inner.incoming.extend(wire);
        assert!(
            matches!(poll_read(&mut client, &mut [0; 2]), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidInput)
        );
        let mut output = [0; 32];
        assert!(matches!(
            poll_read(&mut client, &mut output),
            Poll::Ready(Ok(12))
        ));
        assert_eq!(&output[..12], b"one datagram");
        assert!(matches!(
            poll_read(&mut client, &mut output),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(&output[..3], b"two");
        let oversize = vec![0; client.write.writer.max_payload() + 1];
        assert!(
            matches!(Pin::new(&mut client).poll_write(&mut Context::from_waker(Waker::noop()), &oversize), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidInput)
        );
        assert!(!client.failed());
    }

    #[test]
    fn vmess_write_pairs_keep_record_boundaries_and_resume_under_backpressure() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let keys = client.read.keys.as_ref().unwrap();
                let mut reader = Records::new(
                    cipher,
                    &keys.request_key,
                    &keys.request_iv,
                    auth.then_some((&*keys.request_key, &*keys.request_iv)),
                );
                let max = client.write.writer.max_payload();
                let data = [vec![0x31; max], vec![0x72; max], vec![0x93; 17]].concat();
                let mut cx = Context::from_waker(Waker::noop());
                let header_len = client.write.pending.len();
                assert!(matches!(
                    Pin::new(&mut client).poll_write(&mut cx, &data),
                    Poll::Ready(Ok(n)) if n == 2 * max
                ));
                assert!(client.write.pending.len() <= 16384);
                assert!(client.write.pending.capacity() <= 16384);
                let pair = client.write.pending.clone();
                let allocation = client.write.pending.as_ptr();
                client.inner.write_quota = 1;
                assert!(Pin::new(&mut client).poll_flush(&mut cx).is_pending());
                assert!(Pin::new(&mut client)
                    .poll_write(&mut cx, &data[2 * max..])
                    .is_pending());
                client.inner.write_quota = usize::MAX;
                assert!(matches!(
                    Pin::new(&mut client).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(&client.inner.outgoing[header_len..], pair.as_slice());
                assert!(matches!(
                    Pin::new(&mut client).poll_write(&mut cx, &data[2 * max..]),
                    Poll::Ready(Ok(17))
                ));
                assert_eq!(allocation, client.write.pending.as_ptr());
                assert!(matches!(
                    Pin::new(&mut client).poll_shutdown(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                let mut wire = &client.inner.outgoing[header_len..];
                // Decode independently: two distinct authenticated records,
                // the short tail, and exactly one authenticated termination.
                for expected in [&data[..max], &data[max..2 * max], &data[2 * max..], &[]] {
                    let prefix = reader.size_bytes();
                    let mut length = wire[..prefix].to_vec();
                    let (size, padding) = reader.decode_length(&mut length).unwrap();
                    let mut body = wire[prefix..prefix + size].to_vec();
                    reader.open(&mut body, padding).unwrap();
                    assert_eq!(body, expected);
                    wire = &wire[prefix + size..];
                }
                assert!(wire.is_empty());
            }
        }
    }

    #[test]
    fn vmess_split_bulk_tail_flushes_and_partial_ciphertext_resumes_exactly() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let client = client(cipher, auth, Network::Tcp);
                let keys = client.read.keys.as_ref().unwrap();
                let mut reader = Records::new(
                    cipher,
                    &keys.request_key,
                    &keys.request_iv,
                    auth.then_some((&*keys.request_key, &*keys.request_iv)),
                );
                let max = client.write.writer.max_payload();
                let data = [vec![0x31; max], vec![0x72; max], vec![0x93; 17]].concat();
                let mut cx = Context::from_waker(Waker::noop());
                let header_len = client.write.pending.len();
                let (_, mut writer) = client.into_split_with(|wire| (tokio::io::empty(), wire));
                assert!(matches!(
                    Pin::new(&mut writer).poll_write(&mut cx, &data),
                    Poll::Ready(Ok(n)) if n == 2 * max
                ));
                assert!(writer.state.pending.len() <= 16384);
                assert!(writer.state.pending.capacity() <= 16384);
                let pair = writer.state.pending.clone();
                let allocation = writer.state.pending.as_ptr();
                writer.inner.write_quota = 1;
                assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
                assert!(Pin::new(&mut writer)
                    .poll_write(&mut cx, &data[2 * max..])
                    .is_pending());
                writer.inner.write_quota = usize::MAX;
                assert!(matches!(
                    Pin::new(&mut writer).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(&writer.inner.outgoing[header_len..], pair.as_slice());
                assert!(matches!(
                    Pin::new(&mut writer).poll_write(&mut cx, &data[2 * max..]),
                    Poll::Ready(Ok(17))
                ));
                assert_eq!(allocation, writer.state.pending.as_ptr());
                assert!(matches!(
                    Pin::new(&mut writer).poll_shutdown(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                let mut wire = &writer.inner.outgoing[header_len..];
                // Decode independently: two distinct authenticated records,
                // the short tail, and exactly one authenticated termination.
                for expected in [&data[..max], &data[max..2 * max], &data[2 * max..], &[]] {
                    let prefix = reader.size_bytes();
                    let mut length = wire[..prefix].to_vec();
                    let (size, padding) = reader.decode_length(&mut length).unwrap();
                    let mut body = wire[prefix..prefix + size].to_vec();
                    reader.open(&mut body, padding).unwrap();
                    assert_eq!(body, expected);
                    wire = &wire[prefix + size..];
                }
                assert!(wire.is_empty());
            }
        }
    }

    #[test]
    fn vmess_short_writes_and_datagrams_do_not_grow_a_pair_buffer() {
        for network in [Network::Tcp, Network::Udp] {
            let mut client = client(Cipher::Aes128Gcm, false, network);
            let max = client.write.writer.max_payload();
            let mut cx = Context::from_waker(Waker::noop());
            for n in [1, max] {
                assert!(matches!(
                    Pin::new(&mut client).poll_write(&mut cx, &vec![42; n]),
                    Poll::Ready(Ok(written)) if written == n
                ));
                assert!(client.write.pending.capacity() <= 8192);
                assert!(matches!(
                    Pin::new(&mut client).poll_flush(&mut cx),
                    Poll::Ready(Ok(()))
                ));
            }
        }
    }

    #[test]
    fn vmess_second_record_nonce_exhaustion_discards_the_pair_and_fails_closed() {
        let mut client = client(Cipher::Aes128Gcm, true, Network::Tcp);
        let mut scratch = Vec::new();
        for _ in 0..u16::MAX {
            client.write.writer.seal_into(&[], &mut scratch).unwrap();
            scratch.clear();
        }
        let mut cx = Context::from_waker(Waker::noop());
        let header = client.write.pending.clone();
        let payload = vec![42; 2 * client.write.writer.max_payload()];
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut cx, &payload),
            Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidData
        ));
        assert!(client.failed());
        assert!(client.write.pending.is_empty());
        assert_eq!(client.inner.outgoing, *header);
        assert!(matches!(
            Pin::new(&mut client).poll_flush(&mut cx),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut cx, b"retry"),
            Poll::Ready(Err(_))
        ));
    }

    #[test]
    fn vmess_partial_write_flush_and_shutdown_resume_without_duplicate_bytes() {
        let mut client = client(Cipher::Aes128Gcm, false, Network::Tcp);
        let request = client.write.pending.clone();
        client.inner.write_quota = 1;
        let mut cx = Context::from_waker(Waker::noop());
        assert!(Pin::new(&mut client)
            .poll_write(&mut cx, b"payload")
            .is_pending());
        client.inner.write_quota = usize::MAX;
        assert!(matches!(
            Pin::new(&mut client).poll_write(&mut cx, b"payload"),
            Poll::Ready(Ok(7))
        ));
        assert_eq!(client.inner.outgoing, *request);
        let record = client.write.pending.clone();
        client.inner.write_quota = 1;
        assert!(Pin::new(&mut client).poll_flush(&mut cx).is_pending());
        client.inner.write_quota = usize::MAX;
        assert!(matches!(
            Pin::new(&mut client).poll_flush(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            client.inner.outgoing,
            [request.as_slice(), record.as_slice()].concat()
        );
        client.inner.write_quota = 1;
        assert!(Pin::new(&mut client).poll_shutdown(&mut cx).is_pending());
        let termination = client.write.pending.clone();
        client.inner.write_quota = usize::MAX;
        assert!(matches!(
            Pin::new(&mut client).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert!(matches!(
            Pin::new(&mut client).poll_shutdown(&mut cx),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(
            client.inner.outgoing,
            [
                request.as_slice(),
                record.as_slice(),
                termination.as_slice()
            ]
            .concat()
        );
    }

    #[test]
    fn vmess_truncated_response_is_never_successful_eof() {
        for cut in [0, 1, 17, 18, 19, 37] {
            let mut client = client(Cipher::Aes128Gcm, false, Network::Tcp);
            let wire = response_header(
                &client,
                4,
                client.read.keys.as_ref().unwrap().response_marker,
            );
            client.inner.incoming.extend(&wire[..cut]);
            client.inner.closed = true;
            assert!(
                matches!(poll_read(&mut client, &mut [0; 1]), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof)
            );
        }
    }

    #[test]
    fn vmess_response_accepts_echoed_options_but_rejects_unknown_negotiation() {
        for auth in [false, true] {
            for no_termination in [false, true] {
                for valid in [false, true] {
                    let mut client = client(Cipher::Aes128Gcm, auth, Network::Tcp);
                    client.read.options.no_termination_signal = no_termination;
                    let options = if valid {
                        client.read.options.wire()
                    } else {
                        0x80
                    };
                    let mut wire = response_header_options(
                        &client,
                        4,
                        client.read.keys.as_ref().unwrap().response_marker,
                        options,
                    );
                    wire.extend_from_slice(
                        &response_records(&client, Cipher::Aes128Gcm)
                            .seal(b"echoed options")
                            .unwrap(),
                    );
                    client.inner.incoming.extend(wire);
                    let result = poll_read(&mut client, &mut [0; 32]);
                    if valid {
                        assert!(matches!(result, Poll::Ready(Ok(14))));
                    } else {
                        assert!(matches!(result, Poll::Ready(Err(_))));
                        assert!(client.failed());
                    }
                }
            }
        }
    }

    struct SharedWire(std::sync::Arc<std::sync::Mutex<Wire>>);
    impl AsyncRead for SharedWire {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut *self.0.lock().unwrap()).poll_read(cx, out)
        }
    }
    impl AsyncWrite for SharedWire {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut *self.0.lock().unwrap()).poll_write(cx, data)
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn vmess_split_read_progress_small_write_flush_and_half_close() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let wire = std::sync::Arc::new(std::sync::Mutex::new(Wire::default()));
                let client = ClientStream::new(
                    SharedWire(wire.clone()),
                    &Account::new(
                        &[7; 16],
                        cipher,
                        Options {
                            authenticated_length: auth,
                            no_termination_signal: false,
                        },
                    ),
                    &Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Tcp),
                )
                .unwrap();
                let request = client.write.pending.clone();
                let mut records = response_records(&client, cipher);
                let mut response = response_header(
                    &client,
                    4,
                    client.read.keys.as_ref().unwrap().response_marker,
                );
                response.extend_from_slice(&records.seal(b"response").unwrap());
                wire.lock().unwrap().incoming.extend(response);
                let (mut reader, mut writer) = client.into_split();
                let mut cx = Context::from_waker(Waker::noop());
                assert!(Pin::new(&mut writer)
                    .poll_write(&mut cx, b"request")
                    .is_pending());
                let mut bytes = [0; 8];
                let mut out = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut reader).poll_read(&mut cx, &mut out),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(out.filled(), b"response");
                assert!(reader.state.body.frame()[..8].iter().all(|b| *b == 0));
                wire.lock().unwrap().write_quota = usize::MAX;
                assert!(matches!(
                    Pin::new(&mut writer).poll_write(&mut cx, b"request"),
                    Poll::Ready(Ok(7))
                ));
                assert!(writer.state.pending.is_empty());
                assert!(wire.lock().unwrap().outgoing.len() > request.len() + 7);
                assert!(matches!(
                    Pin::new(&mut writer).poll_shutdown(&mut cx),
                    Poll::Ready(Ok(()))
                ));
                let mut final_response = records.seal(b"after-close").unwrap().to_vec();
                final_response.extend_from_slice(&records.seal(&[]).unwrap());
                wire.lock().unwrap().incoming.extend(final_response);
                let mut bytes = [0; 16];
                let mut out = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut reader).poll_read(&mut cx, &mut out),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(out.filled(), b"after-close");
                let mut out = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut reader).poll_read(&mut cx, &mut out),
                    Poll::Ready(Ok(()))
                ));
                assert!(out.filled().is_empty());
            }
        }
    }

    #[test]
    fn vmess_split_moves_pending_buffer_and_resumes_partial_writes() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            let wire = std::sync::Arc::new(std::sync::Mutex::new(Wire {
                write_quota: usize::MAX,
                ..Wire::default()
            }));
            let mut client = ClientStream::new(
                SharedWire(wire.clone()),
                &Account::new(&[7; 16], cipher, Options::default()),
                &Target::new(TargetAddr::Domain("example.test".into()), 443, Network::Tcp),
            )
            .unwrap();
            let mut cx = Context::from_waker(Waker::noop());
            let payload = vec![0x57; 2 * client.write.writer.max_payload()];
            assert!(
                matches!(Pin::new(&mut client).poll_write(&mut cx,&payload),Poll::Ready(Ok(n)) if n==payload.len())
            );
            let allocation = client.write.pending.as_ptr();
            let capacity = client.write.pending.capacity();
            let expected = client.write.pending.clone();
            assert!(capacity <= 16384);
            let header = wire.lock().unwrap().outgoing.clone();
            let (_reader, mut writer) = client.into_split();
            assert_eq!(allocation, writer.state.pending.as_ptr());
            assert_eq!(capacity, writer.state.pending.capacity());
            wire.lock().unwrap().write_quota = 1;
            assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
            wire.lock().unwrap().write_quota = usize::MAX;
            assert!(matches!(
                Pin::new(&mut writer).poll_flush(&mut cx),
                Poll::Ready(Ok(()))
            ));
            assert_eq!(
                wire.lock().unwrap().outgoing,
                [header.as_slice(), expected.as_slice()].concat()
            );
            assert_eq!(allocation, writer.state.pending.as_ptr());
        }
    }

    #[test]
    fn vmess_split_auth_failure_never_exposes_forged_record() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let mut records = response_records(&client, cipher);
                let mut response = response_header(
                    &client,
                    4,
                    client.read.keys.as_ref().unwrap().response_marker,
                );
                response.extend_from_slice(&records.seal(b"verified").unwrap());
                let mut forged = records.seal(b"forged").unwrap();
                forged[records.size_bytes() + 1] ^= 0x80;
                response.extend_from_slice(&forged);
                client.inner.incoming.extend(response);
                let (mut reader, _writer) = client.into_split();
                let mut bytes = [0xaa; 64];
                let mut out = ReadBuf::new(&mut bytes);
                let mut cx = Context::from_waker(Waker::noop());
                assert!(matches!(
                    Pin::new(&mut reader).poll_read(&mut cx, &mut out),
                    Poll::Ready(Ok(()))
                ));
                assert_eq!(out.filled(), b"verified");
                let mut out = ReadBuf::new(&mut bytes);
                assert!(matches!(
                    Pin::new(&mut reader).poll_read(&mut cx, &mut out),
                    Poll::Ready(Err(_))
                ));
                assert!(out.filled().is_empty());
                assert!(reader.state.failed);
            }
        }
    }
}
