use super::{records::Records, *};
use std::{
    pin::Pin,
    task::{ready, Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Bounded client records with owned pending writes and resumable reads.
/// For a UDP target, each nonempty write and read is exactly one datagram;
/// reads require room for the complete datagram and never truncate it.
pub struct ClientStream<S> {
    inner: S,
    keys: Option<SessionKeys>,
    writer: Records,
    reader: Records,
    options: Options,
    packet: bool,
    pending: Zeroizing<Vec<u8>>,
    pending_pos: usize,
    body: crate::record_buffer::RecordBuffer,
    plain_len: usize,
    plain_pos: usize,
    phase: Phase,
    padding: usize,
    failed: bool,
    eof: bool,
    closing: bool,
}
#[derive(Clone, Copy)]
enum Phase {
    HeaderLength,
    Header,
    Length,
    Payload,
    Plain,
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
        Ok(Self {
            inner,
            keys: Some(keys),
            writer,
            reader,
            options: account.options,
            packet: target.is_some_and(|t| t.network == Network::Udp),
            pending,
            pending_pos: 0,
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
            phase: Phase::HeaderLength,
            padding: 0,
            failed: false,
            eof: false,
            closing: false,
        })
    }
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
                    self.phase = Phase::Plain;
                    self.plain_pos = 0;
                }
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
            return Poll::Ready(Err(invalid("VMess stream failed")));
        }
        if out.remaining() == 0 || this.eof {
            return Poll::Ready(Ok(()));
        }
        // Try to advance buffered writes, but backpressure in that direction
        // must not prevent receiving an already available response. In
        // particular both peers may be writing with full socket buffers.
        if let Poll::Ready(result) = this.drain(cx) {
            result?;
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
                    let n = out.remaining().min(remaining);
                    out.put_slice(&this.body.frame()[this.plain_pos..this.plain_pos + n]);
                    crate::erase::erase(&mut this.body.frame()[this.plain_pos..this.plain_pos + n]);
                    this.plain_pos += n;
                    return Poll::Ready(Ok(()));
                }
                this.expect(this.reader.size_bytes(), Phase::Length);
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
            if let Err(e) = this.process() {
                this.failed = true;
                return Poll::Ready(Err(e));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
        }
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ClientStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed || this.closing {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if this.packet && data.len() > this.writer.max_payload() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VMess datagram exceeds record limit",
            )));
        }
        ready!(this.drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(this.writer.max_payload());
        if let Err(e) = this.writer.seal_into(&data[..n], &mut this.pending) {
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
        if !this.closing {
            this.closing = true;
            if !this.options.no_termination_signal {
                if let Err(e) = this.writer.seal_into(&[], &mut this.pending) {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
        ready!(this.drain(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
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
    fn response_header(client: &ClientStream<Wire>, size: u16, marker: u8) -> Vec<u8> {
        response_header_options(client, size, marker, 0)
    }
    fn response_header_options(
        client: &ClientStream<Wire>,
        size: u16,
        marker: u8,
        options: u8,
    ) -> Vec<u8> {
        let keys = client.keys.as_ref().unwrap();
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
    fn response_records(client: &ClientStream<Wire>, cipher: Cipher) -> Records {
        let keys = client.keys.as_ref().unwrap();
        Records::new(
            cipher,
            &keys.response_key,
            &keys.response_iv,
            client
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
    fn vmess_read_ahead_authenticates_each_record_before_exposing_plaintext() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let mut records = response_records(&client, cipher);
                let mut wire =
                    response_header(&client, 4, client.keys.as_ref().unwrap().response_marker);
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
                assert!(client.body.frame()[..2].iter().all(|&b| b == 0));
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
                assert!(client.failed);
            }
        }
    }

    #[test]
    fn vmess_response_progresses_while_outgoing_record_is_blocked() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            for auth in [false, true] {
                let mut client = client(cipher, auth, Network::Tcp);
                let mut records = response_records(&client, cipher);
                let mut wire =
                    response_header(&client, 4, client.keys.as_ref().unwrap().response_marker);
                wire.extend_from_slice(&records.seal(b"response").unwrap());
                let mut cx = Context::from_waker(Waker::noop());
                assert!(matches!(
                    Pin::new(&mut client).poll_write(&mut cx, b"request"),
                    Poll::Ready(Ok(7))
                ));
                let request = client.pending.clone();
                let sent = client.inner.outgoing.len();
                client.inner.write_quota = 1;
                client.inner.incoming.extend(wire);
                let mut output = [0; 32];
                assert!(matches!(
                    poll_read(&mut client, &mut output),
                    Poll::Ready(Ok(8))
                ));
                assert_eq!(&output[..8], b"response");
                assert_eq!(client.pending_pos, 1);
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
                    let mut wire =
                        response_header(&client, 4, client.keys.as_ref().unwrap().response_marker);
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
            let marker = client.keys.as_ref().unwrap().response_marker;
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
        let mut wire = response_header(&client, 4, client.keys.as_ref().unwrap().response_marker);
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
        let oversize = vec![0; client.writer.max_payload() + 1];
        assert!(
            matches!(Pin::new(&mut client).poll_write(&mut Context::from_waker(Waker::noop()), &oversize), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::InvalidInput)
        );
        assert!(!client.failed);
    }

    #[test]
    fn vmess_partial_write_flush_and_shutdown_resume_without_duplicate_bytes() {
        let mut client = client(Cipher::Aes128Gcm, false, Network::Tcp);
        let request = client.pending.clone();
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
        let record = client.pending.clone();
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
        let termination = client.pending.clone();
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
            let wire = response_header(&client, 4, client.keys.as_ref().unwrap().response_marker);
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
                    client.options.no_termination_signal = no_termination;
                    let options = if valid { client.options.wire() } else { 0x80 };
                    let mut wire = response_header_options(
                        &client,
                        4,
                        client.keys.as_ref().unwrap().response_marker,
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
                        assert!(client.failed);
                    }
                }
            }
        }
    }
}
