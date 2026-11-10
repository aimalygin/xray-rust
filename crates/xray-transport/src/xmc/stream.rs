//! The carrier after the login: the proxied bytes in Minecraft
//! configuration-state custom payload packets, as Xray-core's client
//! `packetStream` carries them. Every byte passes through it, so Vision's
//! direct mode reads and writes it too.
use super::{
    cfb8::Cfb8,
    proto::{decode_body, frame_into, frame_length, invalid, string, Conn, Fields, READ_CHUNK},
};
use crate::{BoxedTransportStream, TransportStream};
use std::{
    io,
    pin::Pin,
    task::{ready, Context, Poll, Waker},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const CLIENTBOUND_CUSTOM_PAYLOAD: i32 = 0x01;
const SERVERBOUND_CUSTOM_PAYLOAD: i32 = 0x02;
const KEEP_ALIVE: i32 = 0x04;
const CHANNEL: &str = "xmc:data";
/// `maxPacketData`: the proxied bytes one packet carries.
const MAX_PAYLOAD: usize = 24 * 1024;
/// The most keep-alive answers that wait for the carrier before reading
/// stops: a peer that sends keep-alives and reads nothing would otherwise
/// grow `out` for as long as it sends them. Xray answers each one with a
/// blocking write, which stops its reader in the same way.
const MAX_UNSENT_ANSWERS: usize = 64 * 1024;

pub struct XmcStream {
    inner: BoxedTransportStream,
    read_cipher: Cfb8,
    write_cipher: Cfb8,
    /// Decrypted bytes from the carrier, and how many frames took.
    raw: Vec<u8>,
    parsed: usize,
    /// One packet's payload, and how much of it was read.
    pending: Vec<u8>,
    consumed: usize,
    /// Encrypted frames, and how much of them went out.
    out: Vec<u8>,
    written: usize,
    /// Bytes of keep-alive answers put in `out` since it last emptied.
    unsent_answers: usize,
    /// The task a write or flush waits in. A carrier keeps one waker per
    /// direction, so a drain from the read side takes the writer's place
    /// and must wake it once the frames are out.
    blocked_writer: Option<Waker>,
    scratch: Box<[u8]>,
    eof: bool,
}

impl XmcStream {
    /// The stream after a login on `conn`, which left both ciphers on.
    pub(crate) fn new(conn: Conn<BoxedTransportStream>) -> io::Result<Self> {
        let (inner, raw, read_cipher, write_cipher) = conn.into_parts();
        let (Some(read_cipher), Some(write_cipher)) = (read_cipher, write_cipher) else {
            return Err(invalid("xmc login left no cipher"));
        };
        Ok(Self {
            inner,
            read_cipher,
            write_cipher,
            raw,
            parsed: 0,
            pending: Vec::new(),
            consumed: 0,
            out: Vec::new(),
            written: 0,
            unsent_answers: 0,
            blocked_writer: None,
            scratch: vec![0; READ_CHUNK].into_boxed_slice(),
            eof: false,
        })
    }

    /// Drains for a write, flush or shutdown, remembering the writer when it
    /// has to wait.
    fn poll_drain_for_writer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.poll_drain(cx);
        if result.is_pending() {
            self.blocked_writer = Some(cx.waker().clone());
        } else {
            self.blocked_writer = None;
        }
        result
    }

    /// Writes out the frames already encrypted.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        self.out.clear();
        self.written = 0;
        self.unsent_answers = 0;
        Poll::Ready(Ok(()))
    }

    /// Takes the next whole frame from `raw`: a payload goes to `pending`, a
    /// keep-alive is answered and anything else skipped, as Xray's client
    /// does. `Ok(false)` when no whole frame is buffered.
    fn take_frame(&mut self) -> io::Result<bool> {
        let available = &self.raw[self.parsed..];
        let Some((length, header)) = frame_length(available)? else {
            return Ok(false);
        };
        if available.len() < header + length {
            return Ok(false);
        }
        let body = &available[header..header + length];
        self.parsed += header + length;
        let (id, data) = decode_body(body)?;
        match id {
            CLIENTBOUND_CUSTOM_PAYLOAD => {
                let mut fields = Fields(data);
                if fields.string()? == CHANNEL.as_bytes() {
                    self.pending.clear();
                    self.pending.extend_from_slice(fields.rest());
                    self.consumed = 0;
                }
            }
            KEEP_ALIVE => {
                let id = Fields(data).long()?;
                let start = self.out.len();
                frame_into(&mut self.out, KEEP_ALIVE, 8, |out| {
                    out.extend_from_slice(&id.to_be_bytes())
                })?;
                self.write_cipher.apply(&mut self.out[start..]);
                self.unsent_answers += self.out.len() - start;
            }
            _ => {}
        }
        Ok(true)
    }
}

impl AsyncRead for XmcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            // A keep-alive answer goes out on whichever poll can send it,
            // and a writer this drain displaced hears that it may go on.
            if this.written < this.out.len() {
                match this.poll_drain(cx) {
                    Poll::Ready(result) => {
                        if let Some(writer) = this.blocked_writer.take() {
                            writer.wake();
                        }
                        result?;
                    }
                    // The drain left this task's waker with the carrier.
                    Poll::Pending if this.unsent_answers > MAX_UNSENT_ANSWERS => {
                        return Poll::Pending;
                    }
                    Poll::Pending => {}
                }
            }
            if this.consumed < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.consumed);
                buf.put_slice(&this.pending[this.consumed..this.consumed + n]);
                this.consumed += n;
                return Poll::Ready(Ok(()));
            }
            if this.take_frame()? {
                continue;
            }
            if this.eof {
                if this.parsed < this.raw.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "read minecraft packet stream: truncated packet",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            this.raw.drain(..this.parsed);
            this.parsed = 0;
            let mut read = ReadBuf::new(&mut this.scratch);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut read))?;
            let filled = read.filled().len();
            if filled == 0 {
                this.eof = true;
                continue;
            }
            let start = this.raw.len();
            this.raw.extend_from_slice(&this.scratch[..filled]);
            this.read_cipher.apply(&mut this.raw[start..]);
        }
    }
}

impl AsyncWrite for XmcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain_for_writer(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let start = this.out.len();
        for chunk in buf.chunks(MAX_PAYLOAD) {
            let data_len = 1 + CHANNEL.len() + chunk.len();
            frame_into(&mut this.out, SERVERBOUND_CUSTOM_PAYLOAD, data_len, |out| {
                string(out, CHANNEL);
                out.extend_from_slice(chunk);
            })?;
        }
        this.write_cipher.apply(&mut this.out[start..]);
        // The bytes are taken; what the socket cannot take yet goes out on
        // the next write or flush.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_for_writer(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain_for_writer(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl TransportStream for XmcStream {
    fn release_record_alignment(&mut self) {
        self.inner.release_record_alignment();
    }

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

#[cfg(test)]
mod tests;
