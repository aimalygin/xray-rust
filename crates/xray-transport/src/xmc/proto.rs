//! Minecraft's framing as Xray-core's xmc mask reads and writes it, over a
//! carrier whose CFB8 cipher turns on after the key exchange.
use super::cfb8::Cfb8;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A frame's data: at most 32 KiB after the packet ID.
pub(crate) const MAX_DATA: usize = 32 * 1024;
/// `maxPacketBodyLength`: the packet ID and its data.
pub(crate) const MAX_BODY: usize = MAX_DATA + 5;
/// How much one read from the carrier asks for.
pub(crate) const READ_CHUNK: usize = 16 * 1024;

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub(crate) fn varint(out: &mut Vec<u8>, value: i32) {
    let mut value = value as u32;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

pub(crate) fn varint_size(value: i32) -> usize {
    let mut value = value as u32;
    let mut size = 1;
    while value >= 0x80 {
        value >>= 7;
        size += 1;
    }
    size
}

pub(crate) fn string(out: &mut Vec<u8>, value: &str) {
    bytes(out, value.as_bytes());
}

pub(crate) fn bytes(out: &mut Vec<u8>, value: &[u8]) {
    varint(out, value.len() as i32);
    out.extend_from_slice(value);
}

/// `encodePacket`, appended to `out`: the body's length, the packet ID and
/// the data, which `write_data` writes.
pub(crate) fn frame_into(
    out: &mut Vec<u8>,
    id: i32,
    data_len: usize,
    write_data: impl FnOnce(&mut Vec<u8>),
) -> io::Result<()> {
    if data_len > MAX_DATA {
        return Err(invalid(format!("write packet: bad length: {data_len}")));
    }
    let body = varint_size(id) + data_len;
    varint(out, body as i32);
    varint(out, id);
    let start = out.len();
    write_data(out);
    debug_assert_eq!(out.len() - start, data_len);
    Ok(())
}

pub(crate) fn frame(id: i32, data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(5 + 5 + data.len());
    frame_into(&mut out, id, data.len(), |out| out.extend_from_slice(data))?;
    Ok(out)
}

/// A reader over a packet's data. Like Xray's `readFields`, it leaves
/// whatever follows the fields it reads.
pub(crate) struct Fields<'a>(pub(crate) &'a [u8]);

impl<'a> Fields<'a> {
    pub(crate) fn varint(&mut self) -> io::Result<i32> {
        match decode_varint(self.0)? {
            Some((value, used)) => {
                self.0 = &self.0[used..];
                Ok(value)
            }
            None => Err(invalid("read varint: short")),
        }
    }

    fn take(&mut self, length: usize) -> io::Result<&'a [u8]> {
        if self.0.len() < length {
            return Err(invalid("read packet field: short"));
        }
        let (head, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(head)
    }

    /// A string's bytes. Go's `String` takes any bytes, UTF-8 or not.
    pub(crate) fn string(&mut self) -> io::Result<&'a [u8]> {
        let length = self.varint()?;
        if !(0..=4096).contains(&length) {
            return Err(invalid(format!("read string: bad length: {length}")));
        }
        self.take(length as usize)
    }

    pub(crate) fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let length = self.varint()?;
        if !(0..1024).contains(&length) {
            return Err(invalid(format!("read bytes: invalid size: {length}")));
        }
        self.take(length as usize)
    }

    #[cfg(test)]
    pub(crate) fn ushort(&mut self) -> io::Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("two bytes"),
        ))
    }

    pub(crate) fn uuid(&mut self) -> io::Result<[u8; 16]> {
        Ok(self.take(16)?.try_into().expect("sixteen bytes"))
    }

    pub(crate) fn boolean(&mut self) -> io::Result<bool> {
        match self.take(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(invalid(format!("read boolean: invalid value: {value}"))),
        }
    }

    pub(crate) fn long(&mut self) -> io::Result<i64> {
        Ok(i64::from_be_bytes(
            self.take(8)?.try_into().expect("eight bytes"),
        ))
    }

    /// What is left: `RestBytes`.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.0
    }
}

/// A canonical varint of at most five bytes at the start of `input`: its
/// value and length, or `None` while every byte so far continues it.
pub(crate) fn decode_varint(input: &[u8]) -> io::Result<Option<(i32, usize)>> {
    let mut value: u32 = 0;
    for index in 0..5 {
        let Some(&byte) = input.get(index) else {
            return Ok(None);
        };
        if index == 4 && byte & 0xf0 != 0 {
            return Err(invalid("read varint: too large"));
        }
        value |= u32::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            let value = value as i32;
            if index + 1 != varint_size(value) {
                return Err(invalid("read varint: non-canonical encoding"));
            }
            return Ok(Some((value, index + 1)));
        }
    }
    Err(invalid("read varint: too large"))
}

/// `decodePacketBody`: the packet ID and its data.
pub(crate) fn decode_body(body: &[u8]) -> io::Result<(i32, &[u8])> {
    if body.is_empty() || body.len() > MAX_BODY {
        return Err(invalid(format!("read packet: bad length: {}", body.len())));
    }
    let (id, used) = decode_varint(body)?.ok_or_else(|| invalid("read packet ID: short"))?;
    let data = &body[used..];
    if data.len() > MAX_DATA {
        return Err(invalid(format!("read packet: bad length: {}", data.len())));
    }
    Ok((id, data))
}

/// A frame's length prefix: `Ok(None)` while it is incomplete, an error when
/// it is not a body length `readFrame` takes.
pub(crate) fn frame_length(input: &[u8]) -> io::Result<Option<(usize, usize)>> {
    let Some((length, used)) = decode_varint(input)? else {
        return Ok(None);
    };
    if length < 1 || length as usize > MAX_BODY {
        return Err(invalid(format!("read packet: bad length: {length}")));
    }
    Ok(Some((length as usize, used)))
}

/// The carrier during the login, with the ciphers it turns on. Reads come
/// through a buffer, as Xray's `bufio.Reader`, and are decrypted as they are
/// taken from it, so a cipher turned on mid-buffer applies from there.
pub(crate) struct Conn<S> {
    inner: S,
    buffer: Vec<u8>,
    taken: usize,
    pub(crate) read_cipher: Option<Cfb8>,
    pub(crate) write_cipher: Option<Cfb8>,
}

impl<S> Conn<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            taken: 0,
            read_cipher: None,
            write_cipher: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// The carrier and the bytes it delivered past the login, decrypted.
    pub(crate) fn into_parts(mut self) -> (S, Vec<u8>, Option<Cfb8>, Option<Cfb8>) {
        let mut rest = self.buffer.split_off(self.taken);
        if let Some(cipher) = &mut self.read_cipher {
            cipher.apply(&mut rest);
        }
        (self.inner, rest, self.read_cipher, self.write_cipher)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Conn<S> {
    pub(crate) async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match &mut self.write_cipher {
            Some(cipher) => {
                let mut data = data.to_vec();
                cipher.apply(&mut data);
                self.inner.write_all(&data).await
            }
            None => self.inner.write_all(data).await,
        }
    }

    pub(crate) async fn read_exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            if self.taken == self.buffer.len() {
                self.buffer.resize(READ_CHUNK, 0);
                let n = self.inner.read(&mut self.buffer).await?;
                self.buffer.truncate(n);
                self.taken = 0;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            let n = (out.len() - filled).min(self.buffer.len() - self.taken);
            out[filled..filled + n].copy_from_slice(&self.buffer[self.taken..self.taken + n]);
            self.taken += n;
            filled += n;
        }
        if let Some(cipher) = &mut self.read_cipher {
            cipher.apply(out);
        }
        Ok(())
    }

    /// `readVarintWithLength`: a varint read byte by byte, and its length.
    pub(crate) async fn read_varint(&mut self) -> io::Result<(i32, usize)> {
        let mut bytes = Vec::with_capacity(5);
        loop {
            let mut byte = [0u8];
            self.read_exact(&mut byte).await?;
            bytes.push(byte[0]);
            if let Some(value) = decode_varint(&bytes)? {
                return Ok(value);
            }
        }
    }

    /// `readPacket`: a frame of at most `MAX_BODY` bytes, as its ID and data.
    pub(crate) async fn read_packet(&mut self) -> io::Result<(i32, Vec<u8>)> {
        let (length, _) = self.read_varint().await?;
        if length < 1 || length as usize > MAX_BODY {
            return Err(invalid(format!("read packet: bad length: {length}")));
        }
        let mut body = vec![0; length as usize];
        self.read_exact(&mut body).await?;
        let (id, data) = decode_body(&body)?;
        Ok((id, data.to_vec()))
    }

    /// `writePacketWithLength`: the frame in one write, and its length.
    pub(crate) async fn write_packet(&mut self, id: i32, data: &[u8]) -> io::Result<usize> {
        let frame = frame(id, data)?;
        self.write_all(&frame).await?;
        Ok(frame.len())
    }
}

#[cfg(test)]
mod tests;
