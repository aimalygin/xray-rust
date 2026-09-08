//! In-memory fuzz drivers. Only compiled with the explicit `fuzzing` feature;
//! the production API cannot construct a stream with caller-selected secrets.
use std::{cell::RefCell, io::Cursor, rc::Rc};

use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_768};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use super::*;
use crate::{CipherSuite, Encryption, XorMode};

type Reply = Box<dyn FnOnce(&[u8]) -> Vec<u8>>;

// Fragment every operation and insert Pending between fragments. A wake is
// guaranteed, so cancellation/partial-I/O paths need neither sockets nor sleep.
struct Wire {
    input: Cursor<Vec<u8>>,
    written: Rc<RefCell<Vec<u8>>>,
    reply: Option<Reply>,
    chunk: usize,
    pending: bool,
}

impl Wire {
    fn new(input: Vec<u8>, chunk: usize) -> Self {
        Self {
            input: Cursor::new(input),
            written: Rc::default(),
            reply: None,
            chunk,
            pending: false,
        }
    }

    fn yield_once(&mut self, cx: &Context<'_>) -> bool {
        self.pending = !self.pending;
        if self.pending {
            cx.waker().wake_by_ref();
        }
        self.pending
    }
}

impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.yield_once(cx) {
            return Poll::Pending;
        }
        if let Some(reply) = self.reply.take() {
            let input = reply(&self.written.borrow());
            self.input = Cursor::new(input);
        }
        let pos = self.input.position() as usize;
        let n = out
            .remaining()
            .min(self.chunk)
            .min(self.input.get_ref().len() - pos);
        out.put_slice(&self.input.get_ref()[pos..pos + n]);
        self.input.set_position((pos + n) as u64);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.yield_once(cx) {
            return Poll::Pending;
        }
        let n = data.len().min(self.chunk);
        self.written.borrow_mut().extend_from_slice(&data[..n]);
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
}

fn suite(data: &[u8]) -> CipherSuite {
    if data[0] & 1 == 0 {
        CipherSuite::Aes256Gcm
    } else {
        CipherSuite::ChaCha20Poly1305
    }
}

fn mutate(wire: &mut Vec<u8>, data: &[u8]) {
    if wire.is_empty() {
        return;
    }
    let offset = usize::from(u16::from_le_bytes([data[2], data[3]])) % wire.len();
    match data[1] % 3 {
        1 => wire[offset] ^= 1 << (data[4] % 8),
        2 => wire.truncate(offset),
        _ => (),
    }
}

/// Exercise raw framing plus authenticated records, masking, padding, rekey,
/// fragmentation and output integrity. Each input is bounded to 64 KiB.
pub fn records(data: &[u8]) {
    if data.len() < 6 || data.len() > 65536 {
        return;
    }
    runtime().block_on(async {
        let key = [0x56; 96];
        let masked = data[0] & 2 != 0;
        let rekey = data[0] & 4 != 0;
        let make = |wire, padding_len| {
            let mut write = Aead::new(b"records", &key, suite(data)).unwrap();
            let mut read = Aead::new(b"records", &key, suite(data)).unwrap();
            if rekey {
                write.nonce = MAX_NONCE;
                read.nonce = MAX_NONCE;
            }
            EncryptedStream::new(
                wire,
                Zeroizing::new(key),
                write,
                Some(read),
                masked.then(|| {
                    (
                        HeaderMask::new(&key, &[1; 16]),
                        HeaderMask::new(&key, &[1; 16]),
                    )
                }),
                padding_len,
            )
        };
        let writer = Wire::new(Vec::new(), usize::from(data[5]) + 1);
        let output = Rc::clone(&writer.written);
        let mut writer = make(writer, 0);
        writer.write_all(&data[6..]).await.unwrap();
        writer.shutdown().await.unwrap();
        let mut wire = output.borrow().clone();
        mutate(&mut wire, data);
        let mut reader = make(Wire::new(wire, usize::from(data[5]) + 1), 0);
        let mut plain = Vec::new();
        let result = reader.read_to_end(&mut plain).await;
        // A damaged/truncated record may expose preceding authenticated records,
        // but never corrupted bytes from the affected record.
        assert!(data[6..].starts_with(&plain));
        if data[1].is_multiple_of(3) {
            result.as_ref().unwrap();
            assert_eq!(plain, data[6..]);
        }
        if result.is_err() {
            assert!(reader.write_all(b"must fail closed").await.is_err());
        }
        // Vision changes only one direction at an authenticated record
        // boundary. Fuzz cancellation/fragmentation and continuous XorConn
        // state across the transition, including arbitrary inner TLS bytes.
        let sink = Wire::new(Vec::new(), usize::from(data[5]) + 1);
        let output = Rc::clone(&sink.written);
        let mut writer = make(sink, 0);
        writer.write_all(b"Dtail").await.unwrap();
        let mut direct = Vec::new();
        for chunk in data[6..].chunks(16000) {
            let mut body = chunk.to_vec();
            body.resize(body.len().max(17), 0);
            direct.extend_from_slice(&[23, 3, 3]);
            direct.extend_from_slice(&(body.len() as u16).to_be_bytes());
            direct.extend_from_slice(&body);
        }
        let mut remaining = direct.as_slice();
        while !remaining.is_empty() {
            let n = std::future::poll_fn(|cx| writer.poll_write_vision_direct(cx, remaining))
                .await
                .unwrap();
            remaining = &remaining[n..];
        }
        writer.shutdown().await.unwrap();
        let mut wire = output.borrow().clone();
        mutate(&mut wire, data);
        let mut reader = make(Wire::new(wire, usize::from(data[5]) + 1), 0);
        if reader.read_u8().await.is_ok() {
            let mut first = [0; 2];
            let mut buffer = ReadBuf::new(&mut first);
            if std::future::poll_fn(|cx| reader.poll_read_vision_direct(cx, &mut buffer))
                .await
                .is_ok()
            {
                let mut actual = buffer.filled().to_vec();
                let result = reader.read_to_end(&mut actual).await;
                if data[1].is_multiple_of(3) {
                    result.unwrap();
                    assert_eq!(actual, [b"tail".as_slice(), direct.as_slice()].concat());
                }
            }
        }
        // Arbitrary headers/ciphertexts and lazy padding lengths, without a
        // generated valid envelope. Bounds are enforced by production code.
        let padding = if data[0] & 8 != 0 {
            usize::from(u16::from_le_bytes([data[2], data[3]]))
        } else {
            0
        };
        let mut raw = make(
            Wire::new(data[6..].to_vec(), usize::from(data[5]) + 1),
            padding,
        );
        let _ = raw.read_to_end(&mut Vec::new()).await;
    });
}

/// Exercise the real client handshake, including authenticated malformed peer
/// keys/tickets/padding. Fresh cryptographic randomness is retained; control
/// bytes deterministically select the corrupted field and I/O fragmentation.
pub fn handshake(data: &[u8]) {
    if data.len() < 6 || data.len() > 65536 {
        return;
    }
    runtime().block_on(async {
        let mode = match data[5] % 3 {
            0 => "native",
            1 => "xorpub",
            _ => "random",
        };
        let secret = StaticSecret::from([0x23; 32]);
        let public = PublicKey::from(&secret);
        let config: Encryption = format!(
            "mlkem768x25519plus.{mode}.1rtt.{}",
            URL_SAFE_NO_PAD.encode(public.as_bytes())
        )
        .parse()
        .unwrap();
        let client = config.client().unwrap();
        let suite = suite(data);
        let controls = data.to_vec();
        let mut wire = Wire::new(Vec::new(), usize::from(data[4]) + 1);
        let xor_mode = client.mode;
        wire.reply = Some(Box::new(move |hello| {
            if controls[0] & 8 != 0 {
                return controls[6..].to_vec();
            }
            let iv: [u8; 16] = hello[..16].try_into().unwrap();
            let mut relay: [u8; 32] = hello[16..48].try_into().unwrap();
            if xor_mode != XorMode::Native {
                HeaderMask::new(public.as_bytes(), &iv)
                    .apply(&mut relay)
                    .unwrap();
            }
            let nfs = secret.diffie_hellman(&PublicKey::from(relay));
            let mut aead = Aead::new(&iv, nfs.as_bytes(), suite).unwrap();
            let mut length = hello[48..66].to_vec();
            aead.open(&mut length, &[]).unwrap();
            let mut client_pfs = hello[66..1298].to_vec();
            aead.open(&mut client_pfs, &[]).unwrap();
            let (ciphertext, shared) = EncapsulationKey::new(&ML_KEM_768, &client_pfs[..1184])
                .unwrap()
                .encapsulate()
                .unwrap();
            let x_secret = StaticSecret::from([0x71; 32]);
            let peer: [u8; 32] = client_pfs[1184..1216].try_into().unwrap();
            let x_shared = x_secret.diffie_hellman(&PublicKey::from(peer));
            let mut united = Zeroizing::new([0; 96]);
            united[..32].copy_from_slice(shared.as_ref());
            united[32..64].copy_from_slice(x_shared.as_bytes());
            united[64..].copy_from_slice(nfs.as_bytes());
            let mut pfs = ciphertext.as_ref().to_vec();
            pfs.extend_from_slice(PublicKey::from(&x_secret).as_bytes());
            if controls[0] & 16 != 0 {
                pfs[1088..].fill(0);
            }
            let mut read = Aead::new(&pfs, united.as_ref(), suite).unwrap();
            // The existing AEAD counter reaches the reserved server nonce.
            aead.nonce = MAX_NONCE;
            aead.nonce[11] -= 1;
            aead.seal(&mut pfs, &[]).unwrap();
            let mut reply = pfs;
            let ticket = [0x35; 16];
            let mut sealed_ticket = ticket.to_vec();
            read.seal(&mut sealed_ticket, &[]).unwrap();
            reply.extend(sealed_ticket);
            let pad_len = if controls[0] & 32 != 0 {
                u16::from_le_bytes([controls[2], controls[3]])
            } else {
                35
            };
            let mut pad_size = pad_len.to_be_bytes().to_vec();
            read.seal(&mut pad_size, &[]).unwrap();
            reply.extend(pad_size);
            let mut padding = vec![0; usize::from(pad_len).saturating_sub(16)];
            read.seal(&mut padding, &[]).unwrap();
            reply.extend(padding);
            if pad_len >= 17 {
                let mut payload = controls[6..].to_vec();
                payload.truncate(8192);
                if !payload.is_empty() {
                    let size = (payload.len() + 16) as u16;
                    let mut header = [23, 3, 3, (size >> 8) as u8, size as u8];
                    read.seal(&mut payload, &header).unwrap();
                    if xor_mode == XorMode::Random {
                        HeaderMask::new(united.as_ref(), &ticket)
                            .apply(&mut header)
                            .unwrap();
                    }
                    reply.extend(header);
                    reply.extend(payload);
                }
            }
            mutate(&mut reply, &controls);
            reply
        }));
        let connected = client.connect_with_cipher(wire, suite).await;
        if let Ok(mut stream) = connected {
            let mut plain = Vec::new();
            let result = stream.read_to_end(&mut plain).await;
            assert!(data[6..data.len().min(8198)].starts_with(&plain));
            if data[0] & 56 == 0 && data[1].is_multiple_of(3) {
                result.unwrap();
                assert_eq!(plain, data[6..data.len().min(8198)]);
            }
        } else if data[0] & 56 == 0 && data[1].is_multiple_of(3) {
            panic!("valid generated handshake must succeed");
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn drivers_reach_valid_and_damaged_paths() {
        for mode in 0..64 {
            for damage in 0..3 {
                let mut data = vec![mode, damage, 0x70, 4, 17, mode];
                data.extend_from_slice(b"authenticated fuzz seed payload");
                super::records(&data);
                super::handshake(&data);
            }
        }
    }
}
