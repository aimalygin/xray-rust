use std::{io, time::Duration};

use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use rand::{rngs::OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{
    crypto::{Aead, HeaderMask},
    crypto_error, invalid_data,
    session::{Cache, Candidate, Prepared},
    CipherSuite, ClientConfig, EncryptedStream, Rtt, XorMode,
};

pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

fn x25519_secret() -> io::Result<StaticSecret> {
    let mut bytes = Zeroizing::new([0; 32]);
    OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| crypto_error())?;
    Ok(StaticSecret::from(*bytes))
}

fn agree(secret: &StaticSecret, public: &[u8]) -> io::Result<x25519_dalek::SharedSecret> {
    let bytes: [u8; 32] = public.try_into().map_err(|_| invalid_data())?;
    let shared = secret.diffie_hellman(&PublicKey::from(bytes));
    if !shared.was_contributory() {
        return Err(invalid_data());
    }
    Ok(shared)
}

impl ClientConfig {
    /// Performs a fresh 1-RTT handshake. A `0rtt` config also stays cold through
    /// this stateless API; use [`crate::Client`] to retain a bounded ticket.
    /// Owns the carrier so cancellation or failure drops it, ephemeral keys,
    /// and pending handshake state. A 30-second ceiling also applies; a
    /// shorter caller deadline wins.
    pub async fn connect<S>(&self, stream: S) -> io::Result<EncryptedStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_with_cipher(stream, CipherSuite::default())
            .await
    }

    /// Explicit cipher selection for platforms and cross-implementation tests.
    /// Both variants use the same pinned wire negotiation; no downgrade retry.
    pub async fn connect_with_cipher<S>(
        &self,
        stream: S,
        suite: CipherSuite,
    ) -> io::Result<EncryptedStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.connect_cached(stream, suite, None).await
    }

    pub(crate) async fn connect_cached<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: S,
        suite: CipherSuite,
        cache: Option<&Cache>,
    ) -> io::Result<EncryptedStream<S>> {
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        tokio::time::timeout_at(deadline, self.handshake(stream, suite, cache, deadline))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "VLESS encryption handshake timed out",
                )
            })?
    }

    async fn handshake<S>(
        &self,
        mut stream: S,
        suite: CipherSuite,
        cache: Option<&Cache>,
        deadline: Instant,
    ) -> io::Result<EncryptedStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut iv = [0; 16];
        OsRng.try_fill_bytes(&mut iv).map_err(|_| crypto_error())?;
        let mut nfs = Zeroizing::new([0; 32]);
        let mut relays = Vec::new();
        let mut previous: Option<HeaderMask> = None;
        for (index, public_key) in self.public_keys.iter().enumerate() {
            let mut relay = match public_key.len() {
                32 => {
                    let secret = x25519_secret()?;
                    let shared = agree(&secret, public_key)?;
                    nfs.copy_from_slice(shared.as_bytes());
                    PublicKey::from(&secret).as_bytes().to_vec()
                }
                1184 => {
                    let key = EncapsulationKey::new(&ML_KEM_768, public_key)
                        .map_err(|_| crypto_error())?;
                    let (ciphertext, shared) = key.encapsulate().map_err(|_| crypto_error())?;
                    nfs.copy_from_slice(shared.as_ref());
                    ciphertext.as_ref().to_vec()
                }
                _ => return Err(crypto_error()),
            };
            if self.mode != XorMode::Native {
                HeaderMask::new(public_key, &iv).apply(&mut relay)?;
            }
            // The previous relay's CTR continues after its 32-byte next-key
            // hash, and masks only the first 32 bytes of this relay blob.
            if let Some(mask) = &mut previous {
                mask.apply(&mut relay[..32])?;
            }
            relays.extend_from_slice(&relay);
            if let Some(next) = self.public_keys.get(index + 1) {
                let mut mask = HeaderMask::new(nfs.as_ref(), &iv);
                let mut hash = *blake3::hash(next).as_bytes();
                mask.apply(&mut hash)?;
                relays.extend_from_slice(&hash);
                previous = Some(mask);
            }
        }
        let mut nfs_aead = Aead::new(&iv, nfs.as_ref(), suite)?;
        let prepared = if self.rtt == Rtt::ZeroRtt {
            cache.map(Cache::prepare).transpose()?
        } else {
            None
        };
        let epoch = match prepared {
            Some(Prepared::Resume(resume)) => {
                let mut united = Zeroizing::new([0; 96]);
                united[..64].copy_from_slice(resume.pfs.as_ref());
                united[64..].copy_from_slice(nfs.as_ref());
                let mut prefix = Vec::with_capacity(16 + relays.len() + 50);
                prefix.extend_from_slice(&iv);
                prefix.extend_from_slice(&relays);
                let mut length = 32_u16.to_be_bytes().to_vec();
                nfs_aead.seal(&mut length, &[])?;
                prefix.extend_from_slice(&length);
                let mut ticket = Zeroizing::new(Vec::with_capacity(32));
                ticket.extend_from_slice(resume.ticket.as_ref());
                nfs_aead.seal(ticket.as_mut(), &[])?;
                let write_aead = Aead::new(&ticket, united.as_ref(), suite)?;
                prefix.extend_from_slice(&ticket);
                let write_mask =
                    (self.mode == XorMode::Random).then(|| HeaderMask::new(united.as_ref(), &iv));
                return Ok(EncryptedStream::resumed(
                    stream,
                    united,
                    write_aead,
                    write_mask,
                    prefix,
                    resume.lease,
                    deadline.min(resume.expires),
                ));
            }
            Some(Prepared::Fresh(epoch)) => Some(epoch),
            None => None,
        };
        let mlkem_secret = DecapsulationKey::generate(&ML_KEM_768).map_err(|_| crypto_error())?;
        let x_secret = x25519_secret()?;
        let mlkem_public = mlkem_secret
            .encapsulation_key()
            .map_err(|_| crypto_error())?;
        let mut client_pfs = mlkem_public
            .key_bytes()
            .map_err(|_| crypto_error())?
            .as_ref()
            .to_vec();
        client_pfs.extend_from_slice(PublicKey::from(&x_secret).as_bytes());

        let padding_plan = self.padding.sample()?;
        let padding_len = padding_plan.total;
        let prefix_len = 16 + relays.len() + 18 + 1232;
        let mut hello = Vec::with_capacity(prefix_len + padding_len);
        hello.extend_from_slice(&iv);
        hello.extend_from_slice(&relays);
        let mut length = 1232_u16.to_be_bytes().to_vec();
        nfs_aead.seal(&mut length, &[])?;
        hello.extend_from_slice(&length);
        let mut pfs = client_pfs.clone();
        nfs_aead.seal(&mut pfs, &[])?;
        hello.extend_from_slice(&pfs);
        let mut length = ((padding_len - 18) as u16).to_be_bytes().to_vec();
        nfs_aead.seal(&mut length, &[])?;
        hello.extend_from_slice(&length);
        let mut padding = vec![0; padding_len - 34];
        nfs_aead.seal(&mut padding, &[])?;
        hello.extend_from_slice(&padding);
        let mut position = 0;
        for (index, length) in padding_plan.lengths.into_iter().enumerate() {
            let length = length + if index == 0 { prefix_len } else { 0 };
            if length > 0 {
                stream
                    .write_all(&hello[position..position + length])
                    .await?;
                stream.flush().await?;
                position += length;
            }
            if let Some(gap) = padding_plan.gaps.get(index).filter(|gap| !gap.is_zero()) {
                tokio::time::sleep(*gap).await;
            }
        }

        let mut server_pfs = [0; 1136];
        stream.read_exact(&mut server_pfs).await?;
        // Authentication is mandatory before using either peer key component.
        let plain_len = nfs_aead.open_server_hello(&mut server_pfs)?;
        if plain_len != 1120 {
            return Err(invalid_data());
        }
        let mlkem_shared = mlkem_secret
            .decapsulate(Ciphertext::from(&server_pfs[..1088]))
            .map_err(|_| invalid_data())?;
        let x_shared = agree(&x_secret, &server_pfs[1088..1120])?;
        let mut united = Zeroizing::new([0; 96]);
        united[..32].copy_from_slice(mlkem_shared.as_ref());
        united[32..64].copy_from_slice(x_shared.as_bytes());
        united[64..].copy_from_slice(nfs.as_ref());
        let write_aead = Aead::new(&client_pfs, united.as_ref(), suite)?;
        let mut read_aead = Aead::new(&server_pfs[..1120], united.as_ref(), suite)?;

        // A cold 0-RTT client receives a ticket through the authenticated
        // 1-RTT path. Keep it unpublished until peer padding verifies.
        let mut ticket = Zeroizing::new([0; 32]);
        stream.read_exact(ticket.as_mut()).await?;
        read_aead.open(ticket.as_mut(), &[])?;
        let mut padding_length = [0; 18];
        stream.read_exact(&mut padding_length).await?;
        read_aead.open(&mut padding_length, &[])?;
        let peer_padding = usize::from(u16::from_be_bytes([padding_length[0], padding_length[1]]));
        if peer_padding < 17 {
            return Err(invalid_data());
        }
        let masks = if self.mode == XorMode::Random {
            Some((
                HeaderMask::new(united.as_ref(), &iv),
                HeaderMask::new(united.as_ref(), ticket[..16].try_into().unwrap()),
            ))
        } else {
            None
        };
        let seconds = u16::from_be_bytes([ticket[0], ticket[1]]);
        let candidate = match (cache, epoch) {
            (Some(cache), Some(epoch)) if seconds > 0 => {
                let mut pfs = Zeroizing::new([0; 64]);
                pfs.copy_from_slice(&united[..64]);
                Some(Candidate::new(
                    cache.clone(),
                    epoch,
                    pfs,
                    ticket[..16].try_into().unwrap(),
                    seconds,
                ))
            }
            _ => None,
        };
        let mut encrypted = EncryptedStream::new(
            stream,
            united,
            write_aead,
            Some(read_aead),
            masks,
            peer_padding,
        );
        encrypted.candidate = candidate;
        Ok(encrypted)
    }
}
