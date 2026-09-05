use super::*;
use xray_vless_encryption::{Client, EncryptedStream};

pub(super) async fn wrap(
    mut stream: BoxedTransportStream,
    client: Option<&Client>,
    vision: bool,
) -> Result<BoxedTransportStream, CoreError> {
    let Some(client) = client else {
        return Ok(stream);
    };
    stream.release_record_alignment();
    Ok(Box::new(EncryptionTransport {
        inner: client.connect(stream).await?,
        vision,
    }))
}

struct EncryptionTransport {
    inner: EncryptedStream<BoxedTransportStream>,
    vision: bool,
}

impl AsyncRead for EncryptionTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, output)
    }
}

impl AsyncWrite for EncryptionTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, input)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl TransportStream for EncryptionTransport {
    // Vision removes only CommonConn: retain outer TLS/REALITY/HTTP and,
    // in random mode, the continuous header mask. Ordinary callers stay encrypted.
    fn poll_read_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.vision {
            self.get_mut().inner.poll_read_vision_direct(cx, output)
        } else {
            AsyncRead::poll_read(self, cx, output)
        }
    }
    fn poll_write_direct(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.vision {
            self.get_mut().inner.poll_write_vision_direct(cx, input)
        } else {
            AsyncWrite::poll_write(self, cx, input)
        }
    }
}
