//! One XUDP association over an owned Mux command stream.
use super::*;
use tokio::io::{AsyncReadExt, ReadHalf, WriteHalf};
use tokio::sync::Mutex as AsyncMutex;
use xray_proxy::mux::{self, Frame, Status};

pub(crate) struct Session {
    target: Target,
    reader: AsyncMutex<Reader>,
    writer: AsyncMutex<Option<Writer>>,
}
struct Reader {
    stream: ReadHalf<BoxedTransportStream>,
    bytes: Vec<u8>,
    failed: bool,
}
struct Writer {
    stream: WriteHalf<BoxedTransportStream>,
    started: bool,
    global_id: [u8; 8],
}
impl Session {
    pub(super) fn new(stream: BoxedTransportStream, target: Target, global_id: [u8; 8]) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            target,
            reader: AsyncMutex::new(Reader {
                stream: reader,
                bytes: Vec::new(),
                failed: false,
            }),
            writer: AsyncMutex::new(Some(Writer {
                stream: writer,
                started: false,
                global_id,
            })),
        }
    }
    pub(super) async fn send(&self, target: &Target, payload: &[u8]) -> Result<(), CoreError> {
        if target != &self.target || payload.is_empty() || payload.len() > mux::MAX_PAYLOAD {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid XUDP datagram").into(),
            );
        }
        let mut owner = self.writer.lock().await;
        let mut writer = owner
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "XUDP writer closed"))?;
        let wire = mux::encode(&Frame {
            session_id: 0,
            status: if writer.started {
                Status::Keep
            } else {
                Status::New
            },
            error: false,
            target: Some(target.clone()),
            global_id: (!writer.started).then_some(writer.global_id),
            payload: Some(payload),
        })?;
        // A cancelled or failed partial frame cannot be retried on this stream.
        writer.stream.write_all(&wire).await?;
        writer.stream.flush().await?;
        writer.started = true;
        *owner = Some(writer);
        Ok(())
    }
    pub(super) async fn recv(&self) -> Result<datagram::Datagram, CoreError> {
        let mut reader = self.reader.lock().await;
        if reader.failed {
            return Err(closed().into());
        }
        loop {
            match mux::decode(&reader.bytes) {
                Ok(Some((frame, n))) => {
                    let result = match frame.status {
                        Status::KeepAlive => None,
                        Status::Keep if frame.session_id == 0 && !frame.error => {
                            frame.payload.filter(|p| !p.is_empty()).map(|payload| {
                                Ok(datagram::Datagram {
                                    source: frame.target.unwrap_or_else(|| self.target.clone()),
                                    payload: payload.to_vec(),
                                })
                            })
                        }
                        _ => Some(Err(closed())),
                    };
                    reader.bytes.drain(..n);
                    if let Some(result) = result {
                        if result.is_err() {
                            reader.failed = true;
                        }
                        return result.map_err(CoreError::from);
                    }
                }
                Err(e) => {
                    reader.failed = true;
                    return Err(e.into());
                }
                Ok(None) => {
                    let capacity = mux::MAX_FRAME - reader.bytes.len();
                    if capacity == 0 {
                        reader.failed = true;
                        return Err(closed().into());
                    }
                    let mut chunk = [0; 4096];
                    let n = match reader.stream.read(&mut chunk[..capacity.min(4096)]).await {
                        Ok(0) => {
                            reader.failed = true;
                            return Err(closed().into());
                        }
                        Ok(n) => n,
                        Err(e) => {
                            reader.failed = true;
                            return Err(e.into());
                        }
                    };
                    reader.bytes.extend_from_slice(&chunk[..n]);
                }
            }
        }
    }
}
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "XUDP session closed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};
    #[tokio::test]
    async fn xudp_receive_retains_partial_metadata_and_payload_when_cancelled() {
        let (stream, mut peer) = tokio::io::duplex(16384);
        let target = Target::new(
            RoutingTargetAddr::Domain("example.test".into()),
            8443,
            RoutingNetwork::Udp,
        );
        let session = Session::new(
            Box::new(protocol_stream::ProtocolStream(stream)),
            target.clone(),
            [7; 8],
        );
        let bytes = mux::encode(&Frame {
            session_id: 0,
            status: Status::Keep,
            error: false,
            target: Some(target.clone()),
            global_id: None,
            payload: Some(b"reply"),
        })
        .unwrap();
        for part in [&bytes[..1], &bytes[1..5], &bytes[5..bytes.len() - 1]] {
            peer.write_all(part).await.unwrap();
            assert!(timeout(Duration::from_millis(1), session.recv())
                .await
                .is_err());
        }
        peer.write_all(&bytes[bytes.len() - 1..]).await.unwrap();
        let packet = session.recv().await.unwrap();
        assert_eq!(packet.source, target);
        assert_eq!(packet.payload, b"reply");
        session.send(&target, b"one").await.unwrap();
        let mut input = [0; 256];
        let n = peer.read(&mut input).await.unwrap();
        let (frame, used) = mux::decode(&input[..n]).unwrap().unwrap();
        assert_eq!(used, n);
        assert_eq!(frame.status, Status::New);
        assert_eq!(frame.global_id, Some([7; 8]));
        session.send(&target, b"two").await.unwrap();
        let n = peer.read(&mut input).await.unwrap();
        let (frame, _) = mux::decode(&input[..n]).unwrap().unwrap();
        assert_eq!(frame.status, Status::Keep);
        assert_eq!(frame.payload, Some(b"two".as_slice()));
    }
}
