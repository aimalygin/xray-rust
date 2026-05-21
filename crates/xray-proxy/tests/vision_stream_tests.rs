use tokio::io::{AsyncReadExt, AsyncWriteExt};
use xray_proxy::vless::{unpad_vision_block, VisionCommand, VisionStream};

const USER_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
];

#[tokio::test]
async fn vision_stream_write_emits_padded_blocks() {
    let (client, mut server) = tokio::io::duplex(4096);
    let mut stream = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);

    stream.write_all(b"hello vision").await.unwrap();
    stream.flush().await.unwrap();

    let mut padded = vec![0; 16 + 5 + "hello vision".len()];
    server.read_exact(&mut padded).await.unwrap();
    let unpadded = unpad_vision_block(&padded, &USER_ID).unwrap();

    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(&unpadded.payload[..], b"hello vision");
}

#[tokio::test]
async fn vision_stream_read_returns_unpadded_payload() {
    let (client, server) = tokio::io::duplex(4096);
    let mut sender = VisionStream::new(server, USER_ID, [0, 0, 0, 0]);
    let mut receiver = VisionStream::new(client, USER_ID, [0, 0, 0, 0]);

    sender.write_all(b"reply bytes").await.unwrap();
    sender.shutdown().await.unwrap();

    let mut received = Vec::new();
    receiver.read_to_end(&mut received).await.unwrap();

    assert_eq!(received, b"reply bytes");
}
