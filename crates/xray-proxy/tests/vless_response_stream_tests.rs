use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::time::{timeout, Duration};
use xray_proxy::vless::VlessResponseStream;

#[tokio::test]
async fn strips_vless_response_header_before_payload() {
    let (mut server, client) = duplex(64);
    let mut stream = VlessResponseStream::new(client);

    let server_task = tokio::spawn(async move {
        server.write_all(&[0, 0]).await.unwrap();
        server.write_all(b"payload").await.unwrap();
    });

    let mut payload = [0; 7];
    stream.read_exact(&mut payload).await.unwrap();

    assert_eq!(&payload, b"payload");
    server_task.await.unwrap();
}

#[tokio::test]
async fn allows_writes_before_response_header_arrives() {
    let (mut server, client) = duplex(64);
    let mut stream = VlessResponseStream::new(client);

    stream.write_all(b"request").await.unwrap();

    let mut request = [0; 7];
    timeout(Duration::from_secs(1), server.read_exact(&mut request))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&request, b"request");
}
