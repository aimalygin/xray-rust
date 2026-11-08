use super::*;
use crate::xmc::{
    testing::{profile, server_frame, Seen, Server},
    XmcStream,
};
use crate::BoxedTransportStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

fn config(hostname: &str, password: &str, profiles: Vec<XmcProfile>) -> XmcConfig {
    XmcConfig::new(hostname, profiles, password).unwrap()
}

/// Both ends of a login: what the client returned, what the server saw,
/// and both carriers.
async fn login(
    config: &XmcConfig,
    server: Server,
    remote: SocketAddr,
    profile: usize,
) -> (
    io::Result<()>,
    io::Result<Seen>,
    Conn<BoxedTransportStream>,
    Conn<DuplexStream>,
) {
    let (ours, theirs) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(async move {
        let mut conn = Conn::new(theirs);
        let seen = server.accept(&mut conn).await;
        (seen, conn)
    });
    let mut conn = Conn::new(Box::new(ours) as BoxedTransportStream);
    let schedule = padding::client_schedule();
    // On a paused clock a stalled login reaches the deadline at once.
    let login = client(
        &mut conn,
        config,
        remote,
        &config.profiles[profile],
        &schedule,
    );
    let result = tokio::time::timeout(std::time::Duration::from_secs(600), login)
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
    if result.is_err() {
        // A server waiting for more sees the end, as when Xray's client
        // closes the failed connection.
        conn.inner_mut().shutdown().await.unwrap();
    }
    let (seen, theirs) = server.await.unwrap();
    (result, seen, conn, theirs)
}

#[tokio::test(start_paused = true)]
async fn logs_in_as_xray_core_expects_and_then_carries_bytes() {
    let profiles = vec![profile("Steve", 1), profile("Alex_2", 2)];
    let config = config("", "synthetic-xmc-password", profiles.clone());
    let server = Server::new("synthetic-xmc-password", profiles);
    let remote: SocketAddr = "192.0.2.1:25565".parse().unwrap();
    let (result, seen, conn, mut theirs) = login(&config, server, remote, 1).await;
    result.unwrap();
    assert_eq!(
        seen.unwrap(),
        Seen {
            version: 775,
            address: b"192.0.2.1".to_vec(),
            port: 25565,
            next_state: 2,
            username: b"Alex_2".to_vec(),
            uuid: [2; 16],
        }
    );

    let mut stream = XmcStream::new(conn).unwrap();
    stream.write_all(b"up").await.unwrap();
    stream.flush().await.unwrap();
    let (id, data) = theirs.read_packet().await.unwrap();
    assert_eq!(id, 0x02);
    assert_eq!(data, [&[8][..], b"xmc:data", b"up"].concat());
    theirs
        .write_all(&server_frame(0x01, Some("xmc:data"), b"down"))
        .await
        .unwrap();
    let mut down = [0u8; 4];
    stream.read_exact(&mut down).await.unwrap();
    assert_eq!(&down, b"down");
}

#[tokio::test(start_paused = true)]
async fn the_address_is_the_host_name_or_the_remote_host() {
    let profiles = vec![profile("Steve", 1)];
    for (hostname, remote, address) in [
        ("mc.example.com", "[2001:db8::1]:443", "mc.example.com"),
        ("", "[2001:db8::1]:443", "2001:db8::1"),
        ("", "[::ffff:192.0.2.7]:80", "192.0.2.7"),
        // Xray's chained connection reports 0.0.0.0:0.
        ("", "0.0.0.0:0", "0.0.0.0"),
    ] {
        let config = config(hostname, "pw", profiles.clone());
        let remote: SocketAddr = remote.parse().unwrap();
        let (result, seen, ..) =
            login(&config, Server::new("pw", profiles.clone()), remote, 0).await;
        result.unwrap();
        let seen = seen.unwrap();
        assert_eq!(seen.address, address.as_bytes());
        assert_eq!(seen.port, remote.port());
    }
}

#[tokio::test(start_paused = true)]
async fn a_rejection_carries_the_servers_reason() {
    let profiles = vec![profile("Steve", 1)];
    let remote: SocketAddr = "192.0.2.1:25565".parse().unwrap();
    // Xray's server derives its key from its own password, so this server
    // only stands in for one whose password check failed.
    let mut server = Server::new("other", profiles.clone());
    server.key_password = "pw".to_owned();
    let (result, ..) = login(&config("", "pw", profiles.clone()), server, remote, 0).await;
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("authservers_down"), "{error}");

    let server = Server::new("pw", vec![profile("Alex", 2)]);
    let (result, ..) = login(&config("", "pw", profiles), server, remote, 0).await;
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(error.to_string().contains("white-listed"), "{error}");
}

#[tokio::test(start_paused = true)]
async fn another_key_or_another_profile_is_refused() {
    let profiles = vec![profile("Steve", 1)];
    let remote: SocketAddr = "192.0.2.1:25565".parse().unwrap();
    let (result, seen, ..) = login(
        &config("", "pw", profiles.clone()),
        Server::new("other", profiles.clone()),
        remote,
        0,
    )
    .await;
    assert_eq!(
        result.unwrap_err().to_string(),
        "server public key mismatch"
    );
    seen.unwrap_err();

    for change in 0..4 {
        let mut confirm = profiles[0].clone();
        match change {
            0 => confirm.uuid[15] ^= 1,
            1 => confirm.username = "Steve2".to_owned(),
            2 => confirm.textures_value.push('x'),
            _ => confirm.textures_signature.push('x'),
        }
        let mut server = Server::new("pw", profiles.clone());
        server.confirm = Some(confirm);
        let (result, ..) = login(&config("", "pw", profiles.clone()), server, remote, 0).await;
        assert_eq!(result.unwrap_err().to_string(), "login profile mismatch");
    }
}

#[test]
fn login_success_must_carry_one_signed_textures_property() {
    let steve = profile("Steve", 1);
    let encode = |count: i32, name: &str, signed: u8| {
        let mut data = steve.uuid.to_vec();
        string(&mut data, &steve.username);
        varint(&mut data, count);
        string(&mut data, name);
        string(&mut data, &steve.textures_value);
        data.push(signed);
        string(&mut data, &steve.textures_signature);
        data
    };
    assert!(confirms(&encode(1, "textures", 1), &steve).unwrap());
    assert!(!confirms(&encode(1, "textures", 1), &profile("Steve", 2)).unwrap());
    assert!(confirms(&encode(2, "textures", 1), &steve).is_err());
    assert!(confirms(&encode(1, "skin", 1), &steve).is_err());
    assert!(confirms(&encode(1, "textures", 0), &steve).is_err());
    assert!(confirms(&encode(1, "textures", 2), &steve).is_err());
    let full = encode(1, "textures", 1);
    assert!(confirms(&full[..full.len() - 1], &steve).is_err());
}

#[tokio::test(start_paused = true)]
async fn the_password_fits_beside_the_token_up_to_113_bytes() {
    let profiles = vec![profile("Steve", 1)];
    let remote: SocketAddr = "192.0.2.1:25565".parse().unwrap();
    let longest = "p".repeat(113);
    let (result, seen, ..) = login(
        &config("", &longest, profiles.clone()),
        Server::new(&longest, profiles.clone()),
        remote,
        0,
    )
    .await;
    result.unwrap();
    seen.unwrap();
    let too_long = "p".repeat(114);
    let (result, ..) = login(
        &config("", &too_long, profiles.clone()),
        Server::new(&too_long, profiles),
        remote,
        0,
    )
    .await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn settings_need_profiles_and_a_password() {
    assert!(XmcConfig::new("", Vec::new(), "pw").is_err());
    assert!(XmcConfig::new("", vec![profile("Steve", 1)], "").is_err());
    let config = XmcConfig::new("", vec![profile("Steve", 1)], "pw").unwrap();
    assert!(!format!("{config:?}").contains("\"pw\""));
}
