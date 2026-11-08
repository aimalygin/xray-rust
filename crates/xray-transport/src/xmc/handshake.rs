//! The client's login, as Xray-core's `clientConn.handshake` runs it.
use super::{
    cfb8::Cfb8,
    padding::{self, Turn},
    proto::{bytes, invalid, string, varint, Conn, Fields},
    XmcConfig, XmcProfile,
};
use rand::RngCore;
use std::{io, net::SocketAddr};
use tokio::io::{AsyncRead, AsyncWrite};

/// Minecraft 26.1.2's protocol number.
const PROTOCOL_VERSION: i32 = 775;
/// The handshake's next state: login.
const LOGIN: i32 = 2;

/// The handshake packet's address: the configured host name, or the host the
/// carrier reports as its remote end, as Go prints it.
fn server_address(config: &XmcConfig, remote: SocketAddr) -> String {
    if config.hostname.is_empty() {
        remote.ip().to_canonical().to_string()
    } else {
        config.hostname.clone()
    }
}

/// Logs in as `profile` and runs `schedule`, leaving the ciphers on.
pub(crate) async fn client<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    config: &XmcConfig,
    remote: SocketAddr,
    profile: &XmcProfile,
    schedule: &[Turn],
) -> io::Result<()> {
    let mut handshake = Vec::new();
    varint(&mut handshake, PROTOCOL_VERSION);
    string(&mut handshake, &server_address(config, remote));
    handshake.extend_from_slice(&remote.port().to_be_bytes());
    varint(&mut handshake, LOGIN);
    conn.write_packet(0x00, &handshake).await?;

    let mut login_start = Vec::new();
    string(&mut login_start, &profile.username);
    login_start.extend_from_slice(&profile.uuid);
    conn.write_packet(0x00, &login_start).await?;

    let (id, request) = conn.read_packet().await?;
    if id != 0x01 {
        return Err(invalid("bad encrypt request packet id"));
    }
    let mut fields = Fields(&request);
    let _server_id = fields.string()?;
    let public_key = fields.bytes()?;
    let verify_token = fields.bytes()?;
    if public_key != config.key.pkix.as_slice() {
        return Err(invalid("server public key mismatch"));
    }

    let mut secret = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let encrypted_secret = config.key.encrypt(&secret)?;
    // The password rides after the verify token.
    let encrypted_token = config
        .key
        .encrypt(&[verify_token, config.password.as_bytes()].concat())?;
    let mut response = Vec::new();
    bytes(&mut response, &encrypted_secret);
    bytes(&mut response, &encrypted_token);
    conn.write_packet(0x01, &response).await?;

    conn.read_cipher = Some(Cfb8::new(&secret, true));
    conn.write_cipher = Some(Cfb8::new(&secret, false));

    let (id, success) = conn.read_packet().await?;
    if id == 0x00 {
        let message = match Fields(&success).string() {
            Ok(reason) => format!(
                "authentication rejected: {}",
                String::from_utf8_lossy(reason)
            ),
            Err(_) => "authentication rejected".to_owned(),
        };
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
    }
    if id != 0x02 {
        return Err(invalid(format!("bad login finished packet id: {id}")));
    }
    if !confirms(&success, profile)? {
        return Err(invalid("login profile mismatch"));
    }
    let acknowledged = conn.write_packet(0x03, &[]).await?;
    padding::run(conn, schedule, true, acknowledged).await
}

/// `readLoginSuccess`, compared with the profile the client logged in as.
fn confirms(data: &[u8], profile: &XmcProfile) -> io::Result<bool> {
    let mut fields = Fields(data);
    let uuid = fields.uuid()?;
    let username = fields.string()?;
    let properties = fields.varint()?;
    let name = fields.string()?;
    let value = fields.string()?;
    let signed = fields.boolean()?;
    let signature = fields.string()?;
    if properties != 1 || name != b"textures" || !signed {
        return Err(invalid("invalid login profile properties"));
    }
    Ok(uuid == profile.uuid
        && username == profile.username.as_bytes()
        && value == profile.textures_value.as_bytes()
        && signature == profile.textures_signature.as_bytes())
}

#[cfg(test)]
mod tests;
