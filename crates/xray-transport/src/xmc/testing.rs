//! Xray-core's server side of the login, as `serverConn.handshake` runs it,
//! for tests that need a peer.
use super::{
    cfb8::Cfb8,
    padding,
    proto::{bytes, frame_into, invalid, string, varint, Conn, Fields},
    rsa, XmcProfile,
};
use rand::RngCore;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) fn profile(username: &str, seed: u8) -> XmcProfile {
    XmcProfile {
        username: username.to_owned(),
        uuid: [seed; 16],
        textures_value: format!("textures-of-{username}"),
        textures_signature: format!("signature-of-{username}"),
    }
}

/// What the client's handshake and Login Start said.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) version: i32,
    pub(crate) address: Vec<u8>,
    pub(crate) port: u16,
    pub(crate) next_state: i32,
    pub(crate) username: Vec<u8>,
    pub(crate) uuid: [u8; 16],
}

pub(crate) struct Server {
    /// The password it checks.
    pub(crate) password: String,
    /// The password whose key it sends, which Xray's server derives from its
    /// own password.
    pub(crate) key_password: String,
    pub(crate) profiles: Vec<XmcProfile>,
    /// A profile it confirms instead of the client's.
    pub(crate) confirm: Option<XmcProfile>,
}

impl Server {
    pub(crate) fn new(password: &str, profiles: Vec<XmcProfile>) -> Self {
        Self {
            password: password.to_owned(),
            key_password: password.to_owned(),
            profiles,
            confirm: None,
        }
    }

    async fn disconnect<S: AsyncRead + AsyncWrite + Unpin>(
        conn: &mut Conn<S>,
        reason: &str,
    ) -> io::Result<Seen> {
        let mut data = Vec::new();
        string(&mut data, reason);
        conn.write_packet(0x00, &data).await?;
        Err(io::Error::new(io::ErrorKind::PermissionDenied, reason))
    }

    /// The login and the startup padding, ciphers on at the end.
    pub(crate) async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut Conn<S>,
    ) -> io::Result<Seen> {
        let (id, handshake) = conn.read_packet().await?;
        let (id2, login_start) = conn.read_packet().await?;
        if id != 0 || id2 != 0 {
            return Err(invalid("bad handshake or login start packet id"));
        }
        let mut fields = Fields(&handshake);
        let (version, address, port, next_state) = (
            fields.varint()?,
            fields.string()?.to_vec(),
            fields.ushort()?,
            fields.varint()?,
        );
        let mut fields = Fields(&login_start);
        let (username, uuid) = (fields.string()?.to_vec(), fields.uuid()?);
        let seen = Seen {
            version,
            address,
            port,
            next_state,
            username,
            uuid,
        };

        let key = rsa::derived_public_key(&self.key_password);
        let mut token = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut token);
        let mut request = Vec::new();
        string(&mut request, "");
        bytes(&mut request, &key.pkix);
        bytes(&mut request, &token);
        request.push(1); // shouldAuthenticate, which the client skips.
        conn.write_packet(0x01, &request).await?;

        let (id, response) = conn.read_packet().await?;
        if id != 0x01 {
            return Err(invalid("bad encrypt response packet id"));
        }
        let mut fields = Fields(&response);
        let private = rsa::derived_private_key(&self.key_password);
        let secret: [u8; 16] = private
            .decrypt(fields.bytes()?)
            .and_then(|secret| secret.try_into().ok())
            .ok_or_else(|| invalid("bad shared secret"))?;
        let token_and_password = private
            .decrypt(fields.bytes()?)
            .ok_or_else(|| invalid("bad verify token"))?;
        if token_and_password.len() < 4 || token_and_password[..4] != token {
            return Err(invalid("verify token mismatch"));
        }
        conn.read_cipher = Some(Cfb8::new(&secret, true));
        conn.write_cipher = Some(Cfb8::new(&secret, false));
        if token_and_password[4..] != *self.password.as_bytes() {
            return Self::disconnect(
                conn,
                r#"{"type":"translatable","translate":"multiplayer.disconnect.authservers_down"}"#,
            )
            .await;
        }
        let Some(found) = self
            .profiles
            .iter()
            .find(|profile| profile.username.as_bytes() == seen.username && profile.uuid == uuid)
        else {
            return Self::disconnect(
                conn,
                r#"{"text":"You are not white-listed on this server!"}"#,
            )
            .await;
        };
        let confirmed = self.confirm.as_ref().unwrap_or(found);
        let mut success = confirmed.uuid.to_vec();
        string(&mut success, &confirmed.username);
        varint(&mut success, 1);
        string(&mut success, "textures");
        string(&mut success, &confirmed.textures_value);
        success.push(1);
        string(&mut success, &confirmed.textures_signature);
        conn.write_packet(0x02, &success).await?;

        // `readPacketWithLength`: Login Acknowledged, empty.
        let (length, header) = conn.read_varint().await?;
        let mut body = vec![0u8; length as usize];
        conn.read_exact(&mut body).await?;
        if body != [0x03] {
            return Err(invalid("bad login acknowledged packet"));
        }
        padding::run(conn, &padding::schedule(), false, header + body.len()).await?;
        Ok(seen)
    }
}

/// One frame as the server writes it after the login.
pub(crate) fn server_frame(id: i32, channel: Option<&str>, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::new();
    if let Some(channel) = channel {
        string(&mut data, channel);
    }
    data.extend_from_slice(payload);
    let mut out = Vec::new();
    frame_into(&mut out, id, data.len(), |out| out.extend_from_slice(&data)).unwrap();
    out
}
