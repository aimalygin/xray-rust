//! The control messages of Xray-core v26.10.31's VLESS reverse proxy
//! (`app/reverse/config.proto`). The portal sends them to the bridge over a
//! session of the reverse Mux.Cool connection, one per datagram: the state
//! it wants the tunnel in, padded with 1 to 64 random bytes.

use prost::Message;

/// The domain the portal's control session goes to, as `udp reverse:0`.
pub const CONTROL_DOMAIN: &str = "reverse";

#[derive(Clone, PartialEq, Message)]
struct Control {
    #[prost(int32, tag = "1")]
    state: i32,
    #[prost(bytes = "vec", tag = "99")]
    random: Vec<u8>,
}

/// `Control.State`: `ACTIVE` keeps the tunnel taking sessions; `DRAIN`, sent
/// once the portal has opened enough sessions on it, retires it. Any other
/// value leaves the tunnel inactive too, as it does in Xray-core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlState {
    Active,
    Drain,
    Other(i32),
}

impl ControlState {
    fn from_wire(state: i32) -> Self {
        match state {
            0 => Self::Active,
            1 => Self::Drain,
            other => Self::Other(other),
        }
    }

    fn to_wire(self) -> i32 {
        match self {
            Self::Active => 0,
            Self::Drain => 1,
            Self::Other(other) => other,
        }
    }

    /// Whether the tunnel keeps taking sessions.
    pub fn is_active(self) -> bool {
        self == Self::Active
    }
}

/// Reads one control message, as `proto.Unmarshal` does: unknown fields are
/// skipped and missing ones are zero.
pub fn decode_control(datagram: &[u8]) -> Result<ControlState, prost::DecodeError> {
    Control::decode(datagram).map(|control| ControlState::from_wire(control.state))
}

/// Writes a control message as Xray-core's portal marshals it.
pub fn encode_control(state: ControlState, random: &[u8]) -> Vec<u8> {
    Control {
        state: state.to_wire(),
        random: random.to_vec(),
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mux::{self, Frame, Status};
    use crate::vless::{encode_request_header, VlessCommand, VlessRequest};
    use serde_json::Value;
    use xray_routing::{Network, Target, TargetAddr};

    fn bytes(value: &Value) -> Vec<u8> {
        let text = value.as_str().unwrap();
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn endpoint(value: &Value) -> Option<Target> {
        if value.is_null() {
            return None;
        }
        let address = value["address"].as_str().unwrap();
        Some(Target::new(
            address
                .parse()
                .map_or_else(|_| TargetAddr::Domain(address.into()), TargetAddr::Ip),
            value["port"].as_u64().unwrap() as u16,
            if value["network"] == "tcp" {
                Network::Tcp
            } else {
                Network::Udp
            },
        ))
    }

    fn status(value: &Value) -> Status {
        match value.as_u64().unwrap() {
            1 => Status::New,
            2 => Status::Keep,
            3 => Status::End,
            4 => Status::KeepAlive,
            other => panic!("status {other}"),
        }
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../../tests/fixtures/reverse/vectors.json")).unwrap()
    }

    /// What Xray-core's portal writes reads back as what it was asked to
    /// write; tools/reverse-oracle records it.
    #[test]
    fn portal_frames_match_the_pinned_go_oracle() {
        for case in vectors()["portal"].as_array().unwrap() {
            let wire = bytes(&case["wire"]);
            let (frame, consumed) = mux::decode_reverse(&wire)
                .unwrap_or_else(|error| panic!("{}: {error}", case["name"]))
                .unwrap();
            assert_eq!(consumed, wire.len(), "{}", case["name"]);
            let payload = (!case["payload"].is_null()).then(|| bytes(&case["payload"]));
            assert_eq!(
                frame,
                mux::ReverseFrame {
                    frame: Frame {
                        session_id: case["session"].as_u64().unwrap() as u16,
                        status: status(&case["status"]),
                        error: case["error"].as_bool().unwrap(),
                        target: endpoint(&case["target"]),
                        global_id: None,
                        payload: payload.as_deref(),
                    },
                    source: endpoint(&case["source"]),
                    local: endpoint(&case["local"]),
                },
                "{}",
                case["name"]
            );
        }
    }

    /// The frames the bridge answers with are Xray-core's, byte for byte.
    #[test]
    fn bridge_frames_match_the_pinned_go_oracle() {
        for case in vectors()["bridge"].as_array().unwrap() {
            let payload = (!case["payload"].is_null()).then(|| bytes(&case["payload"]));
            let frame = Frame {
                session_id: case["session"].as_u64().unwrap() as u16,
                status: status(&case["status"]),
                error: case["error"].as_bool().unwrap(),
                target: endpoint(&case["target"]),
                global_id: None,
                payload: payload.as_deref(),
            };
            let wire = bytes(&case["wire"]);
            assert_eq!(mux::encode(&frame).unwrap(), wire, "{}", case["name"]);
            assert_eq!(
                mux::decode(&wire).unwrap(),
                Some((frame, wire.len())),
                "{}",
                case["name"]
            );
        }
    }

    #[test]
    fn control_messages_and_the_tunnel_request_match_the_pinned_go_oracle() {
        let vectors = vectors();
        for case in vectors["control"].as_array().unwrap() {
            let state = match case["state"].as_i64().unwrap() {
                0 => ControlState::Active,
                1 => ControlState::Drain,
                other => ControlState::Other(other as i32),
            };
            let wire = bytes(&case["wire"]);
            assert_eq!(decode_control(&wire), Ok(state));
            assert_eq!(encode_control(state, &bytes(&case["random"])), wire);
        }
        for case in vectors["request"].as_array().unwrap() {
            let flow = case["flow"].as_str().unwrap();
            let request = VlessRequest {
                user_id: uuid::Uuid::parse_str("27848739-7e62-4138-9fd3-098a63964b6b").unwrap(),
                command: VlessCommand::Reverse,
                target: Target::new(TargetAddr::Domain("v1.rvs.cool".into()), 0, Network::Tcp),
                flow: (!flow.is_empty()).then(|| flow.to_owned()),
            };
            assert_eq!(
                encode_request_header(&request).unwrap(),
                bytes(&case["wire"])
            );
        }
    }

    #[test]
    fn control_messages_round_trip_and_skip_unknown_fields() {
        for state in [
            ControlState::Active,
            ControlState::Drain,
            ControlState::Other(7),
            ControlState::Other(-1),
        ] {
            let wire = encode_control(state, &[0xaa; 17]);
            assert_eq!(decode_control(&wire), Ok(state));
        }
        // proto3 leaves a zero state out: only the padding is on the wire.
        assert_eq!(
            encode_control(ControlState::Active, &[1])[..],
            [0x9a, 0x06, 1, 1]
        );
        assert_eq!(decode_control(&[]), Ok(ControlState::Active));
        // An unknown varint field, then DRAIN.
        assert_eq!(decode_control(&[0x10, 5, 0x08, 1]), Ok(ControlState::Drain));
        assert!(decode_control(&[0x08]).is_err());
        assert!(ControlState::Active.is_active());
        assert!(!ControlState::Drain.is_active());
        assert!(!ControlState::Other(2).is_active());
    }
}
