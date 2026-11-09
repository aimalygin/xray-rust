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
