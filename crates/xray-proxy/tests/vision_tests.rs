use bytes::BytesMut;
use std::collections::HashSet;
use xray_proxy::vless::{
    unpad_vision_block, VisionCommand, VisionError, VisionPadding, DEFAULT_VISION_SEED,
};

#[test]
fn vision_padding_round_trips_user_uuid_once() {
    let user = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut padding = VisionPadding::new(user, [900, 500, 900, 256]);
    let payload = BytesMut::from(&b"hello"[..]);

    let padded = padding
        .pad(payload.clone(), VisionCommand::Continue, 3)
        .unwrap();
    assert_eq!(&padded[..16], &user);

    let unpadded = unpad_vision_block(&padded, &user).unwrap();
    assert_eq!(unpadded.payload, payload);
    assert_eq!(unpadded.command, VisionCommand::Continue);

    let second = padding
        .pad(BytesMut::from(&b"world"[..]), VisionCommand::End, 0)
        .unwrap();
    assert_ne!(&second[..16], &user);
}

#[test]
fn vision_padding_uses_seed_padding_when_no_override() {
    let user = [7; 16];
    let mut padding = VisionPadding::new(user, DEFAULT_VISION_SEED);

    let padded = padding
        .pad(BytesMut::from(&b"hello"[..]), VisionCommand::Continue, 0)
        .unwrap();

    let padding_len = u16::from_be_bytes([padded[19], padded[20]]) as usize;
    assert!((895..=1394).contains(&padding_len));
    assert_eq!(padded.len(), 16 + 5 + 5 + padding_len);
}

#[test]
fn vision_padding_matches_xray_core_empty_header_camouflage_range() {
    let user = [7; 16];
    let mut observed = HashSet::new();

    for _ in 0..32 {
        let mut padding = VisionPadding::new(user, DEFAULT_VISION_SEED);
        let padded = padding
            .pad(BytesMut::new(), VisionCommand::Continue, 0)
            .unwrap();

        let padding_len = u16::from_be_bytes([padded[19], padded[20]]) as usize;
        assert!((900..=1399).contains(&padding_len));
        assert_eq!(padded.len(), 16 + 5 + padding_len);
        observed.insert(padding_len);
    }

    assert!(
        observed.len() > 1,
        "Xray-core long padding is random in the 900..=1399 range"
    );
}

#[test]
fn vision_padding_matches_xray_core_short_padding_range_when_long_padding_disabled() {
    let user = [7; 16];
    let payload = b"hello";
    let mut observed = HashSet::new();

    for _ in 0..32 {
        let mut padding = VisionPadding::new(user, DEFAULT_VISION_SEED);
        let mut padded = BytesMut::new();

        padding
            .pad_into_with_long_padding(payload, VisionCommand::Continue, false, 0, &mut padded)
            .unwrap();

        let padding_len = u16::from_be_bytes([padded[19], padded[20]]) as usize;
        assert!(padding_len <= 255);
        assert_eq!(padded.len(), 16 + 5 + payload.len() + padding_len);
        observed.insert(padding_len);
    }

    assert!(
        observed.len() > 1,
        "Xray-core short padding is random in the 0..=255 range"
    );
}

#[test]
fn vision_unpadding_accepts_block_without_user_uuid() {
    let user = [9; 16];
    let mut padding = VisionPadding::new(user, [0, 0, 0, 0]);
    let _first = padding
        .pad(BytesMut::from(&b"first"[..]), VisionCommand::Continue, 0)
        .unwrap();
    let second = padding
        .pad(BytesMut::from(&b"second"[..]), VisionCommand::End, 0)
        .unwrap();

    let unpadded = unpad_vision_block(&second, &user).unwrap();

    assert_eq!(unpadded.command, VisionCommand::End);
    assert_eq!(unpadded.payload, BytesMut::from(&b"second"[..]));
}

#[test]
fn vision_unpadding_accepts_long_block_without_user_uuid() {
    let user = [9; 16];
    let mut padding = VisionPadding::new(user, [0, 0, 0, 0]);
    let _first = padding
        .pad(BytesMut::from(&b"first"[..]), VisionCommand::Continue, 0)
        .unwrap();
    let payload = BytesMut::from(&b"this payload is longer than sixteen bytes"[..]);
    let second = padding.pad(payload.clone(), VisionCommand::End, 0).unwrap();

    let unpadded = unpad_vision_block(&second, &user).unwrap();

    assert_eq!(unpadded.command, VisionCommand::End);
    assert_eq!(unpadded.payload, payload);
}

#[test]
fn vision_unpadding_prefers_matching_user_uuid_over_ambiguous_header() {
    let user = [0, 0, 16, 0, 5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let mut padding = VisionPadding::new(user, [0, 0, 0, 0]);
    let padded = padding
        .pad(BytesMut::from(&b"hello"[..]), VisionCommand::Continue, 0)
        .unwrap();

    let unpadded = unpad_vision_block(&padded, &user).unwrap();

    assert_eq!(unpadded.command, VisionCommand::Continue);
    assert_eq!(unpadded.payload, BytesMut::from(&b"hello"[..]));
}

#[test]
fn vision_padding_accepts_max_u16_payload() {
    let user = [3; 16];
    let mut padding = VisionPadding::new(user, [0, 0, 0, 0]);
    let payload = BytesMut::from(vec![b'a'; u16::MAX as usize].as_slice());

    let padded = padding
        .pad(payload.clone(), VisionCommand::Continue, 0)
        .unwrap();
    let unpadded = unpad_vision_block(&padded, &user).unwrap();

    assert_eq!(unpadded.payload.len(), u16::MAX as usize);
    assert_eq!(unpadded.payload, payload);
}

#[test]
fn vision_padding_rejects_payload_larger_than_u16() {
    let user = [3; 16];
    let mut padding = VisionPadding::new(user, [0, 0, 0, 0]);
    let payload = BytesMut::from(vec![b'a'; u16::MAX as usize + 1].as_slice());

    let err = padding
        .pad(payload, VisionCommand::Continue, 0)
        .unwrap_err();

    assert_eq!(
        err,
        VisionError::PayloadTooLarge {
            len: u16::MAX as usize + 1
        }
    );
}

#[test]
fn vision_unpadding_rejects_unknown_command() {
    let user = [1; 16];
    let padded = [3, 0, 0, 0, 0];

    let err = unpad_vision_block(&padded, &user).unwrap_err();

    assert_eq!(err, VisionError::UnknownCommand(3));
}

#[test]
fn vision_unpadding_preserves_unknown_command_for_long_malformed_block() {
    let user = [1; 16];
    let padded = [9; 21];

    let err = unpad_vision_block(&padded, &user).unwrap_err();

    assert_eq!(err, VisionError::UnknownCommand(9));
}

#[test]
fn vision_unpadding_rejects_mismatched_user_uuid() {
    let user = [1; 16];
    let mut padded = BytesMut::from(&[2; 16][..]);
    padded.extend_from_slice(&[VisionCommand::Continue as u8, 0, 0, 0, 0]);

    let err = unpad_vision_block(&padded, &user).unwrap_err();

    assert_eq!(err, VisionError::UserMismatch);
}

#[test]
fn vision_unpadding_rejects_length_mismatch() {
    let user = [1; 16];
    let padded = [VisionCommand::Continue as u8, 0, 2, 0, 0, b'a'];

    let err = unpad_vision_block(&padded, &user).unwrap_err();

    assert_eq!(err, VisionError::LengthMismatch);
}

#[test]
fn vision_unpadding_rejects_short_block() {
    let user = [1; 16];
    let padded = [VisionCommand::Continue as u8, 0, 1, 0];

    let err = unpad_vision_block(&padded, &user).unwrap_err();

    assert_eq!(err, VisionError::ShortBlock);
}

#[test]
fn pad_into_appends_identical_frames_to_pad() {
    let user_id = [7u8; 16];
    let mut reference = VisionPadding::new(user_id, [900, 500, 900, 256]);
    let mut streaming = VisionPadding::new(user_id, [900, 500, 900, 256]);

    let mut expected = BytesMut::new();
    let mut actual = BytesMut::new();
    for payload in [&b"hello"[..], &b"world!"[..]] {
        let frame = reference
            .pad(BytesMut::from(payload), VisionCommand::Continue, 3)
            .unwrap();
        expected.extend_from_slice(&frame);
        streaming
            .pad_into(payload, VisionCommand::Continue, 3, &mut actual)
            .unwrap();
    }

    assert_eq!(actual, expected);
}
