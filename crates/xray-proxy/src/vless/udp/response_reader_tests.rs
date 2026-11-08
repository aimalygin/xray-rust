use super::*;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use xray_routing::TargetAddr;

fn target() -> Target {
    Target::new(
        TargetAddr::Ip(IpAddr::from([192, 0, 2, 7])),
        5353,
        Network::Udp,
    )
}

/// A read dropped after it took a frame's head leaves the head for the next
/// read, as a `select!` that picks another branch drops it.
#[tokio::test]
async fn a_dropped_read_keeps_the_bytes_it_took() {
    let frame = encode_xudp_keep_packet(Some(&target()), &[0xa5; 4096]).unwrap();
    let (mut ours, mut theirs) = tokio::io::duplex(1 << 16);
    let mut responses = UdpResponseReader::default();
    // The head and the first data bytes, then a pause the read is dropped in.
    theirs.write_all(&frame[..40]).await.unwrap();
    let pending = tokio::time::timeout(
        Duration::from_millis(20),
        responses.read_xudp_packet(&mut ours),
    )
    .await;
    assert!(pending.is_err(), "nothing whole yet");
    theirs.write_all(&frame[40..]).await.unwrap();
    let packet = responses.read_xudp_packet(&mut ours).await.unwrap();
    assert_eq!(packet.source, Some(target()));
    assert_eq!(packet.payload.as_ref(), [0xa5; 4096]);

    // The same for length-prefixed packets.
    let frame = encode_udp_packet(&[1, 2, 3]).unwrap();
    theirs.write_all(&frame[..1]).await.unwrap();
    let pending = tokio::time::timeout(
        Duration::from_millis(20),
        responses.read_udp_packet(&mut ours),
    )
    .await;
    assert!(pending.is_err());
    theirs.write_all(&frame[1..]).await.unwrap();
    assert_eq!(
        responses.read_udp_packet(&mut ours).await.unwrap().as_ref(),
        [1, 2, 3]
    );
}

#[tokio::test]
async fn frames_in_one_read_come_out_one_at_a_time() {
    let wire = [
        encode_xudp_new_packet(&target(), b"first", [1; 8]).unwrap(),
        // No data: skipped.
        vec![0, 4, 0, 0, XUDP_CMD_KEEP, 0],
        // Empty data and a discard: skipped.
        encode_xudp_keep_packet(Some(&target()), b"").unwrap(),
        {
            let mut discard = encode_xudp_keep_packet(None, b"dropped").unwrap();
            discard[4] = XUDP_CMD_DISCARD;
            discard
        },
        encode_xudp_keep_packet(None, b"second").unwrap(),
    ]
    .concat();
    let (mut ours, mut theirs) = tokio::io::duplex(1 << 16);
    theirs.write_all(&wire).await.unwrap();
    drop(theirs);
    let mut responses = UdpResponseReader::default();
    let first = responses.read_xudp_packet(&mut ours).await.unwrap();
    assert_eq!(first.payload.as_ref(), b"first");
    let second = responses.read_xudp_packet(&mut ours).await.unwrap();
    assert_eq!(
        (second.source, second.payload.as_ref()),
        (None, &b"second"[..])
    );
    let end = responses.read_xudp_packet(&mut ours).await.unwrap_err();
    assert_eq!(end.kind(), io::ErrorKind::UnexpectedEof);
}

#[test]
fn malformed_frames_fail_as_the_one_shot_reader_fails() {
    assert!(
        decode_xudp_frame(&[0, 3, 0, 0, 2]).is_err(),
        "metadata under 4 bytes"
    );
    assert!(
        decode_xudp_frame(&[0, 4, 0, 0, 9, 1]).is_err(),
        "unknown command"
    );
    assert!(
        matches!(decode_xudp_frame(&[0, 4, 0, 0]), Ok(None)),
        "not whole"
    );
    assert!(decode_udp_packet(&[0, 2, 1]).is_none());
}
