//! Slot frames, rings and whole sessions in slots over a store in memory,
//! both ends in one process, as Xray-core's `slots_test.go` runs them.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use super::params::Params;
use super::slots::memory::MemorySlots;
use super::slots::{
    crc32, make_ring, Ring, SlotFrame, SlotStore, SlotTable, SLOT_END, SLOT_ERR, SLOT_INLINE,
    SLOT_INLINE_LIMIT, SLOT_MEDIA,
};
use super::stream::XdriveStream;
use super::XdriveTuning;

fn params(concurrency: u32) -> Params {
    Params::from_tuning(&XdriveTuning {
        flush_interval_ms: 5,
        poll_interval_ms: 5,
        max_poll_interval_ms: 20,
        eager_window_ms: 2000,
        concurrency,
        ..XdriveTuning::default()
    })
}

#[test]
fn crc_is_ieee() {
    assert_eq!(crc32(b""), 0);
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn frames_round_trip_and_refuse_what_is_no_frame() {
    let data = Bytes::from_static(b"segment");
    let inline = SlotFrame::new(7, SLOT_INLINE, &data);
    let decoded = SlotFrame::decode(&inline.encode()).unwrap();
    assert_eq!(decoded, inline);
    assert_eq!(decoded.data, data);
    // A media frame carries the size and checksum, not the bytes.
    let media = SlotFrame::new(8, SLOT_MEDIA, &data);
    let decoded = SlotFrame::decode(&media.encode()).unwrap();
    assert!(decoded.data.is_empty() && decoded.holds(&data) && !decoded.holds(b"other"));
    assert_eq!(
        SlotFrame::new(9, SLOT_END, &Bytes::new()).encode().len() % 4,
        0
    );
    assert!(SlotFrame::decode("not base64!").is_none());
    assert!(SlotFrame::decode("WERSVlNMMDE=").is_none(), "too short");
    let mut wrong = inline.clone();
    wrong.crc ^= 1;
    assert!(
        SlotFrame::decode(&wrong.encode()).is_none(),
        "an inline segment that is not what it says"
    );
    let mut magic = base64_decode(&inline.encode());
    magic[0] = b'Y';
    assert!(SlotFrame::decode(&base64_encode(&magic)).is_none());
    // A negative number is a large unsigned one on the wire, as in Go.
    let negative = SlotFrame::new(-1, SLOT_END, &Bytes::new());
    assert_eq!(&base64_decode(&negative.encode())[8..16], &[0xff; 8]);
}

fn base64_decode(text: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap()
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[test]
fn rings_are_spelled_as_go_marshals_them() {
    let ring = Ring {
        up: SlotTable {
            slots: vec!["a".to_owned(), "b\"<".to_owned()],
            watermark: "w1".to_owned(),
        },
        down: SlotTable {
            slots: vec!["c".to_owned()],
            watermark: "w2".to_owned(),
        },
        first: None,
    };
    let json = ring.to_json();
    assert_eq!(
        json,
        r#"{"u":{"s":["a","b\"\u003c"],"w":"w1"},"d":{"s":["c"],"w":"w2"}}"#
    );
    assert_eq!(Ring::from_json(json.as_bytes()), Some(ring.clone()));
    // Since v26.11.9 a client may announce its first segment with the ring,
    // as standard base64 after the tables; an empty one is left out.
    let with_first = Ring {
        first: Some(Bytes::from_static(b"\x00hi\xff")),
        ..ring.clone()
    };
    let json = with_first.to_json();
    assert_eq!(
        json,
        r#"{"u":{"s":["a","b\"\u003c"],"w":"w1"},"d":{"s":["c"],"w":"w2"},"first":"AGhp/w=="}"#
    );
    assert_eq!(Ring::from_json(json.as_bytes()), Some(with_first));
    let empty = Ring {
        first: Some(Bytes::new()),
        ..ring.clone()
    };
    assert_eq!(empty.to_json(), ring.to_json());
    assert!(Ring::from_json(br#"{"U":{"S":["a"],"W":"w"},"D":{"s":["c"],"w":"x"}}"#).is_some());
    assert!(Ring::from_json(br#"{"u":{"s":[],"w":"w"},"d":{"s":["c"],"w":"x"}}"#).is_none());
    assert!(Ring::from_json(br#"{"u":{"s":["a"],"w":""},"d":{"s":["c"],"w":"x"}}"#).is_none());
    assert!(Ring::from_json(b"").is_none());
}

#[tokio::test]
async fn rings_are_as_deep_as_the_concurrency() {
    // Since v26.11.9 the depth follows the concurrency up to its cap of 256.
    for (concurrency, depth) in [(1, 2), (2, 2), (8, 8), (100, 100), (1000, 256)] {
        let store = Arc::new(MemorySlots::default());
        let dyn_store: Arc<dyn SlotStore> = store.clone();
        let ring = make_ring(&dyn_store, "abc", &params(concurrency))
            .await
            .unwrap();
        assert_eq!((ring.up.slots.len(), ring.down.slots.len()), (depth, depth));
        let names = store.names.lock().unwrap().clone();
        assert_eq!(names[&ring.up.slots[1]], "streams/abc/c2s/s1");
        assert_eq!(names[&ring.down.watermark], "streams/abc/s2c/w");
        assert_eq!(names.len(), 2 * depth + 2);
    }
}

/// Both ends of a session over one store: the client writes up and reads
/// down, the server the other way.
async fn session(concurrency: u32) -> (Arc<MemorySlots>, XdriveStream, XdriveStream, Ring) {
    let store = Arc::new(MemorySlots::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(concurrency);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    let client = XdriveStream::slots(
        Arc::clone(&dyn_store),
        ring.up.clone(),
        ring.down.clone(),
        p,
    );
    let server = XdriveStream::slots(dyn_store, ring.down.clone(), ring.up.clone(), p);
    (store, client, server, ring)
}

async fn read_exactly(stream: &mut XdriveStream, size: usize) -> Vec<u8> {
    let mut got = vec![0; size];
    timeout(Duration::from_secs(20), stream.read_exact(&mut got))
        .await
        .expect("the bytes arrive")
        .unwrap();
    got
}

#[tokio::test]
async fn sessions_carry_bytes_both_ways_and_end() {
    let (store, mut client, mut server, ring) = session(2).await;
    client.write_all(b"hello").await.unwrap();
    assert_eq!(read_exactly(&mut server, 5).await, b"hello");
    server.write_all(b"world").await.unwrap();
    assert_eq!(read_exactly(&mut client, 5).await, b"world");
    // More than a lap of the two slots, large enough for media frames and a
    // burst at full size.
    let big: Vec<u8> = (0..300_000u32).map(|n| (n % 251) as u8).collect();
    client.write_all(&big).await.unwrap();
    assert_eq!(read_exactly(&mut server, big.len()).await, big);
    client.shutdown().await.unwrap();
    let mut rest = Vec::new();
    timeout(Duration::from_secs(20), server.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty());
    let sets = store.sets.lock().unwrap().clone();
    let frames: Vec<SlotFrame> = sets
        .iter()
        .filter(|(id, _, _)| ring.up.slots.contains(id))
        .filter_map(|(_, description, _)| SlotFrame::decode(description))
        .collect();
    assert!(
        frames.iter().any(|f| f.mode == SLOT_MEDIA),
        "large segments go in bodies"
    );
    assert!(frames
        .iter()
        .all(|f| f.mode != SLOT_MEDIA || f.size as usize > SLOT_INLINE_LIMIT));
    assert_eq!(frames.last().unwrap().mode, SLOT_END);
    // Media frames went with their body in the same request.
    assert!(sets
        .iter()
        .filter(|(_, d, _)| SlotFrame::decode(d).is_some_and(|f| f.mode == SLOT_MEDIA))
        .all(|(_, _, body)| *body));
    // The reader's watermark names the last segment it took: "hello" was
    // 0 and the burst went at once as 1.
    let watermark = store.slots.lock().unwrap()[&ring.up.watermark].0.clone();
    assert_eq!(watermark, "1");
}

#[tokio::test]
async fn a_slot_waits_for_its_reader_before_a_lap() {
    let store = Arc::new(MemorySlots::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(2);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    // A writer with nobody reading: two segments fill the ring, the third
    // waits for a watermark that never comes.
    let mut client = XdriveStream::slots(
        Arc::clone(&dyn_store),
        ring.up.clone(),
        ring.down.clone(),
        p,
    );
    for chunk in [vec![1u8; 100], vec![2; 100], vec![3; 100]] {
        client.write_all(&chunk).await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let written: Vec<i64> = store
        .sets
        .lock()
        .unwrap()
        .iter()
        .filter_map(|(_, d, _)| SlotFrame::decode(d).map(|f| f.seq))
        .collect();
    assert_eq!(written, [0, 1]);
    // Once the reader says it took the first, the third goes into its slot.
    store.set_slot(&ring.up.watermark, "0", None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(600)).await;
    let slot0 = store.slots.lock().unwrap()[&ring.up.slots[0]].0.clone();
    assert_eq!(SlotFrame::decode(&slot0).unwrap().seq, 2);
    drop(client);
}

#[tokio::test]
async fn a_segment_the_writer_cannot_store_fails_the_reader() {
    let (store, mut client, mut server, ring) = session(2).await;
    *store.fail_set.lock().unwrap() = Some(ring.up.slots[0].clone());
    client.write_all(b"lost").await.unwrap();
    let mut buf = [0u8; 8];
    let read = timeout(Duration::from_secs(20), server.read(&mut buf))
        .await
        .unwrap();
    let error = read.unwrap_err().to_string();
    assert!(
        error.contains("the peer could not store segment 0"),
        "{error}"
    );
    // The refused segment left a failure mark in its slot.
    let slot0 = store.slots.lock().unwrap()[&ring.up.slots[0]].0.clone();
    assert_eq!(SlotFrame::decode(&slot0).unwrap().mode, SLOT_ERR);
    // The writer reports it too.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(client.write_all(b"more").await.is_err());
}

fn bodies(store: &MemorySlots, ring: &Ring) -> usize {
    store
        .sets
        .lock()
        .unwrap()
        .iter()
        .filter(|(id, _, body)| *body && ring.up.slots.contains(id))
        .count()
}

/// `TestSlotBurstSplitsInline`, `TestSlotLargeBurstInline` and
/// `TestSlotBurstInlineWaves`: a burst that twice the write slots take in
/// inline segments goes inline, segment by segment; a larger one does not.
#[tokio::test]
async fn bursts_the_write_slots_take_go_inline() {
    for (concurrency, size, media) in [
        (8, 90 << 10, false),
        (16, 10 * SLOT_INLINE_LIMIT, false),
        (16, 20 * SLOT_INLINE_LIMIT, false),
        (16, 30 * SLOT_INLINE_LIMIT, true),
    ] {
        let (store, mut client, mut server, ring) = session(concurrency).await;
        let payload: Vec<u8> = (0..size).map(|i| (i * 7 + 3) as u8).collect();
        let writer = tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            client
        });
        let got = read_exactly(&mut server, size).await;
        assert!(got.iter().enumerate().all(|(i, b)| *b == (i * 7 + 3) as u8));
        let _client = writer.await.unwrap();
        assert_eq!(
            bodies(&store, &ring) > 0,
            media,
            "{size} bytes over {concurrency} slots"
        );
    }
}

/// A store that counts the slot writes under way at once.
#[derive(Debug, Default)]
struct Counting {
    inner: MemorySlots,
    now: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl SlotStore for Counting {
    async fn make_slot(&self, name: &str) -> Result<String, super::storage::StorageError> {
        self.inner.make_slot(name).await
    }
    async fn set_slot(
        &self,
        id: &str,
        description: &str,
        body: Option<Bytes>,
    ) -> Result<(), super::storage::StorageError> {
        use std::sync::atomic::Ordering;
        let now = self.now.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(5)).await;
        let set = self.inner.set_slot(id, description, body).await;
        self.now.fetch_sub(1, Ordering::SeqCst);
        set
    }
    async fn read_description(&self, id: &str) -> Result<String, super::storage::StorageError> {
        self.inner.read_description(id).await
    }
    async fn read_body(&self, id: &str) -> Result<Bytes, super::storage::StorageError> {
        self.inner.read_body(id).await
    }
}

/// `TestSlotWriteInflightCap`: a deep ring still has at most twelve
/// segments on their way.
#[tokio::test]
async fn at_most_twelve_segments_are_written_at_once() {
    let store = Arc::new(Counting::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(48);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    let mut client = XdriveStream::slots(
        Arc::clone(&dyn_store),
        ring.up.clone(),
        ring.down.clone(),
        p,
    );
    let mut server = XdriveStream::slots(dyn_store, ring.down.clone(), ring.up.clone(), p);
    let size = 60 * SLOT_INLINE_LIMIT;
    let writer = tokio::spawn(async move {
        for _ in 0..60 {
            client.write_all(&[9; SLOT_INLINE_LIMIT]).await.unwrap();
        }
        client
    });
    assert_eq!(read_exactly(&mut server, size).await.len(), size);
    let _client = writer.await.unwrap();
    let peak = store.peak.load(std::sync::atomic::Ordering::SeqCst);
    // The reader's watermark writes count too: at most one at a time.
    assert!(peak <= 12 + 1, "{peak} slot writes at once");
    assert!(peak > 2, "the writes overlapped: {peak}");
}

/// The first segment reaches the announcement as it is cut, and still goes
/// to slot 0 for a server that does not read it there.
#[tokio::test]
async fn the_first_segment_is_handed_to_the_announcement() {
    let store = Arc::new(MemorySlots::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(2);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    let (mut client, announcer) = XdriveStream::slots_announced(
        Arc::clone(&dyn_store),
        ring.up.clone(),
        ring.down.clone(),
        p,
    );
    client.write_all(b"first bytes").await.unwrap();
    let first = timeout(Duration::from_secs(5), announcer.first)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(first.as_ref(), b"first bytes");
    let mut server = XdriveStream::slots(dyn_store, ring.down.clone(), ring.up.clone(), p);
    assert_eq!(read_exactly(&mut server, 11).await, b"first bytes");
    let slot0 = store.slots.lock().unwrap()[&ring.up.slots[0]].0.clone();
    assert_eq!(SlotFrame::decode(&slot0).unwrap().seq, 0);
}

/// An announcement that failed fails the session's reads and writes.
#[tokio::test]
async fn a_failed_announcement_fails_the_session() {
    let store = Arc::new(MemorySlots::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(2);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    let (mut client, announcer) =
        XdriveStream::slots_announced(dyn_store, ring.up.clone(), ring.down.clone(), p);
    announcer.fail("failed to announce session s > refused".to_owned());
    let mut buf = [0; 8];
    let read = timeout(Duration::from_secs(5), client.read(&mut buf))
        .await
        .unwrap();
    assert!(read
        .unwrap_err()
        .to_string()
        .contains("failed to announce session s"));
    assert!(client.write_all(b"x").await.is_err());
}

/// A slot whose description does not decode fails the session after a
/// minute; an empty one is idle and does not.
#[tokio::test(start_paused = true)]
async fn an_invalid_frame_fails_after_a_minute_and_an_empty_slot_never() {
    for (description, fails) in [("not a frame", true), ("", false)] {
        let store = Arc::new(MemorySlots::default());
        let dyn_store: Arc<dyn SlotStore> = store.clone();
        let p = params(2);
        let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
        dyn_store
            .set_slot(&ring.up.slots[0], description, None)
            .await
            .unwrap();
        let mut server = XdriveStream::slots(dyn_store, ring.down.clone(), ring.up.clone(), p);
        let mut buf = [0; 8];
        let read = timeout(Duration::from_secs(90), server.read(&mut buf)).await;
        match (read, fails) {
            (Ok(Err(error)), true) => {
                assert!(
                    error.to_string().contains("holds an invalid frame"),
                    "{error}"
                )
            }
            (Err(_), false) => {}
            (other, _) => panic!("{description:?}: {other:?}"),
        }
    }
}

/// A store whose first body read of each slot never answers.
#[derive(Debug, Default)]
struct SlowBodies {
    inner: MemorySlots,
    reads: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl SlotStore for SlowBodies {
    async fn make_slot(&self, name: &str) -> Result<String, super::storage::StorageError> {
        self.inner.make_slot(name).await
    }
    async fn set_slot(
        &self,
        id: &str,
        description: &str,
        body: Option<Bytes>,
    ) -> Result<(), super::storage::StorageError> {
        self.inner.set_slot(id, description, body).await
    }
    async fn read_description(&self, id: &str) -> Result<String, super::storage::StorageError> {
        self.inner.read_description(id).await
    }
    async fn read_body(&self, id: &str) -> Result<Bytes, super::storage::StorageError> {
        if self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            std::future::pending::<()>().await;
        }
        self.inner.read_body(id).await
    }
}

/// `TestSlotBodyHedge`: a body read that has not answered after two seconds
/// gets a second request, which answers.
#[tokio::test(start_paused = true)]
async fn a_slow_body_read_is_hedged() {
    let store = Arc::new(SlowBodies::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(2);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    let body = Bytes::from(vec![5u8; 40 << 10]);
    let frame = SlotFrame::new(0, SLOT_MEDIA, &body);
    dyn_store
        .set_slot(&ring.up.slots[0], &frame.encode(), Some(body.clone()))
        .await
        .unwrap();
    let mut server = XdriveStream::slots(dyn_store, ring.down.clone(), ring.up.clone(), p);
    let started = tokio::time::Instant::now();
    assert_eq!(read_exactly(&mut server, body.len()).await, body);
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(store.reads.load(std::sync::atomic::Ordering::SeqCst), 2);
}

/// A slot whose body never checks out against its frame fails the session
/// after a minute.
#[tokio::test(start_paused = true)]
async fn a_body_that_never_checks_out_fails_after_a_minute() {
    let store = Arc::new(MemorySlots::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(2);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    let frame = SlotFrame::new(0, SLOT_MEDIA, &Bytes::from(vec![1u8; 20 << 10]));
    dyn_store
        .set_slot(
            &ring.up.slots[0],
            &frame.encode(),
            Some(Bytes::from(vec![2u8; 20 << 10])),
        )
        .await
        .unwrap();
    let mut server = XdriveStream::slots(dyn_store, ring.down.clone(), ring.up.clone(), p);
    let mut buf = [0; 8];
    let error = timeout(Duration::from_secs(90), server.read(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("has no usable body"), "{error}");
}

#[tokio::test]
async fn fourteen_kib_go_inline_and_a_burst_at_once_as_media() {
    let (store, mut client, mut server, ring) = session(2).await;
    // A write of 14 KiB is one inline segment; one of more than four times
    // that goes at once, in the body.
    for size in [14 << 10, 4 * (14 << 10) + 1] {
        client.write_all(&vec![1u8; size]).await.unwrap();
        assert_eq!(read_exactly(&mut server, size).await.len(), size);
    }
    let modes: Vec<(u32, u8)> = store
        .sets
        .lock()
        .unwrap()
        .iter()
        .filter(|(id, _, _)| ring.up.slots.contains(id))
        .filter_map(|(_, d, _)| SlotFrame::decode(d).map(|f| (f.size, f.mode)))
        .collect();
    assert_eq!(
        modes,
        [(14 << 10, SLOT_INLINE), (4 * (14 << 10) + 1, SLOT_MEDIA)]
    );
}

#[tokio::test]
async fn a_media_frame_waits_for_its_body() {
    // The description says segment 0 is in the body, but the body read
    // right after is still an old one: the reader asks again.
    let store = Arc::new(MemorySlots::default());
    let dyn_store: Arc<dyn SlotStore> = store.clone();
    let p = params(2);
    let ring = make_ring(&dyn_store, "s", &p).await.unwrap();
    let fresh = Bytes::from(vec![5u8; 20_000]);
    let frame = SlotFrame::new(0, SLOT_MEDIA, &fresh);
    dyn_store
        .set_slot(
            &ring.up.slots[0],
            &frame.encode(),
            Some(Bytes::from_static(b"stale")),
        )
        .await
        .unwrap();
    let mut server = XdriveStream::slots(
        Arc::clone(&dyn_store),
        ring.down.clone(),
        ring.up.clone(),
        p,
    );
    let mut buf = [0u8; 16];
    assert!(timeout(Duration::from_millis(400), server.read(&mut buf))
        .await
        .is_err());
    dyn_store
        .set_slot(&ring.up.slots[0], &frame.encode(), Some(fresh.clone()))
        .await
        .unwrap();
    assert_eq!(read_exactly(&mut server, fresh.len()).await, fresh.to_vec());
}
