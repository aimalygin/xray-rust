use super::*;
use crate::xmc::cfb8::Cfb8;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::ReadBuf;

/// `validatePaddingSchedule`, for the schedules this side builds.
fn validate(schedule: &[Turn], prefix: usize) {
    assert!(!schedule.is_empty());
    for (i, turn) in schedule.iter().enumerate() {
        for delay in [&turn.start_delay, &turn.chunk_delay].into_iter().flatten() {
            assert!(delay.start() <= delay.end(), "turn {i}");
        }
        if let Some(chunk) = &turn.write_chunk {
            assert!(chunk.start() <= chunk.end() && *chunk.end() <= MAX_CHUNK);
            assert!(turn.variants.is_empty(), "turn {i}");
        }
        let (min, max) = match &turn.length {
            Some(range) => {
                assert!(turn.variants.is_empty());
                assert!(*range.start() >= 1 && range.start() <= range.end());
                assert!(*range.end() <= MAX_TURN);
                (*range.start(), *range.end())
            }
            None => {
                assert!(!turn.variants.is_empty(), "turn {i}");
                let totals = turn.variants.iter().map(|variant| {
                    assert_eq!(variant.chunks.len(), variant.delays.len());
                    assert!(variant.chunks.iter().all(|c| (1..=MAX_CHUNK).contains(c)));
                    variant.chunks.iter().sum::<usize>()
                });
                let totals: Vec<usize> = totals.collect();
                (*totals.iter().min().unwrap(), *totals.iter().max().unwrap())
            }
        };
        if let Some(send) = &turn.send {
            assert!(turn.variants.is_empty());
            assert!(min <= *send.start() && send.start() <= send.end() && *send.end() <= max);
        }
        if i == 0 {
            assert!(turn.client_sends);
            assert!(min - prefix >= 1);
            for _ in 0..turn.variants.len().max(1) * 4 {
                turn.plan(prefix).unwrap();
            }
        } else {
            assert_ne!(turn.client_sends, schedule[i - 1].client_sends, "turn {i}");
        }
    }
}

#[test]
fn the_schedule_matches_the_captured_templates() {
    let schedule = schedule();
    assert_eq!(schedule.len(), STARTUP_TURNS + 33);
    for (i, turn) in schedule.iter().enumerate() {
        assert_eq!(turn.client_sends, i % 2 == 0, "turn {i}");
    }
    let lengths: [&[usize]; STARTUP_TURNS] = [
        &[44],
        &[72],
        &[25],
        &[41172],
        &[2],
        &[
            7464, 8267, 8790, 8153, 7375, 7347, 8184, 6633, 7670, 8241, 7857, 7254, 8407, 8283,
            6804, 8177, 8177, 7929, 8296, 8177,
        ],
    ];
    for (turn, want) in schedule.iter().zip(lengths) {
        let got: Vec<usize> = turn
            .variants
            .iter()
            .map(|variant| variant.chunks.iter().sum())
            .collect();
        assert_eq!(got, want);
        assert_eq!(turn.length, None);
    }
    let starts = [None, Some(ms(0, 20)), Some(ms(2, 22)), Some(ms(20, 50))];
    for (turn, start) in schedule.iter().zip(starts) {
        assert_eq!(turn.start_delay, start);
    }
    assert_eq!(schedule[4].start_delay, Some(ms(10, 35)));
    assert_eq!(schedule[5].start_delay, Some(ms(35, 50)));
    assert_eq!(schedule[3].variants[0].chunks.len(), 30);
    assert!(schedule[5]
        .variants
        .iter()
        .all(|variant| variant.chunks[0] == 4941));
    for (i, turn) in schedule[STARTUP_TURNS..].iter().enumerate() {
        assert_eq!(turn.length, Some(PLAY_JOIN[i].0..=PLAY_JOIN[i].1));
        assert!(turn.variants.is_empty());
        if turn.client_sends {
            assert_eq!(turn.start_delay, Some(ms(1, 30)));
            assert_eq!(turn.chunk_delay, None);
            assert_eq!(turn.write_chunk, Some(1024..=1024));
        } else {
            assert_eq!(turn.start_delay, Some(ms(1, 45)));
            assert_eq!(turn.chunk_delay, Some(ms(1, 4)));
            assert_eq!(turn.write_chunk, Some(32 * 1024..=48 * 1024));
        }
    }
    validate(&schedule, 2);
}

#[test]
fn variants_pause_where_the_captures_paused() {
    let schedule = schedule();
    let registry = &schedule[3].variants[0];
    for (i, delay) in registry.delays.iter().enumerate() {
        let want = match i {
            28 => Some(ms(1, 4)),
            29 => Some(ms(44, 61)),
            _ => None,
        };
        assert_eq!(*delay, want, "registry chunk {i}");
    }
    for variant in &schedule[5].variants {
        let n = variant.chunks.len();
        for (i, delay) in variant.delays.iter().enumerate() {
            let want = if i == n - 1 {
                Some(ms(9, 20))
            } else if i == n / 2 {
                Some(ms(1, 5))
            } else {
                None
            };
            assert_eq!(*delay, want);
        }
    }
    for turn in &schedule[..3] {
        assert!(turn.variants[0].delays.iter().all(Option::is_none));
    }
}

#[test]
fn one_play_turn_carries_the_burst() {
    assert_eq!(
        (0..20).map(burst_slot).collect::<Vec<_>>(),
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2]
    );
    for selected in 0..3 {
        let schedule = with_burst(selected);
        validate(&schedule, 2);
        let sends: Vec<_> = schedule
            .iter()
            .enumerate()
            .filter_map(|(i, turn)| turn.send.clone().map(|send| (i - STARTUP_TURNS, send)))
            .collect();
        let mut want = vec![(0, 6..=44), (2, 6..=45), (10, 2..=19)];
        want[selected].1 = [877..=883, 884..=887, 851..=851][selected].clone();
        assert_eq!(sends, want);
    }
    for _ in 0..20 {
        validate(&client_schedule(), 2);
    }
}

#[test]
fn a_turn_sends_within_its_send_range() {
    let mut turn = client_play(6, 883);
    turn.send = Some(877..=883);
    for _ in 0..100 {
        let (record, chunks, delays) = turn.plan(0).unwrap();
        assert!((877..=883).contains(&record));
        assert_eq!(chunks, [record]);
        assert_eq!(delays, [None]);
    }
    turn.send = None;
    let records: std::collections::HashSet<usize> =
        (0..200).map(|_| turn.plan(0).unwrap().0).collect();
    assert!(records.iter().all(|record| (6..=883).contains(record)));
    assert!(records.len() > 20, "lengths are drawn: {records:?}");
}

#[test]
fn generated_chunks_split_the_record() {
    let turn = Turn {
        length: Some(2000..=2000),
        ..client_play(1, 1)
    };
    let (record, chunks, delays) = turn.plan(0).unwrap();
    assert_eq!(
        (record, chunks, delays),
        (2000, vec![1024, 976], vec![None, None])
    );

    let server = server_play(100_000, 100_000);
    let (record, chunks, delays) = server.plan(0).unwrap();
    assert_eq!(record, 100_000);
    assert_eq!(chunks.iter().sum::<usize>(), 100_000);
    let chunk = chunks[0];
    assert!((32 * 1024..=48 * 1024).contains(&chunk));
    assert!(chunks[..chunks.len() - 1].iter().all(|c| *c == chunk));
    assert_eq!(delays[0], None);
    assert!(delays[1..].iter().all(|delay| *delay == Some(ms(1, 4))));

    // A prefix the turn cannot hold is refused.
    assert!(client_play(2, 2).plan(2).is_err());
    assert_eq!(client_play(3, 3).plan(2).unwrap().0, 1);
}

#[test]
fn a_prefix_takes_whole_chunks() {
    let turn = variants(true, vec![chunks(&[2, 26, 16])], None);
    assert_eq!(turn.plan(2).unwrap(), (42, vec![26, 16], vec![None, None]));
    assert_eq!(turn.plan(28).unwrap(), (16, vec![16], vec![None]));
    assert_eq!(turn.plan(0).unwrap().0, 44);
    assert!(turn.plan(3).is_err(), "splits a chunk");
    assert!(turn.plan(44).is_err(), "leaves nothing");
}

/// A carrier that records each write.
#[derive(Default)]
struct Recorder {
    writes: Vec<Vec<u8>>,
}

impl AsyncRead for Recorder {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Recorder {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.writes.push(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn writes_keep_the_captured_boundaries() {
    let mut conn = Conn::new(Recorder::default());
    variants(true, vec![chunks(&[2, 26, 16])], None)
        .write(&mut conn, 2)
        .await
        .unwrap();
    let turn = Turn {
        length: Some(2000..=2000),
        ..client_play(1, 1)
    };
    turn.write(&mut conn, 0).await.unwrap();
    let (recorder, ..) = conn.into_parts();
    let sizes: Vec<usize> = recorder.writes.iter().map(Vec::len).collect();
    assert_eq!(sizes, [26, 16, 1024, 976]);
    // The record's length leads its first chunk; the rest is zeros.
    assert_eq!(recorder.writes[0][0], 42);
    assert_eq!(&recorder.writes[2][..2], [0xd0, 0x0f]);
    let zeros = recorder.writes.iter().enumerate().flat_map(|(i, write)| {
        let skip = [1, 0, 2, 0][i];
        write[skip..].iter().copied()
    });
    assert!(zeros.into_iter().all(|byte| byte == 0));
}

async fn read_turn(turn: &Turn, wire: &[u8]) -> io::Result<()> {
    let (mut ours, mut theirs) = tokio::io::duplex(1 << 16);
    tokio::io::AsyncWriteExt::write_all(&mut theirs, wire)
        .await
        .unwrap();
    drop(theirs);
    turn.read(&mut Conn::new(&mut ours), 0).await
}

#[tokio::test]
async fn reads_check_the_record() {
    let turn = client_play(3, 300);
    let record = |length: usize| {
        let mut wire = Vec::new();
        varint(&mut wire, length as i32);
        wire.resize(length, 0);
        wire
    };
    read_turn(&turn, &record(3)).await.unwrap();
    read_turn(&turn, &record(300)).await.unwrap();
    assert!(read_turn(&turn, &record(2)).await.is_err(), "too short");
    assert!(read_turn(&turn, &record(301)).await.is_err(), "too long");
    assert!(
        read_turn(&turn, &[0]).await.is_err(),
        "shorter than its header"
    );
    let mut non_canonical = vec![0x83, 0x00];
    non_canonical.resize(3, 0);
    assert!(read_turn(&turn, &non_canonical).await.is_err());
    let error = read_turn(&turn, &record(300)[..299]).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    let mut huge = Vec::new();
    varint(&mut huge, MAX_TURN as i32 + 1);
    let mut unbounded = client_play(1, 1);
    unbounded.length = Some(1..=usize::MAX);
    assert!(read_turn(&unbounded, &huge).await.is_err());

    let variant = variants(false, vec![chunks(&[26, 21, 25])], None);
    read_turn(&variant, &record(72)).await.unwrap();
    assert!(read_turn(&variant, &record(71)).await.is_err());
}

/// Both ends of the schedule over a CFB8 carrier, as after the login.
#[tokio::test(start_paused = true)]
async fn both_sides_run_the_schedule() {
    let secret = [9u8; 16];
    let (client, server) = tokio::io::duplex(1 << 20);
    let mut client = Conn::new(client);
    client.read_cipher = Some(Cfb8::new(&secret, true));
    client.write_cipher = Some(Cfb8::new(&secret, false));
    let mut server = Conn::new(server);
    server.read_cipher = Some(Cfb8::new(&secret, true));
    server.write_cipher = Some(Cfb8::new(&secret, false));
    let server = tokio::spawn(async move {
        run(&mut server, &schedule(), false, 2).await.unwrap();
        server
    });
    // On a paused clock a stalled schedule reaches the deadline at once.
    let schedule = client_schedule();
    tokio::time::timeout(
        Duration::from_secs(600),
        run(&mut client, &schedule, true, 2),
    )
    .await
    .expect("the schedule finishes")
    .unwrap();
    let server = server.await.unwrap();
    // Neither side reads past the last turn.
    let (_, rest, ..) = server.into_parts();
    assert!(rest.is_empty());
}
