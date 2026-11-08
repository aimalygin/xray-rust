//! The startup padding of Xray-core's xmc mask: turns that copy the
//! lengths and write boundaries of a Minecraft 26.1.2 login, with broad
//! random timing. Each side writes its turns as records, a varint length
//! and zeros, and reads the other side's, checking only the length.
use super::proto::{invalid, varint, Conn};
use rand::Rng;
use std::{io, ops::RangeInclusive, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

/// `paddingBufferLength`: the default write chunk and the read buffer.
const DEFAULT_CHUNK: usize = 16 * 1024;
const MAX_CHUNK: usize = 48 * 1024;
const MAX_TURN: usize = 8 * 1024 * 1024;

type Delay = RangeInclusive<Duration>;

const fn ms(min: u64, max: u64) -> Delay {
    Duration::from_millis(min)..=Duration::from_millis(max)
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Variant {
    pub(crate) chunks: Vec<usize>,
    /// The pause before each chunk, if any.
    pub(crate) delays: Vec<Option<Delay>>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Turn {
    pub(crate) client_sends: bool,
    /// The lengths a turn may have, when it has no variants.
    pub(crate) length: Option<RangeInclusive<usize>>,
    pub(crate) variants: Vec<Variant>,
    pub(crate) start_delay: Option<Delay>,
    pub(crate) chunk_delay: Option<Delay>,
    /// The write chunk length, drawn from the range.
    pub(crate) write_chunk: Option<RangeInclusive<usize>>,
    /// The narrower range this side sends within.
    pub(crate) send: Option<RangeInclusive<usize>>,
}

fn chunks(chunks: &[usize]) -> Variant {
    Variant {
        chunks: chunks.to_vec(),
        delays: vec![None; chunks.len()],
    }
}

/// `pacedPaddingVariant`.
fn paced(chunks: &[usize], pauses: &[(usize, Delay)]) -> Variant {
    let mut delays = vec![None; chunks.len()];
    for (chunk, delay) in pauses {
        delays[*chunk] = Some(delay.clone());
    }
    Variant {
        chunks: chunks.to_vec(),
        delays,
    }
}

fn variants(client_sends: bool, variants: Vec<Variant>, start: Option<Delay>) -> Turn {
    Turn {
        client_sends,
        length: None,
        variants,
        start_delay: start,
        chunk_delay: None,
        write_chunk: None,
        send: None,
    }
}

/// `playStartPaddingVariant`.
fn play_start(chunks: &[usize]) -> Variant {
    paced(
        chunks,
        &[(chunks.len() / 2, ms(1, 5)), (chunks.len() - 1, ms(9, 20))],
    )
}

/// `clientPlayPaddingTurn`.
fn client_play(min: usize, max: usize) -> Turn {
    Turn {
        client_sends: true,
        length: Some(min..=max),
        variants: Vec::new(),
        start_delay: Some(ms(1, 30)),
        chunk_delay: None,
        write_chunk: Some(1024..=1024),
        send: None,
    }
}

/// `serverPlayPaddingTurn`.
fn server_play(min: usize, max: usize) -> Turn {
    Turn {
        client_sends: false,
        length: Some(min..=max),
        variants: Vec::new(),
        start_delay: Some(ms(1, 45)),
        chunk_delay: Some(ms(1, 4)),
        write_chunk: Some(32 * 1024..=MAX_CHUNK),
        send: None,
    }
}

const PLAY_STARTS: [&[usize]; 20] = [
    &[4941, 252, 259, 267, 268, 251, 303, 259, 264, 54, 346],
    &[
        4941, 262, 284, 272, 260, 260, 313, 264, 151, 224, 207, 215, 224, 390,
    ],
    &[
        4941, 257, 272, 275, 260, 260, 313, 283, 274, 226, 207, 230, 215, 204, 221, 352,
    ],
    &[
        4941, 259, 272, 288, 260, 260, 311, 270, 70, 236, 223, 201, 210, 352,
    ],
    &[4941, 255, 269, 277, 263, 260, 136, 207, 210, 232, 325],
    &[4941, 259, 270, 274, 263, 258, 327, 170, 210, 375],
    &[
        4941, 257, 275, 291, 260, 260, 325, 269, 70, 230, 226, 207, 221, 352,
    ],
    &[4941, 252, 273, 262, 252, 254, 306, 93],
    &[4941, 273, 270, 269, 258, 256, 322, 221, 207, 215, 438],
    &[
        4941, 259, 275, 274, 250, 258, 308, 267, 154, 233, 209, 207, 213, 393,
    ],
    &[
        4941, 254, 267, 272, 260, 253, 311, 167, 204, 232, 207, 481, 8,
    ],
    &[4941, 259, 269, 272, 261, 313, 207, 213, 500, 19],
    &[
        4941, 262, 269, 274, 263, 274, 311, 270, 242, 210, 229, 221, 210, 431,
    ],
    &[
        4941, 259, 265, 277, 263, 277, 316, 269, 156, 204, 210, 226, 207, 413,
    ],
    &[4941, 215, 251, 249, 317, 260, 270, 249, 52],
    &[
        4941, 224, 263, 277, 316, 267, 272, 260, 138, 230, 226, 207, 204, 352,
    ],
    &[
        4941, 221, 258, 263, 319, 269, 288, 263, 136, 204, 210, 220, 207, 378,
    ],
    &[
        4941, 221, 258, 260, 316, 273, 291, 226, 204, 229, 213, 489, 8,
    ],
    &[
        4941, 238, 260, 261, 306, 272, 277, 260, 224, 241, 212, 207, 204, 393,
    ],
    &[
        4941, 224, 260, 260, 309, 272, 277, 277, 138, 207, 207, 212, 241, 352,
    ],
];

const REGISTRY: [usize; 30] = [
    1590, 226, 329, 229, 186, 151, 78, 81, 79, 235, 67, 67, 78, 71, 82, 74, 982, 117, 1118, 1038,
    970, 400, 239, 49, 50, 95, 65, 104, 32320, 2,
];

/// `startupPaddingSchedule2612`.
fn startup() -> Vec<Turn> {
    vec![
        variants(true, vec![chunks(&[2, 26, 16])], None),
        variants(false, vec![chunks(&[26, 21, 25])], Some(ms(0, 20))),
        variants(true, vec![chunks(&[25])], Some(ms(2, 22))),
        variants(
            false,
            vec![paced(&REGISTRY, &[(28, ms(1, 4)), (29, ms(44, 61))])],
            Some(ms(20, 50)),
        ),
        variants(true, vec![chunks(&[2])], Some(ms(10, 35))),
        variants(
            false,
            PLAY_STARTS
                .iter()
                .map(|chunks| play_start(chunks))
                .collect(),
            Some(ms(35, 50)),
        ),
    ]
}

const STARTUP_TURNS: usize = 6;

/// `playJoinPaddingSchedule2612`'s bounds: the Play tail through the client's
/// `player_loaded`, client turns first.
const PLAY_JOIN: [(usize, usize); 33] = [
    (6, 883),
    (346, 58638),
    (6, 887),
    (388, 61077),
    (2, 50),
    (575, 65584),
    (6, 45),
    (86, 63563),
    (2, 44),
    (42, 51983),
    (2, 851),
    (309, 25083),
    (2, 19),
    (74, 63885),
    (8, 24),
    (30, 66128),
    (2, 19),
    (26, 35818),
    (6, 19),
    (35, 59407),
    (6, 19),
    (37, 65328),
    (2, 19),
    (26, 60622),
    (6, 19),
    (11, 60808),
    (8, 43),
    (55, 62027),
    (2, 19),
    (427, 65622),
    (5, 19),
    (35, 59401),
    (6, 19),
];

/// `clientPlayBursts2612`: the Play turn, its regular send range and the
/// client initialization burst's.
type Burst = (usize, RangeInclusive<usize>, RangeInclusive<usize>);
const BURSTS: [Burst; 3] = [
    (0, 6..=44, 877..=883),
    (2, 6..=45, 884..=887),
    (10, 2..=19, 851..=851),
];

/// `buildPaddingSchedule2612`.
pub(crate) fn schedule() -> Vec<Turn> {
    let mut schedule = startup();
    debug_assert_eq!(schedule.len(), STARTUP_TURNS);
    schedule.extend(PLAY_JOIN.iter().enumerate().map(|(i, &(min, max))| {
        if i % 2 == 0 {
            client_play(min, max)
        } else {
            server_play(min, max)
        }
    }));
    schedule
}

/// `newClientPaddingSchedule2612`: one of three Play turns carries the
/// client's initialization burst.
pub(crate) fn client_schedule() -> Vec<Turn> {
    with_burst(burst_slot(rand::thread_rng().gen_range(0..20)))
}

/// `clientPlayBurstChoices2612`: the 20 samples put the burst first 17
/// times, second twice and third once.
pub(crate) fn burst_slot(draw: u32) -> usize {
    match draw {
        0..=16 => 0,
        17 | 18 => 1,
        _ => 2,
    }
}

pub(crate) fn with_burst(selected: usize) -> Vec<Turn> {
    let mut schedule = schedule();
    for (i, (play_index, regular, burst)) in BURSTS.into_iter().enumerate() {
        schedule[STARTUP_TURNS + play_index].send =
            Some(if i == selected { burst } else { regular });
    }
    schedule
}

fn pick<T: Copy + rand::distributions::uniform::SampleUniform + PartialOrd>(
    range: &RangeInclusive<T>,
) -> T {
    if range.start() == range.end() {
        return *range.start();
    }
    rand::thread_rng().gen_range(range.clone())
}

async fn pause(delay: &Option<Delay>) {
    if let Some(delay) = delay {
        let delay = pick(delay);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }
}

/// What one turn writes: the record length, its chunks and the pause
/// before each.
pub(crate) type Plan = (usize, Vec<usize>, Vec<Option<Delay>>);

impl Turn {
    /// `paddingTurnAcceptsLength`.
    pub(crate) fn accepts(&self, total: usize) -> bool {
        match &self.length {
            Some(range) => range.contains(&total),
            None => self
                .variants
                .iter()
                .any(|variant| variant.chunks.iter().sum::<usize>() == total),
        }
    }

    /// `selectPaddingVariant` and the chunking of `writePaddingTurn`, after
    /// `prefix` bytes another packet already took from the turn.
    pub(crate) fn plan(&self, prefix: usize) -> io::Result<Plan> {
        if self.variants.is_empty() {
            let range = self
                .send
                .as_ref()
                .or(self.length.as_ref())
                .ok_or_else(|| invalid("padding turn without lengths"))?;
            let record = pick(range)
                .checked_sub(prefix)
                .filter(|record| *record >= 1)
                .ok_or_else(|| invalid("padding turn too short for its prefix"))?;
            let chunk = match &self.write_chunk {
                None => DEFAULT_CHUNK,
                Some(range) => pick(range),
            };
            let chunks: Vec<usize> = (0..record)
                .step_by(chunk)
                .map(|start| chunk.min(record - start))
                .collect();
            let mut delays = vec![self.chunk_delay.clone(); chunks.len()];
            delays[0] = None;
            return Ok((record, chunks, delays));
        }
        let variant = &self.variants[rand::thread_rng().gen_range(0..self.variants.len())];
        // The prefix must cover whole chunks at the start: `trimPaddingPrefix`.
        let (mut remaining, mut first) = (prefix, 0);
        while first < variant.chunks.len() && remaining > 0 {
            remaining = remaining
                .checked_sub(variant.chunks[first])
                .ok_or_else(|| invalid(format!("prefix length {prefix} splits chunk {first}")))?;
            first += 1;
        }
        if first == variant.chunks.len() {
            return Err(invalid(format!(
                "prefix length {prefix} leaves no padding record"
            )));
        }
        let chunks = variant.chunks[first..].to_vec();
        Ok((
            chunks.iter().sum(),
            chunks,
            variant.delays[first..].to_vec(),
        ))
    }

    async fn write<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut Conn<S>,
        prefix: usize,
    ) -> io::Result<()> {
        pause(&self.start_delay).await;
        let (record, chunks, delays) = self.plan(prefix)?;
        let mut header = Vec::new();
        varint(&mut header, record as i32);
        if chunks[0] < header.len() {
            return Err(invalid(format!(
                "first padding chunk {} is shorter than header {}",
                chunks[0],
                header.len()
            )));
        }
        if let Some(chunk) = chunks
            .iter()
            .find(|chunk| **chunk == 0 || **chunk > MAX_CHUNK)
        {
            return Err(invalid(format!("invalid padding chunk length: {chunk}")));
        }
        let mut buffer = vec![0u8; chunks.iter().copied().max().unwrap_or(0)];
        buffer[..header.len()].copy_from_slice(&header);
        for (i, (chunk, delay)) in chunks.iter().zip(&delays).enumerate() {
            pause(delay).await;
            conn.write_all(&buffer[..*chunk]).await?;
            if i == 0 {
                buffer[..header.len()].fill(0);
            }
        }
        Ok(())
    }

    async fn read<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut Conn<S>,
        prefix: usize,
    ) -> io::Result<()> {
        let (record, header) = conn.read_varint().await?;
        let record = usize::try_from(record)
            .ok()
            .filter(|record| *record >= header && *record <= MAX_TURN)
            .ok_or_else(|| invalid(format!("invalid padding record length: {record}")))?;
        if !self.accepts(prefix + record) {
            return Err(invalid(format!(
                "padding turn length {} is not allowed",
                prefix + record
            )));
        }
        let mut remaining = record - header;
        let mut buffer = vec![0u8; DEFAULT_CHUNK];
        while remaining > 0 {
            let chunk = remaining.min(buffer.len());
            conn.read_exact(&mut buffer[..chunk]).await?;
            remaining -= chunk;
        }
        Ok(())
    }
}

/// `runPaddingSchedule`: the Login Acknowledged packet of `prefix` bytes
/// opens the first turn.
pub(crate) async fn run<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut Conn<S>,
    schedule: &[Turn],
    client: bool,
    prefix: usize,
) -> io::Result<()> {
    for (i, turn) in schedule.iter().enumerate() {
        let prefix = if i == 0 { prefix } else { 0 };
        let sends = turn.client_sends == client;
        let result = if sends {
            turn.write(conn, prefix).await
        } else {
            turn.read(conn, prefix).await
        };
        result.map_err(|error| {
            let side = if sends { "write" } else { "read" };
            io::Error::new(error.kind(), format!("{side} padding turn {i}: {error}"))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
