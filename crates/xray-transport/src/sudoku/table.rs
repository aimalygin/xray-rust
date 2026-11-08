//! Sudoku tables as Xray-core v26.10.31 builds them: every byte stands for
//! one of the 288 4x4 sudoku grids, shuffled by the password, and is sent
//! as four clues that only that grid has. A layout decides which byte
//! values carry a clue and which pad.
use super::gorand::GoRand;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    sync::{Arc, Mutex, OnceLock},
};

/// Which byte values carry a clue's 6-bit group, as `byteLayout` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layout {
    kind: Kind,
    hint_mask: u8,
    hint_value: u8,
    /// The padding byte that also ends a packed write's partial group.
    pub(crate) pad_marker: u8,
    pub(crate) padding_pool: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    Ascii,
    Entropy,
    Custom {
        x_mask: u8,
        p_bits: [u8; 2],
        v_bits: [u8; 4],
    },
}

impl Layout {
    fn ascii() -> Self {
        Self {
            kind: Kind::Ascii,
            hint_mask: 0x40,
            hint_value: 0x40,
            pad_marker: 0x3f,
            padding_pool: (0x20..0x40).collect(),
        }
    }

    fn entropy() -> Self {
        Self {
            kind: Kind::Entropy,
            hint_mask: 0x90,
            hint_value: 0x00,
            pad_marker: 0x80,
            padding_pool: (0..8).flat_map(|i| [0x80 + i, 0x10 + i]).collect(),
        }
    }

    /// A custom layout from a normalized pattern of two `x`, two `p` and
    /// four `v`, the first character the top bit.
    fn custom(pattern: &str) -> io::Result<Self> {
        let (mut x_bits, mut p_bits, mut v_bits) = (Vec::new(), Vec::new(), Vec::new());
        for (i, c) in pattern.chars().enumerate() {
            let bit = 7 - i as u8;
            match c {
                'x' => x_bits.push(bit),
                'p' => p_bits.push(bit),
                _ => v_bits.push(bit),
            }
        }
        let x_mask = x_bits.iter().fold(0u8, |mask, bit| mask | 1 << bit);
        let p_bits = [p_bits[0], p_bits[1]];
        let v_bits = [v_bits[0], v_bits[1], v_bits[2], v_bits[3]];
        let mut padding = Vec::new();
        for &drop in &x_bits {
            for group in 0..64u8 {
                let byte = custom_group(x_mask & !(1 << drop), p_bits, v_bits, group);
                if byte.count_ones() >= 5 && !padding.contains(&byte) {
                    padding.push(byte);
                }
            }
        }
        padding.sort_unstable();
        let Some(&pad_marker) = padding.first() else {
            return Err(invalid("customTable produced empty padding pool"));
        };
        Ok(Self {
            kind: Kind::Custom {
                x_mask,
                p_bits,
                v_bits,
            },
            hint_mask: x_mask,
            hint_value: x_mask,
            pad_marker,
            padding_pool: padding,
        })
    }

    pub(crate) fn is_hint(&self, byte: u8) -> bool {
        // ASCII sends '\n' for 0x7f, to avoid DEL on the wire.
        byte & self.hint_mask == self.hint_value || self.hint_mask == 0x40 && byte == b'\n'
    }

    /// The byte that carries a clue's or a packed 6-bit group.
    pub(crate) fn encode_group(&self, group: u8) -> u8 {
        let group = group & 0x3f;
        match self.kind {
            Kind::Ascii => match 0x40 | group {
                0x7f => b'\n',
                byte => byte,
            },
            Kind::Entropy => ((group & 0x30) << 1) | (group & 0x0f),
            Kind::Custom {
                x_mask,
                p_bits,
                v_bits,
            } => custom_group(x_mask, p_bits, v_bits, group),
        }
    }

    pub(crate) fn decode_group(&self, byte: u8) -> Option<u8> {
        match self.kind {
            Kind::Ascii if byte == b'\n' => Some(0x3f),
            Kind::Ascii => (byte & 0x40 != 0).then_some(byte & 0x3f),
            Kind::Entropy => (byte & 0x90 == 0).then_some(((byte >> 1) & 0x30) | (byte & 0x0f)),
            Kind::Custom {
                x_mask,
                p_bits,
                v_bits,
            } => {
                if byte & x_mask != x_mask {
                    return None;
                }
                let value = (u8::from(byte & (1 << p_bits[0]) != 0) << 1)
                    | u8::from(byte & (1 << p_bits[1]) != 0);
                let position = v_bits.iter().enumerate().fold(0u8, |position, (i, bit)| {
                    position | u8::from(byte & (1 << bit) != 0) << (3 - i)
                });
                Some((value << 4) | position)
            }
        }
    }
}

/// `encodeGroupWithDropX` with the x bits already chosen.
fn custom_group(x: u8, p_bits: [u8; 2], v_bits: [u8; 4], group: u8) -> u8 {
    let value = (group >> 4) & 0x03;
    let position = group & 0x0f;
    let mut out = x;
    if value & 0x02 != 0 {
        out |= 1 << p_bits[0];
    }
    if value & 0x01 != 0 {
        out |= 1 << p_bits[1];
    }
    for (i, bit) in v_bits.iter().enumerate() {
        if (position >> (3 - i)) & 0x01 == 1 {
            out |= 1 << bit;
        }
    }
    out
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// One password's table in one layout.
#[derive(Debug)]
pub(crate) struct Table {
    /// Each byte's clue sets, each four clue bytes.
    pub(crate) encode: Vec<Vec<[u8; 4]>>,
    decode: HashMap<u32, u8>,
    pub(crate) layout: Layout,
}

impl Table {
    /// The byte four clues stand for, in any order.
    pub(crate) fn decode(&self, hints: [u8; 4]) -> Option<u8> {
        self.decode.get(&pack_key(sort4(hints))).copied()
    }
}

fn pack_key(hints: [u8; 4]) -> u32 {
    u32::from_be_bytes(hints)
}

fn sort4(mut hints: [u8; 4]) -> [u8; 4] {
    hints.sort_unstable();
    hints
}

/// Tables by password, ASCII mode and custom patterns, as Xray caches them.
type TableCache = HashMap<(String, bool, Vec<String>), Arc<Vec<Table>>>;

/// The mask's settings, as `sudoku.Config` holds them.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct SudokuConfig {
    pub password: String,
    pub ascii: String,
    pub custom_table: String,
    pub custom_tables: Vec<String>,
    pub padding_min: u32,
    pub padding_max: u32,
}

impl std::fmt::Debug for SudokuConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SudokuConfig")
            .field("password", &"<redacted>")
            .field("ascii", &self.ascii)
            .field("custom_table", &self.custom_table)
            .field("custom_tables", &self.custom_tables)
            .field("padding_min", &self.padding_min)
            .field("padding_max", &self.padding_max)
            .finish()
    }
}

impl SudokuConfig {
    /// `normalizedPadding`: both percentages at most 100, the maximum at
    /// least the minimum.
    pub(crate) fn padding(&self) -> (u32, u32) {
        let min = self.padding_min.min(100);
        (min, self.padding_max.min(100).max(min))
    }

    /// `getTables`: one table per distinct layout, built once per process.
    pub(crate) fn tables(&self) -> io::Result<Arc<Vec<Table>>> {
        static CACHE: OnceLock<Mutex<TableCache>> = OnceLock::new();
        let ascii = ascii_mode(&self.ascii)?;
        let patterns = self.patterns(ascii)?;
        let key = (self.password.clone(), ascii, patterns.clone());
        let cache = CACHE.get_or_init(Default::default);
        if let Some(tables) = cache.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            return Ok(tables.clone());
        }
        let tables = patterns
            .iter()
            .map(|pattern| {
                let layout = if ascii {
                    Layout::ascii()
                } else if pattern.is_empty() {
                    Layout::entropy()
                } else {
                    Layout::custom(pattern)?
                };
                build_table(&self.password, layout)
            })
            .collect::<io::Result<Vec<_>>>()?;
        let tables = Arc::new(tables);
        cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, tables.clone());
        Ok(tables)
    }

    /// `normalizedCustomPatterns`: the custom tables, or the one, trimmed,
    /// normalized and deduplicated in order; ASCII mode takes none.
    fn patterns(&self, ascii: bool) -> io::Result<Vec<String>> {
        if ascii {
            return Ok(vec![String::new()]);
        }
        let raw: Vec<&str> = if self.custom_tables.is_empty() {
            vec![&self.custom_table]
        } else {
            self.custom_tables.iter().map(String::as_str).collect()
        };
        let mut patterns = Vec::new();
        for raw in raw {
            let trimmed = raw.trim();
            let pattern = if trimmed.is_empty() {
                String::new()
            } else {
                normalize_custom_table(trimmed)?
            };
            if !patterns.contains(&pattern) {
                patterns.push(pattern);
            }
        }
        if patterns.is_empty() {
            patterns.push(String::new());
        }
        Ok(patterns)
    }
}

/// `normalizeASCII`: true for the ASCII layout.
pub(crate) fn ascii_mode(mode: &str) -> io::Result<bool> {
    match mode.trim().to_lowercase().as_str() {
        "" | "entropy" | "prefer_entropy" => Ok(false),
        "ascii" | "prefer_ascii" => Ok(true),
        _ => Err(invalid(format!("invalid sudoku ascii mode: {mode}"))),
    }
}

/// `normalizeCustomTable`.
pub(crate) fn normalize_custom_table(pattern: &str) -> io::Result<String> {
    let cleaned = pattern.trim().to_lowercase().replace(' ', "");
    if cleaned.len() != 8 {
        return Err(invalid(format!(
            "customTable must be 8 chars, got {}",
            cleaned.len()
        )));
    }
    let count = |wanted: char| cleaned.chars().filter(|&c| c == wanted).count();
    if let Some(c) = cleaned.chars().find(|c| !matches!(c, 'x' | 'p' | 'v')) {
        return Err(invalid(format!("customTable has invalid char {c:?}")));
    }
    if count('x') != 2 || count('p') != 2 || count('v') != 4 {
        return Err(invalid("customTable must contain exactly 2 x, 2 p and 4 v"));
    }
    Ok(cleaned)
}

/// `buildTable`: the grids in the order the password's SHA-256 shuffles
/// them with Go's `math/rand`, byte `b` taking the `b`th.
fn build_table(password: &str, layout: Layout) -> io::Result<Table> {
    let patterns = base_patterns();
    let hash = Sha256::digest(password.as_bytes());
    let seed = i64::from_be_bytes(hash[..8].try_into().expect("eight bytes"));
    let mut order: Vec<usize> = (0..patterns.len()).collect();
    GoRand::new(seed).shuffle(&mut order);
    let mut encode = Vec::with_capacity(256);
    let mut decode = HashMap::new();
    for (byte, &grid) in order.iter().take(256).enumerate() {
        let mut clues = Vec::with_capacity(patterns[grid].len());
        for groups in &patterns[grid] {
            let hints = groups.map(|group| layout.encode_group(group));
            let previous = decode.insert(pack_key(sort4(hints)), byte as u8);
            if previous.is_some_and(|previous| previous != byte as u8) {
                return Err(invalid(format!(
                    "decode key collision for byte {} and {byte}",
                    previous.unwrap_or_default()
                )));
            }
            clues.push(hints);
        }
        encode.push(clues);
    }
    Ok(Table {
        encode,
        decode,
        layout,
    })
}

/// `buildBasePatterns`: for each grid, the sorted clue groups of every set
/// of four positions that no other grid shares.
fn base_patterns() -> &'static [Vec<[u8; 4]>] {
    static PATTERNS: OnceLock<Vec<Vec<[u8; 4]>>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let grids = all_grids();
        let mut patterns = vec![Vec::new(); grids.len()];
        for positions in hint_positions() {
            let groups: Vec<[u8; 4]> = grids
                .iter()
                .map(|grid| sort4(positions.map(|position| clue_group(grid, position))))
                .collect();
            let mut counts: HashMap<[u8; 4], u16> = HashMap::with_capacity(grids.len());
            for key in &groups {
                *counts.entry(*key).or_default() += 1;
            }
            for (grid, key) in groups.into_iter().enumerate() {
                if counts[&key] == 1 {
                    patterns[grid].push(key);
                }
            }
        }
        patterns
    })
}

/// Two bits of value and four of position.
fn clue_group(grid: &[u8; 16], position: u8) -> u8 {
    ((grid[usize::from(position)] - 1) << 4) | (position & 0x0f)
}

/// Every 4x4 sudoku grid, in Xray's depth-first order.
fn all_grids() -> Vec<[u8; 16]> {
    fn fill(grid: &mut [u8; 16], index: usize, out: &mut Vec<[u8; 16]>) {
        if index == 16 {
            out.push(*grid);
            return;
        }
        let (row, col) = (index / 4, index % 4);
        let (box_row, box_col) = ((row / 2) * 2, (col / 2) * 2);
        for number in 1..=4 {
            let clashes = (0..4)
                .any(|i| grid[row * 4 + i] == number || grid[i * 4 + col] == number)
                || (0..2).any(|r| (0..2).any(|c| grid[(box_row + r) * 4 + box_col + c] == number));
            if clashes {
                continue;
            }
            grid[index] = number;
            fill(grid, index + 1, out);
            grid[index] = 0;
        }
    }
    let mut grids = Vec::with_capacity(288);
    fill(&mut [0; 16], 0, &mut grids);
    grids
}

/// The 1820 sets of four positions, in lexicographic order.
fn hint_positions() -> Vec<[u8; 4]> {
    let mut positions = Vec::with_capacity(1820);
    for a in 0..13 {
        for b in a + 1..14 {
            for c in b + 1..15 {
                for d in c + 1..16 {
                    positions.push([a, b, c, d]);
                }
            }
        }
    }
    positions
}

#[cfg(test)]
mod tests;
