//! Sudoku encoding as Xray-core v26.10.31 runs it. The classic form sends
//! each byte as four clue bytes in random order, taking the tables in turn;
//! the packed form, which the server writes over TCP, sends six bits per
//! byte. Both scatter padding bytes, which carry no clue, with one chance
//! drawn per encoder.
#[cfg(test)]
use super::table::Layout;
use super::table::Table;
use rand::Rng;
use std::{io, sync::Arc};

const PERMUTATIONS: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `pickPaddingChance`: a percentage within the normalized range.
fn padding_chance((min, max): (u32, u32)) -> u32 {
    if max == min {
        min
    } else {
        rand::thread_rng().gen_range(min..=max)
    }
}

fn should_pad(chance: u32) -> bool {
    match chance {
        0 => false,
        100.. => true,
        _ => rand::thread_rng().gen_range(0..100) < chance,
    }
}

/// The classic encoder: four clues per byte.
pub(crate) struct Encoder {
    tables: Arc<Vec<Table>>,
    chance: u32,
    index: usize,
}

impl Encoder {
    pub(crate) fn new(tables: Arc<Vec<Table>>, padding: (u32, u32)) -> Self {
        Self {
            tables,
            chance: padding_chance(padding),
            index: 0,
        }
    }

    fn padding(&self, table: &Table) -> u8 {
        let pool = &table.layout.padding_pool;
        pool[rand::thread_rng().gen_range(0..pool.len())]
    }

    pub(crate) fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        for &byte in input {
            let table = &self.tables[self.index % self.tables.len()];
            if should_pad(self.chance) {
                out.push(self.padding(table));
            }
            let clues = &table.encode[usize::from(byte)];
            let hints = clues[rng.gen_range(0..clues.len())];
            for index in PERMUTATIONS[rng.gen_range(0..PERMUTATIONS.len())] {
                if should_pad(self.chance) {
                    out.push(self.padding(table));
                }
                out.push(hints[index]);
            }
            self.index += 1;
        }
        if !input.is_empty() && should_pad(self.chance) {
            out.push(self.padding(&self.tables[self.index % self.tables.len()]));
        }
    }
}

/// The classic decoder, which skips any byte that carries no clue.
#[derive(Default)]
pub(crate) struct Decoder {
    index: usize,
    hints: Vec<u8>,
}

impl Decoder {
    pub(crate) fn decode(
        &mut self,
        tables: &[Table],
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        for &byte in input {
            let table = &tables[self.index % tables.len()];
            if !table.layout.is_hint(byte) {
                continue;
            }
            self.hints.push(byte);
            if self.hints.len() < 4 {
                continue;
            }
            let hints = [self.hints[0], self.hints[1], self.hints[2], self.hints[3]];
            self.hints.clear();
            out.push(
                table
                    .decode(hints)
                    .ok_or_else(|| invalid("invalid sudoku hint tuple"))?,
            );
            self.index += 1;
        }
        Ok(())
    }

    /// Whether a clue tuple is incomplete.
    pub(crate) fn partial(&self) -> bool {
        !self.hints.is_empty()
    }
}

/// The packed encoder, which Xray's server writes TCP downlinks with.
#[cfg(test)]
pub(crate) struct PackedEncoder {
    layouts: Vec<Layout>,
    chance: u32,
    index: usize,
}

#[cfg(test)]
impl PackedEncoder {
    pub(crate) fn new(tables: &[Table], padding: (u32, u32)) -> Self {
        Self {
            layouts: tables.iter().map(|table| table.layout.clone()).collect(),
            chance: padding_chance(padding),
            index: 0,
        }
    }

    fn layout(&self) -> &Layout {
        &self.layouts[self.index % self.layouts.len()]
    }

    fn maybe_pad(&self, layout: &Layout, out: &mut Vec<u8>) {
        if !should_pad(self.chance) {
            return;
        }
        let pool = &layout.padding_pool;
        if pool.len() == 1 {
            out.push(pool[0]);
            return;
        }
        loop {
            let byte = pool[rand::thread_rng().gen_range(0..pool.len())];
            if byte != layout.pad_marker {
                out.push(byte);
                return;
            }
        }
    }

    pub(crate) fn encode(&mut self, input: &[u8], out: &mut Vec<u8>) {
        let (mut bits, mut count) = (0u64, 0u8);
        for &byte in input {
            bits = (bits << 8) | u64::from(byte);
            count += 8;
            while count >= 6 {
                count -= 6;
                let layout = self.layout().clone();
                self.maybe_pad(&layout, out);
                out.push(layout.encode_group((bits >> count) as u8));
                self.index += 1;
                bits &= (1u64 << count) - 1;
            }
        }
        if count > 0 {
            let layout = self.layout().clone();
            self.maybe_pad(&layout, out);
            out.push(layout.encode_group((bits << (6 - count)) as u8));
            self.index += 1;
            out.push(self.layout().pad_marker);
        }
        let layout = self.layout().clone();
        self.maybe_pad(&layout, out);
    }
}

/// The packed decoder: a pad marker drops a partial group's bits.
#[derive(Default)]
pub(crate) struct PackedDecoder {
    index: usize,
    bits: u64,
    count: u32,
}

impl PackedDecoder {
    pub(crate) fn decode(
        &mut self,
        tables: &[Table],
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> io::Result<()> {
        for &byte in input {
            let layout = &tables[self.index % tables.len()].layout;
            if !layout.is_hint(byte) {
                if byte == layout.pad_marker {
                    (self.bits, self.count) = (0, 0);
                }
                continue;
            }
            let group = layout
                .decode_group(byte)
                .ok_or_else(|| invalid("invalid packed sudoku byte"))?;
            self.index += 1;
            self.bits = (self.bits << 6) | u64::from(group);
            self.count += 6;
            while self.count >= 8 {
                self.count -= 8;
                out.push((self.bits >> self.count) as u8);
                self.bits &= (1u64 << self.count) - 1;
            }
        }
        Ok(())
    }

    /// At the end of the stream, as Xray's reader resets it.
    pub(crate) fn reset(&mut self) {
        (self.bits, self.count) = (0, 0);
    }
}

#[cfg(test)]
mod tests;
