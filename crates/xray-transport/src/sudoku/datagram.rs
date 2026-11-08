//! The sudoku mask on datagrams, as Xray-core's `udpConn` runs it: each
//! datagram encoded afresh in the classic form, starting from the first
//! table, and dropped on the way in unless it decodes whole.
use super::{
    codec::{Decoder, Encoder},
    table::Table,
    SudokuConfig,
};
use std::{io, ops::Range, sync::Arc};

pub(crate) struct DatagramMask {
    tables: Arc<Vec<Table>>,
    padding: (u32, u32),
}

impl DatagramMask {
    pub(crate) fn new(config: &SudokuConfig) -> io::Result<Self> {
        Ok(Self {
            tables: config.tables()?,
            padding: config.padding(),
        })
    }

    pub(crate) fn encode(&self, datagram: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(datagram.len() * 4 + 8);
        Encoder::new(self.tables.clone(), self.padding).encode(datagram, &mut out);
        out
    }

    /// Decodes `buf[range]` in place, returning the plaintext's range, or
    /// `None` for a datagram with a bad or unfinished clue tuple.
    pub(crate) fn decode(&self, buf: &mut [u8], range: Range<usize>) -> Option<Range<usize>> {
        let mut decoder = Decoder::default();
        let mut out = Vec::with_capacity(range.len() / 4 + 1);
        decoder
            .decode(&self.tables, &buf[range.clone()], &mut out)
            .ok()?;
        if decoder.partial() {
            return None;
        }
        buf[range.start..range.start + out.len()].copy_from_slice(&out);
        Some(range.start..range.start + out.len())
    }
}
