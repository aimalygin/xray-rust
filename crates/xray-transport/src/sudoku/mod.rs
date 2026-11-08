//! The `sudoku` finalmask of Xray-core v26.10.31: a transform that hides
//! bytes as sudoku clues, with no handshake of its own.
mod codec;
pub(crate) mod datagram;
mod gorand;
mod stream;
mod table;

pub use stream::SudokuStream;
pub use table::SudokuConfig;
