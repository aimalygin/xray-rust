//! How much memory this process may give transport buffers.
//!
//! Most transports size their buffers to the link. Flow-controlled multiplexed
//! transports also hold whatever the peer may send and a slow reader has not
//! taken yet, and on a phone that has to fit beside everything else inside a
//! VPN extension's memory limit. The core sets the class from its runtime
//! profile before it builds any outbound; until then it follows the target.

use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryClass {
    /// Buffers sized for throughput, as Go's clients size them.
    Standard,
    /// Buffers that start small and grow only for a reader that keeps up.
    Constrained,
}

const TARGET_DEFAULT: u8 = 0;
const STANDARD: u8 = 1;
const CONSTRAINED: u8 = 2;

static CLASS: AtomicU8 = AtomicU8::new(TARGET_DEFAULT);

/// Sets the class for connections opened from now on; `None` restores the
/// target's default. Open connections keep the class they started with.
pub fn set_memory_class(class: Option<MemoryClass>) {
    let value = match class {
        None => TARGET_DEFAULT,
        Some(MemoryClass::Standard) => STANDARD,
        Some(MemoryClass::Constrained) => CONSTRAINED,
    };
    CLASS.store(value, Ordering::Relaxed);
}

pub fn memory_class() -> MemoryClass {
    match CLASS.load(Ordering::Relaxed) {
        STANDARD => MemoryClass::Standard,
        CONSTRAINED => MemoryClass::Constrained,
        _ => target_default(),
    }
}

fn target_default() -> MemoryClass {
    if cfg!(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    )) {
        MemoryClass::Constrained
    } else {
        MemoryClass::Standard
    }
}
