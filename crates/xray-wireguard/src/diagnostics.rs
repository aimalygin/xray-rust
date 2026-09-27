//! Explicit diagnostic builds only: bounded numeric metadata, no keys,
//! addresses, packet contents or application data. Flush after shutdown.
use std::{
    collections::VecDeque,
    fs::OpenOptions,
    io::{self, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex,
    },
    time::Instant,
};
const CAPACITY: usize = 2048;
static NEXT: AtomicU64 = AtomicU64::new(1);
struct Event {
    us: u128,
    event: &'static str,
    a: u64,
    b: u64,
    c: u64,
}
struct Buffer {
    start: Instant,
    events: VecDeque<Event>,
    omitted: u64,
}
pub(crate) struct Trace {
    buffer: Option<Mutex<Buffer>>,
    path: Option<PathBuf>,
    flushed: AtomicBool,
}
impl Trace {
    pub(crate) fn new() -> Self {
        let directory = std::env::var_os("XRAY_WIREGUARD_DIAGNOSTICS_DIR")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_dir());
        let buffer = directory.as_ref().map(|_| {
            Mutex::new(Buffer {
                start: Instant::now(),
                events: VecDeque::with_capacity(CAPACITY),
                omitted: 0,
            })
        });
        Self {
            buffer,
            path: directory.map(|p| {
                p.join(format!(
                    "wireguard-{}-{}.jsonl",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ))
            }),
            flushed: AtomicBool::new(false),
        }
    }
    pub(crate) fn record(&self, event: &'static str, a: u64, b: u64, c: u64) {
        let Some(buffer) = &self.buffer else { return };
        let Ok(mut buffer) = buffer.lock() else {
            return;
        };
        let us = buffer.start.elapsed().as_micros();
        if buffer.events.len() == CAPACITY {
            buffer.events.pop_front();
            buffer.omitted += 1;
        }
        buffer.events.push_back(Event { us, event, a, b, c });
    }
    pub(crate) fn flush(&self) {
        if self.flushed.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.write(); // Diagnostic I/O must never fail the transport.
    }
    fn write(&self) -> io::Result<()> {
        let (Some(buffer), Some(path)) = (&self.buffer, &self.path) else {
            return Ok(());
        };
        let buffer = buffer
            .lock()
            .map_err(|_| io::Error::other("trace poisoned"))?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = io::BufWriter::new(options.open(path)?);
        writeln!(
            file,
            "{{\"schema\":1,\"capacity\":{CAPACITY},\"omitted\":{}}}",
            buffer.omitted
        )?;
        for e in &buffer.events {
            writeln!(
                file,
                "{{\"us\":{},\"event\":\"{}\",\"a\":{},\"b\":{},\"c\":{}}}",
                e.us, e.event, e.a, e.b, e.c
            )?;
        }
        file.flush()
    }
}
impl Drop for Trace {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trace_is_bounded_and_counts_omitted_events() {
        let trace = Trace {
            buffer: Some(Mutex::new(Buffer {
                start: Instant::now(),
                events: VecDeque::new(),
                omitted: 0,
            })),
            path: None,
            flushed: AtomicBool::new(false),
        };
        for n in 0..CAPACITY + 7 {
            trace.record("synthetic", n as u64, 0, 0);
        }
        let buffer = trace.buffer.as_ref().unwrap().lock().unwrap();
        assert_eq!(buffer.events.len(), CAPACITY);
        assert_eq!(buffer.omitted, 7);
        assert_eq!(buffer.events.front().unwrap().a, 7);
        assert_eq!(buffer.events.back().unwrap().a, (CAPACITY + 6) as u64);
    }
}
