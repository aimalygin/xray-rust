//! Exhaustive model of the routing-policy publication lock protocol.
//!
//! The production router serializes writers, snapshots the current immutable
//! `Arc<State>`, prepares a complete replacement, and publishes it through an
//! `RwLock`. This small Loom model deliberately mirrors that protocol without
//! pulling the full network runtime into the state-space search.

use loom::sync::{Arc, Mutex, RwLock};
use loom::thread;

#[derive(Debug, Clone, Copy)]
struct PolicyState {
    revision: u64,
    rule_count: usize,
    strategy_marker: usize,
}

#[derive(Debug)]
struct PolicyCell {
    published: RwLock<Arc<PolicyState>>,
    writer: Mutex<()>,
}

impl PolicyCell {
    fn new() -> Self {
        Self {
            published: RwLock::new(Arc::new(PolicyState {
                revision: 0,
                rule_count: 0,
                strategy_marker: 0,
            })),
            writer: Mutex::new(()),
        }
    }

    fn replace(&self, marker: usize) {
        let _writer = self.writer.lock().expect("writer lock");
        let current = self.snapshot();
        let next = Arc::new(PolicyState {
            revision: current.revision.checked_add(1).expect("model revision"),
            rule_count: marker * 10,
            strategy_marker: marker,
        });
        *self.published.write().expect("publication lock") = next;
    }

    fn snapshot(&self) -> Arc<PolicyState> {
        Arc::clone(&self.published.read().expect("snapshot lock"))
    }
}

fn assert_coherent(snapshot: &PolicyState) {
    assert!(snapshot.revision <= 2);
    assert_eq!(snapshot.rule_count, snapshot.strategy_marker * 10);
    assert!(snapshot.strategy_marker <= 2);
}

#[test]
fn concurrent_readers_observe_whole_policies_and_writers_do_not_lose_revisions() {
    loom::model(|| {
        let cell = Arc::new(PolicyCell::new());

        let writer_one = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || cell.replace(1))
        };
        let writer_two = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || cell.replace(2))
        };
        let reader = {
            let cell = Arc::clone(&cell);
            thread::spawn(move || assert_coherent(&cell.snapshot()))
        };

        writer_one.join().expect("first writer");
        writer_two.join().expect("second writer");
        reader.join().expect("reader");

        let final_state = cell.snapshot();
        assert_coherent(&final_state);
        assert_eq!(final_state.revision, 2);
        assert!(matches!(final_state.strategy_marker, 1 | 2));
    });
}
