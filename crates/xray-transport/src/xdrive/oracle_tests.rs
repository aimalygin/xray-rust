//! Replays tests/fixtures/xdrive/wal-vectors.json, which
//! tools/xdrive-oracle records from Xray-core v26.10.31's own code: the
//! tuning it derives, the names it gives and reads, the local storage's
//! name resolution, and its segment writer and reader driven step by step.

use std::collections::{BTreeMap, HashMap};
use std::future::poll_fn;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::local::LocalStorage;
use super::names::{announce_name, object_name, parse_entry};
use super::params::{Params, XdriveTuning};
use super::storage::{Entry, Storage, StorageError};
use super::wal::{WalReader, WalWriter};

/// Go's errors package names the package before its own messages.
const GO_PREFIX: &str = "transport/internet/xdrive: ";

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tests/fixtures/xdrive/wal-vectors.json"
    ))
    .unwrap()
}

fn go_message(message: &str) -> &str {
    message.strip_prefix(GO_PREFIX).unwrap_or(message)
}

fn u32s(value: &Value) -> Vec<u32> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u32)
        .collect()
}

#[test]
fn params_match_xray() {
    let vectors = vectors();
    for case in vectors["params"].as_array().unwrap() {
        let input = u32s(&case["input"]);
        let params = Params::from_tuning(&XdriveTuning {
            segment_bytes: input[0],
            flush_interval_ms: input[1],
            poll_interval_ms: input[2],
            max_poll_interval_ms: input[3],
            session_ttl_seconds: input[4],
            concurrency: input[5],
            eager_window_ms: input[6],
            hole_timeout_ms: input[7],
        });
        let out = &case["output"];
        let nanos = |key: &str| Duration::from_nanos(out[key].as_u64().unwrap());
        assert_eq!(
            params.segment_bytes as u64,
            out["segmentBytes"].as_u64().unwrap(),
            "{case}"
        );
        assert_eq!(params.flush_interval, nanos("flushIntervalNs"), "{case}");
        assert_eq!(
            params.min_poll_interval,
            nanos("minPollIntervalNs"),
            "{case}"
        );
        assert_eq!(
            params.max_poll_interval,
            nanos("maxPollIntervalNs"),
            "{case}"
        );
        assert_eq!(params.eager_window, nanos("eagerWindowNs"), "{case}");
        assert_eq!(params.hole_timeout, nanos("holeTimeoutNs"), "{case}");
        assert_eq!(params.session_ttl, nanos("sessionTtlNs"), "{case}");
        assert_eq!(
            params.concurrency as u64,
            out["concurrency"].as_u64().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn names_match_xray() {
    let vectors = vectors();
    for case in vectors["objectNames"].as_array().unwrap() {
        let name = object_name(
            case["prefix"].as_str().unwrap(),
            case["seq"].as_i64().unwrap(),
            case["suffix"].as_str().unwrap(),
        );
        assert_eq!(name, case["name"].as_str().unwrap(), "{case}");
    }
    for case in vectors["entries"].as_array().unwrap() {
        let parsed = parse_entry(case["name"].as_str().unwrap()).map(|(seq, _)| seq);
        let expected = case["ok"]
            .as_bool()
            .unwrap()
            .then(|| case["seq"].as_i64().unwrap());
        assert_eq!(parsed, expected, "{case}");
    }
    for case in vectors["announce"].as_array().unwrap() {
        let nanos = case["nanos"].as_i64().unwrap();
        let at = if nanos >= 0 {
            UNIX_EPOCH + Duration::from_nanos(nanos as u64)
        } else {
            UNIX_EPOCH - Duration::from_nanos(nanos.unsigned_abs())
        };
        assert_eq!(
            announce_name(case["session"].as_str().unwrap(), at),
            case["name"].as_str().unwrap(),
            "{case}"
        );
    }
}

#[tokio::test]
async fn local_names_resolve_as_xrays() {
    let vectors = vectors();
    let root = std::env::temp_dir().join(format!(
        "xray-rust-xdrive-resolve-{}",
        super::names::new_session_id()
    ));
    let storage = LocalStorage::open(root.to_str().unwrap()).await.unwrap();
    for case in vectors["resolve"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        match (storage.resolve_for_test(name), case.get("path")) {
            (Ok(path), Some(expected)) => {
                let relative = path.strip_prefix(&root).unwrap();
                assert_eq!(
                    relative.to_str().unwrap(),
                    expected.as_str().unwrap(),
                    "{case}"
                );
            }
            (Err(error), None) => {
                assert_eq!(
                    error.to_string(),
                    go_message(case["error"].as_str().unwrap()),
                    "{case}"
                );
            }
            (got, _) => panic!("{case}: {got:?}"),
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

/// A storage in memory that refuses the names it is told to.
#[derive(Debug, Default)]
struct Recording {
    objects: Mutex<BTreeMap<String, Bytes>>,
    refuse: Vec<String>,
}

#[async_trait]
impl Storage for Recording {
    async fn put(&self, name: &str, data: Bytes) -> Result<(), StorageError> {
        if self.refuse.iter().any(|refused| refused == name) {
            return Err(StorageError::Failed("refused".to_owned()));
        }
        self.objects.lock().unwrap().insert(name.to_owned(), data);
        Ok(())
    }
    async fn get(&self, _name: &str) -> Result<Bytes, StorageError> {
        Err(StorageError::NotFound)
    }
    async fn delete(&self, _name: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<Entry>, StorageError> {
        Ok(Vec::new())
    }
}

/// Byte `k` of a writer case's stream, as the oracle makes it.
fn payload(from: usize, size: usize) -> Vec<u8> {
    (from..from + size)
        .map(|k| ((k * 131 + 7) % 256) as u8)
        .collect()
}

/// `Write` of all of `data`: Xray-core takes it at once; here the writer
/// may take it in parts and wait for its segments in between.
async fn write_all(writer: &WalWriter, data: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < data.len() {
        let step = poll_fn(|cx| Poll::Ready(writer.poll_write(cx, &data[offset..]))).await;
        match step {
            Poll::Ready(Ok(taken)) => offset += taken,
            Poll::Ready(Err(error)) => return Err(error.to_string()),
            Poll::Pending => writer.settle().await,
        }
    }
    Ok(())
}

#[tokio::test]
async fn the_writer_stores_what_xrays_stores() {
    let vectors = vectors();
    for case in vectors["writers"].as_array().unwrap() {
        let storage = Arc::new(Recording {
            refuse: case["refuse"]
                .as_array()
                .map(|names| {
                    names
                        .iter()
                        .map(|n| n.as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_default(),
            ..Recording::default()
        });
        let params = Params::from_tuning(&XdriveTuning {
            segment_bytes: case["segmentBytes"].as_u64().unwrap() as u32,
            concurrency: case["concurrency"].as_u64().unwrap() as u32,
            ..XdriveTuning::default()
        });
        let writer = WalWriter::manual(
            Arc::clone(&storage) as Arc<dyn Storage>,
            "up".to_owned(),
            params,
        );
        let mut written = 0;
        let mut write_errors = BTreeMap::new();
        let mut close_error = None;
        for (index, op) in case["ops"].as_array().unwrap().iter().enumerate() {
            let op = op.as_str().unwrap();
            if let Some(size) = op.strip_prefix('w') {
                let size: usize = size.parse().unwrap();
                match write_all(&writer, &payload(written, size)).await {
                    Ok(()) => written += size,
                    Err(error) => {
                        write_errors.insert(index.to_string(), error);
                    }
                }
            } else if op == "t" {
                writer.tick();
            } else if op == "c" {
                if let Err(error) = writer.close().await {
                    close_error = Some(error.to_string());
                }
            }
            writer.settle().await;
        }
        let expected_errors: BTreeMap<String, String> = case["writeErrors"]
            .as_object()
            .map(|errors| {
                errors
                    .iter()
                    .map(|(op, error)| (op.clone(), go_message(error.as_str().unwrap()).to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        assert_eq!(write_errors, expected_errors, "{}", case["name"]);
        assert_eq!(
            close_error.as_deref(),
            case["closeError"].as_str().map(go_message),
            "{}",
            case["name"]
        );
        let objects: Vec<(String, usize, String)> = storage
            .objects
            .lock()
            .unwrap()
            .iter()
            .map(|(name, data)| (name.clone(), data.len(), hex(&Sha256::digest(data))))
            .collect();
        let expected: Vec<(String, usize, String)> = case["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|object| {
                (
                    object["name"].as_str().unwrap().to_owned(),
                    object["size"].as_u64().unwrap() as usize,
                    object["sha256"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(objects, expected, "{}", case["name"]);
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A direction whose listing and objects each step sets.
#[derive(Debug, Default)]
struct Listing {
    step: Mutex<Step>,
}

#[derive(Debug, Default)]
struct Step {
    listing: Vec<Entry>,
    data: HashMap<String, Bytes>,
    fail: HashMap<String, String>,
}

#[async_trait]
impl Storage for Listing {
    async fn put(&self, _name: &str, _data: Bytes) -> Result<(), StorageError> {
        Ok(())
    }
    async fn get(&self, name: &str) -> Result<Bytes, StorageError> {
        let step = self.step.lock().unwrap();
        if let Some(error) = step.fail.get(name) {
            return Err(StorageError::Failed(error.clone()));
        }
        step.data.get(name).cloned().ok_or(StorageError::NotFound)
    }
    async fn delete(&self, _name: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<Entry>, StorageError> {
        Ok(self.step.lock().unwrap().listing.clone())
    }
}

#[tokio::test]
async fn the_reader_takes_what_xrays_takes() {
    let vectors = vectors();
    for case in vectors["readers"].as_array().unwrap() {
        let storage = Arc::new(Listing::default());
        let mut params = Params::from_tuning(&XdriveTuning {
            concurrency: case["concurrency"].as_u64().unwrap() as u32,
            ..XdriveTuning::default()
        });
        params.hole_timeout = match case["holeTimeout"].as_str().unwrap() {
            "zero" => Duration::ZERO,
            "long" => Duration::from_secs(3600),
            other => panic!("hole timeout {other}"),
        };
        let (mut reader, mut chunks, mut discards) = WalReader::manual(
            Arc::clone(&storage) as Arc<dyn Storage>,
            "down".to_owned(),
            params,
        );
        for (index, step) in case["steps"].as_array().unwrap().iter().enumerate() {
            {
                let mut current = storage.step.lock().unwrap();
                *current = Step::default();
                for listed in step["listing"].as_array().map_or(&[][..], Vec::as_slice) {
                    let name = listed["name"].as_str().unwrap();
                    current.listing.push(Entry {
                        name: name.to_owned(),
                        inline: listed["inline"]
                            .as_str()
                            .map(|inline| Bytes::from(inline.as_bytes().to_vec())),
                    });
                    if let Some(data) = listed["data"].as_str() {
                        current.data.insert(
                            format!("down/{name}"),
                            Bytes::from(data.as_bytes().to_vec()),
                        );
                    }
                    if let Some(error) = listed["fail"].as_str() {
                        current
                            .fail
                            .insert(format!("down/{name}"), error.to_owned());
                    }
                }
            }
            let (advanced, eof, error, seq) = reader.poll_once().await;
            let mut got_chunks = Vec::new();
            while let Ok(chunk) = chunks.try_recv() {
                got_chunks.push(String::from_utf8(chunk.to_vec()).unwrap());
            }
            let mut got_discards = Vec::new();
            while let Ok(name) = discards.try_recv() {
                got_discards.push(name);
            }
            let label = format!("{} step {index}", case["name"]);
            assert_eq!(advanced, step["advanced"].as_bool().unwrap(), "{label}");
            assert_eq!(eof, step["eof"].as_bool().unwrap(), "{label}");
            assert_eq!(
                error.as_deref(),
                step["error"].as_str().map(go_message),
                "{label}"
            );
            let strings = |key: &str| -> Vec<String> {
                step[key]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| s.as_str().unwrap().to_owned())
                    .collect()
            };
            assert_eq!(got_chunks, strings("chunks"), "{label}");
            assert_eq!(got_discards, strings("discarded"), "{label}");
            assert_eq!(seq, step["seq"].as_i64().unwrap(), "{label}");
        }
    }
}
