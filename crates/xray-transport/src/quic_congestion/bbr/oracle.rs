//! The differential oracle: Xray-core's own BBR sender, driven over
//! simulated paths by `tools/bbr-oracle`, recorded every call it received
//! and a digest of its whole state after each congestion event. The port
//! replays the calls and must reach the same state at every step.
//!
//! `scripts/check-bbr-oracle.sh` regenerates the trace with the pinned
//! Xray-core and points `XRAY_BBR_TRACE` at it: the fresh trace must equal
//! the committed fixture byte for byte, and replays the same.

use std::collections::VecDeque;

use serde_json::Value;

use super::*;

/// quic-go's clock start, which the trace's times count from.
const CLOCK_START: Time = 3_600 * SECOND;

const FIXTURE: &[u8] = include_bytes!("../../../../../tests/fixtures/bbr/xray-bbr-trace.json.zst");

fn fixture() -> Vec<u8> {
    zstd::decode_all(FIXTURE).expect("the fixture is zstd")
}

/// The values the Go oracle digests, in its `stateFields` order.
fn state(sender: &BbrSender) -> Vec<String> {
    let flag = |value: bool| i64::from(value).to_string();
    let mut values = vec![
        (sender.mode as i64).to_string(),
        (sender.recovery_state as i64).to_string(),
        sender.cycle_current_offset.to_string(),
        sender.round_trip_count.to_string(),
        sender.min_rtt.to_string(),
        sender.min_rtt_timestamp.to_string(),
        sender.congestion_window.to_string(),
        sender.recovery_window.to_string(),
        sender.congestion_window().to_string(),
        sender.pacing_rate.to_string(),
        sender.pacing_rate().to_string(),
        sender.pacing_gain.to_bits().to_string(),
        sender.congestion_window_gain.to_bits().to_string(),
        flag(sender.is_at_full_bandwidth),
        sender.rounds_without_bandwidth_gain.to_string(),
        sender.bandwidth_at_last_round.to_string(),
        sender.max_bandwidth.best().to_string(),
        sender.exit_probe_rtt_at.to_string(),
        flag(sender.probe_rtt_round_passed),
        flag(sender.last_sample_is_app_limited),
        flag(sender.has_no_app_limited_sample),
        sender.end_recovery_at.to_string(),
        sender.current_round_trip_end.to_string(),
        sender.num_loss_events_in_round.to_string(),
        sender.bytes_lost_in_round.to_string(),
        flag(sender.detect_overshooting),
        sender.bytes_lost_while_detecting_overshooting.to_string(),
        sender.bytes_in_flight.to_string(),
        flag(sender.exiting_quiescence),
        sender.last_sent_packet.to_string(),
        sender.max_datagram_size.to_string(),
        sender.initial_congestion_window.to_string(),
        sender.min_congestion_window.to_string(),
        sender.max_congestion_window.to_string(),
        sender.cwnd_to_calculate_min_pacing_rate.to_string(),
        sender.last_cycle_start.to_string(),
    ];
    values.extend(sender.sampler.oracle_state());
    values
}

/// FNV-1a 64 over the values joined by commas, in Go's `%x`.
fn digest(values: &[String]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in values.join(",").bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:x}")
}

fn number(value: &Value) -> i64 {
    value
        .as_i64()
        .unwrap_or_else(|| panic!("an integer, not {value}"))
}

fn packets(value: &Value) -> Vec<(i64, i64)> {
    value
        .as_array()
        .expect("a packet list")
        .iter()
        .map(|pair| (number(&pair[0]), number(&pair[1])))
        .collect()
}

fn profile(name: &str) -> BbrProfile {
    match name {
        "conservative" => BbrProfile::Conservative,
        "standard" => BbrProfile::Standard,
        "aggressive" => BbrProfile::Aggressive,
        other => panic!("unknown profile {other}"),
    }
}

/// Replays one run, returning how many snapshots matched.
fn replay(run: &Value, fields: &[&str]) -> usize {
    let name = format!(
        "{}/{}",
        run["profile"].as_str().unwrap(),
        run["name"].as_str().unwrap()
    );
    let steps = run["steps"].as_array().expect("steps");
    // What Go's global math/rand source yielded, in order.
    let draws: VecDeque<u32> = run["draws"]
        .as_array()
        .expect("draws")
        .iter()
        .map(|draw| u32::try_from(number(draw)).expect("a draw below 10,000"))
        .collect();
    let mut sender = BbrSender::new(
        CLOCK_START,
        number(&run["datagram"]),
        profile(run["profile"].as_str().unwrap()),
    );
    sender.set_gain_cycle_draw(GainCycleDraw::Scripted(draws));
    let mut checked = 0;
    for (index, step) in steps.iter().enumerate() {
        let (expected, full) = match step[0].as_str().expect("a step kind") {
            "s" => {
                sender.on_packet_sent(
                    CLOCK_START + number(&step[1]),
                    number(&step[2]),
                    number(&step[3]),
                    number(&step[4]),
                    number(&step[5]) == 1,
                );
                continue;
            }
            "r" => {
                sender.on_rtt_sample(number(&step[1]));
                continue;
            }
            "e" => {
                let acked: Vec<AckedPacket> = packets(&step[3])
                    .into_iter()
                    .map(|(packet_number, bytes_acked)| AckedPacket {
                        packet_number,
                        bytes_acked,
                    })
                    .collect();
                let lost: Vec<LostPacket> = packets(&step[4])
                    .into_iter()
                    .map(|(packet_number, bytes_lost)| LostPacket {
                        packet_number,
                        bytes_lost,
                    })
                    .collect();
                sender.on_congestion_event(
                    number(&step[1]),
                    CLOCK_START + number(&step[2]),
                    &acked,
                    &lost,
                );
                (&step[5], step.get(6))
            }
            "m" => {
                sender.set_max_datagram_size(number(&step[1]));
                (&step[2], step.get(3))
            }
            other => panic!("{name}: unknown step {other}"),
        };
        let values = state(&sender);
        assert_eq!(values.len(), fields.len(), "the oracle's state layout");
        if let Some(full) = full {
            let go: Vec<String> = full
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.to_string())
                .collect();
            let differences: Vec<String> = fields
                .iter()
                .zip(go.iter().zip(&values))
                .filter(|(_, (go, port))| go != port)
                .map(|(field, (go, port))| format!("{field}: Go {go}, port {port}"))
                .collect();
            assert!(
                differences.is_empty(),
                "{name}, step {index} {step}: {differences:?}"
            );
        }
        assert_eq!(
            Some(digest(&values).as_str()),
            expected.as_str(),
            "{name}, step {index} {step}: the port's state differs from Xray's:\n{}",
            fields
                .iter()
                .zip(&values)
                .map(|(field, value)| format!("{field}={value}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        checked += 1;
    }
    checked
}

#[test]
fn the_port_reaches_xrays_state_after_every_recorded_call() {
    let committed = fixture();
    let trace = match std::env::var_os("XRAY_BBR_TRACE") {
        Some(fresh) => {
            let fresh = std::fs::read(fresh).expect("the regenerated trace");
            assert!(
                fresh == committed,
                "the pinned Xray-core no longer produces the committed trace"
            );
            fresh
        }
        None => committed,
    };
    let trace: Value = serde_json::from_slice(&trace).expect("JSON");
    let fields: Vec<&str> = trace["state"].as_str().unwrap().split(',').collect();
    let runs = trace["runs"].as_array().unwrap();
    assert_eq!(runs.len(), 15, "five paths for each of three profiles");
    let mut checked = 0;
    for run in runs {
        checked += replay(run, &fields);
    }
    assert!(checked > 4000, "{checked} snapshots");
}

#[test]
fn the_digest_is_go_fnv1a_in_hex() {
    // FNV-1a 64 of the empty string and of "a".
    assert_eq!(digest(&[]), "cbf29ce484222325");
    assert_eq!(digest(&["a".to_owned()]), "af63dc4c8601ec8c");
}
