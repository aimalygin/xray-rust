use super::*;
use crate::sudoku::SudokuConfig;

fn tables(ascii: &str, custom: &[&str]) -> Arc<Vec<Table>> {
    SudokuConfig {
        password: "synthetic".into(),
        ascii: ascii.into(),
        custom_tables: custom.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
    .tables()
    .unwrap()
}

#[test]
fn classic_encoding_round_trips_with_padding_and_rotating_tables() {
    let plain: Vec<u8> = (0..=255).chain(b"hello sudoku".iter().copied()).collect();
    for (ascii, custom) in [
        ("", &[][..]),
        ("ascii", &[]),
        ("", &["xppvvvvx", "vvxpvxpv"]),
    ] {
        let tables = tables(ascii, custom);
        for padding in [(0, 0), (30, 60), (100, 100)] {
            let mut encoder = Encoder::new(tables.clone(), padding);
            let mut wire = Vec::new();
            // Split across writes, and decoded in arbitrary chunks.
            encoder.encode(&plain[..100], &mut wire);
            encoder.encode(&plain[100..], &mut wire);
            if padding == (0, 0) {
                assert_eq!(wire.len(), plain.len() * 4);
            }
            let mut decoder = Decoder::default();
            let mut out = Vec::new();
            for chunk in wire.chunks(7) {
                decoder.decode(&tables, chunk, &mut out).unwrap();
            }
            assert!(!decoder.partial());
            assert_eq!(out, plain, "{ascii} {custom:?} {padding:?}");
        }
    }
}

#[test]
fn packed_encoding_round_trips_and_pad_markers_end_partial_groups() {
    for (ascii, custom) in [
        ("", &[][..]),
        ("ascii", &[]),
        ("", &["xppvvvvx", "vvxpvxpv"]),
    ] {
        let tables = tables(ascii, custom);
        for padding in [(0, 0), (50, 50)] {
            let mut encoder = PackedEncoder::new(&tables, padding);
            let mut wire = Vec::new();
            // Writes of 1, 2 and 3 bytes leave 2, 4 and no bits over.
            for write in [&b"a"[..], b"bc", b"def", &[0xff; 100]] {
                encoder.encode(write, &mut wire);
            }
            let mut decoder = PackedDecoder::default();
            let mut out = Vec::new();
            for chunk in wire.chunks(5) {
                decoder.decode(&tables, chunk, &mut out).unwrap();
            }
            let mut expected = b"abcdef".to_vec();
            expected.extend([0xff; 100]);
            assert_eq!(out, expected, "{ascii} {custom:?} {padding:?}");
        }
    }
}

#[test]
fn a_tuple_no_table_knows_fails() {
    let tables = tables("", &[]);
    let hint = tables[0].layout.encode_group(0);
    let mut decoder = Decoder::default();
    let mut out = Vec::new();
    // Four copies of one clue are no grid's clue set.
    assert!(decoder
        .decode(&tables, &[hint, hint, hint, hint], &mut out)
        .is_err());
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// What Xray-core's own mask wrote (`tools/sudoku-oracle`), or a fresh run
/// of it named by `XRAY_SUDOKU_VECTORS`: its encoding is random, so only a
/// decoder with the same tables reads every run.
#[test]
fn decodes_what_xray_core_encodes() {
    let text = match std::env::var("XRAY_SUDOKU_VECTORS") {
        Ok(path) => std::fs::read_to_string(path).unwrap(),
        Err(_) => include_str!("../../../../../tests/fixtures/sudoku/vectors.json").to_owned(),
    };
    let cases: serde_json::Value = serde_json::from_str(&text).unwrap();
    for case in cases.as_array().unwrap() {
        let raw = &case["config"];
        let strings = |key: &str| -> Vec<String> {
            raw[key]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().unwrap().to_owned())
                        .collect()
                })
                .unwrap_or_default()
        };
        let config = SudokuConfig {
            password: raw["password"].as_str().unwrap_or("").into(),
            ascii: raw["ascii"].as_str().unwrap_or("").into(),
            custom_table: raw["customTable"].as_str().unwrap_or("").into(),
            custom_tables: strings("customTables"),
            padding_min: raw["paddingMin"].as_u64().unwrap_or(0) as u32,
            padding_max: raw["paddingMax"].as_u64().unwrap_or(0) as u32,
        };
        let tables = config.tables().unwrap();
        let name = case["name"].as_str().unwrap();
        for exchange in case["classic"].as_array().unwrap() {
            let mut out = Vec::new();
            let mut decoder = Decoder::default();
            decoder
                .decode(
                    &tables,
                    &unhex(exchange["wire"].as_str().unwrap()),
                    &mut out,
                )
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!decoder.partial(), "{name}");
            assert_eq!(out, unhex(exchange["plain"].as_str().unwrap()), "{name}");
        }
        let packed = &case["packed"];
        let expected: Vec<u8> = packed["writes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|write| unhex(write.as_str().unwrap()))
            .collect();
        let mut out = Vec::new();
        PackedDecoder::default()
            .decode(&tables, &unhex(packed["wire"].as_str().unwrap()), &mut out)
            .unwrap();
        assert_eq!(out, expected, "{name} packed");
    }
}
