//! The `sudoku` finalmask, as Xray-core v26.10.31's `Sudoku.Build` reads it.
use super::*;
use crate::{go_lowercase, SudokuMask, UdpSudoku};

impl Parser<'_> {
    /// The settings of a `sudoku` mask, TCP or UDP. Xray-core leaves an
    /// unknown `ascii` mode or a malformed custom table to fail every dial;
    /// here they fail the configuration.
    pub(super) fn parse_sudoku(&mut self, settings: &Value, path: &str) -> Option<SudokuMask> {
        if settings.is_null() {
            return Some(SudokuMask::default());
        }
        if !settings.is_object() {
            self.error(path, "sudoku settings must be an object or null");
            return None;
        }
        self.reject_unknown_fields(settings, path, &surface::SUDOKU_MASK);
        let string = |parser: &mut Self, key: &str| {
            parser
                .nullable_string_at(settings, key, format!("{path}.{key}"))
                .map(str::to_owned)
        };
        let password = string(self, "password");
        let ascii = string(self, "ascii");
        let custom_table = string(self, "customTable");
        let legacy_custom_table = string(self, "custom_table");
        let custom_tables = self.sudoku_tables(settings, "customTables", path);
        let legacy_custom_tables = self.sudoku_tables(settings, "custom_tables", path);
        let padding_min =
            self.nullable_u32_at(settings, "paddingMin", format!("{path}.paddingMin"));
        let legacy_padding_min =
            self.nullable_u32_at(settings, "padding_min", format!("{path}.padding_min"));
        let padding_max =
            self.nullable_u32_at(settings, "paddingMax", format!("{path}.paddingMax"));
        let legacy_padding_max =
            self.nullable_u32_at(settings, "padding_max", format!("{path}.padding_max"));
        // The camelCase field wins unless it is empty or zero, as in Build.
        let either = |value: String, legacy: String| if value.is_empty() { legacy } else { value };
        let either_list =
            |value: Vec<String>, legacy| if value.is_empty() { legacy } else { value };
        let either_u32 = |value: u32, legacy| if value == 0 { legacy } else { value };
        let mask = SudokuMask {
            password: password?.into(),
            ascii: ascii?,
            custom_table: either(custom_table?, legacy_custom_table?),
            custom_tables: either_list(custom_tables?, legacy_custom_tables?),
            padding_min: either_u32(padding_min?, legacy_padding_min?),
            padding_max: either_u32(padding_max?, legacy_padding_max?),
        };
        let mut valid = true;
        let ascii_mode = match mask.ascii.trim().to_lowercase().as_str() {
            "" | "entropy" | "prefer_entropy" => false,
            "ascii" | "prefer_ascii" => true,
            _ => {
                self.error(
                    format!("{path}.ascii"),
                    "sudoku ascii is entropy, prefer_entropy, ascii or prefer_ascii",
                );
                valid = false;
                false
            }
        };
        // ASCII mode never reads the custom tables.
        if !ascii_mode {
            let tables: Vec<&str> = if mask.custom_tables.is_empty() {
                vec![&mask.custom_table]
            } else {
                mask.custom_tables.iter().map(String::as_str).collect()
            };
            for table in tables {
                let cleaned = table.trim().to_lowercase().replace(' ', "");
                let count = |wanted| cleaned.chars().filter(|&c| c == wanted).count();
                if !cleaned.is_empty()
                    && (cleaned.len() != 8 || count('x') != 2 || count('p') != 2 || count('v') != 4)
                {
                    self.error(
                        format!("{path}.customTable"),
                        "a sudoku custom table is 8 characters: 2 x, 2 p and 4 v",
                    );
                    valid = false;
                }
            }
        }
        valid.then_some(mask)
    }

    /// A list of custom tables: null or an array of strings, a null entry
    /// read as empty, as Go reads `[]string`.
    fn sudoku_tables(&mut self, settings: &Value, key: &str, path: &str) -> Option<Vec<String>> {
        match settings.get(key) {
            None | Some(Value::Null) => Some(Vec::new()),
            Some(Value::Array(items)) => items
                .iter()
                .enumerate()
                .map(|(i, item)| match item {
                    Value::Null => Some(String::new()),
                    Value::String(table) => Some(table.clone()),
                    _ => {
                        self.error(format!("{path}.{key}[{i}]"), "must be a string");
                        None
                    }
                })
                .collect::<Vec<_>>()
                .into_iter()
                .collect(),
            Some(_) => {
                self.error(
                    format!("{path}.{key}"),
                    "must be an array of strings or null",
                );
                None
            }
        }
    }

    /// The `sudoku` entry of `finalmask.udp`, with its place among a QUIC
    /// carrier's other masks. The stream checks its carrier.
    pub(super) fn parse_udp_sudoku(
        &mut self,
        stream: Option<&Value>,
        index: usize,
    ) -> Option<UdpSudoku> {
        let masks = stream?.pointer("/finalmask/udp")?.as_array()?;
        let position = |name: &str| {
            masks.iter().position(|mask| {
                mask.get("type")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| go_lowercase(kind) == name)
            })
        };
        let i = position("sudoku")?;
        let path = format!("$.outbounds[{index}].streamSettings.finalmask.udp[{i}].settings");
        let mask = self.parse_sudoku(masks[i].get("settings").unwrap_or(&Value::Null), &path)?;
        let before = |name: &str| position(name).is_some_and(|other| i < other);
        Some(UdpSudoku {
            mask,
            before_salamander: before("salamander"),
            before_noise: before("noise"),
            before_header_custom: before("header-custom"),
        })
    }
}
