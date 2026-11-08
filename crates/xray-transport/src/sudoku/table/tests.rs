use super::*;

#[test]
fn there_are_288_grids_each_with_its_own_clue_sets() {
    let grids = all_grids();
    assert_eq!(grids.len(), 288);
    assert_eq!(hint_positions().len(), 1820);
    let patterns = base_patterns();
    assert_eq!(patterns.len(), 288);
    assert!(patterns.iter().all(|sets| !sets.is_empty()));
}

#[test]
fn layouts_round_trip_every_group_and_keep_padding_off_clues() {
    for layout in [
        Layout::ascii(),
        Layout::entropy(),
        Layout::custom("xppvvvvx").unwrap(),
        Layout::custom("vxvpvxpv").unwrap(),
    ] {
        for group in 0..64 {
            let byte = layout.encode_group(group);
            assert!(layout.is_hint(byte), "{layout:?} {group}");
            assert_eq!(layout.decode_group(byte), Some(group), "{layout:?}");
        }
        assert!(!layout.padding_pool.is_empty());
        for &pad in &layout.padding_pool {
            assert!(!layout.is_hint(pad), "{layout:?} pads with a clue {pad:#x}");
        }
        assert!(layout.padding_pool.contains(&layout.pad_marker));
    }
    // ASCII never sends DEL, and its clues and padding stay printable.
    let ascii = Layout::ascii();
    assert_eq!(ascii.encode_group(0x3f), b'\n');
    assert!((0..64).all(|g| ascii.encode_group(g) != 0x7f));
}

#[test]
fn settings_normalize_as_go_does() {
    assert!(!ascii_mode(" Prefer_Entropy ").unwrap());
    assert!(ascii_mode("ASCII").unwrap());
    assert!(ascii_mode("text").is_err());
    assert_eq!(normalize_custom_table(" XP PV VV VX ").unwrap(), "xppvvvvx");
    for bad in ["xxppvvvvx", "xppvvvvy", "xxxpvvvv"] {
        assert!(normalize_custom_table(bad).is_err(), "{bad}");
    }
    let config = SudokuConfig {
        custom_table: "unused".into(),
        custom_tables: vec!["xppvvvvx".into(), " XPPVVVVX".into(), "".into()],
        ..Default::default()
    };
    assert_eq!(config.patterns(false).unwrap(), ["xppvvvvx", ""]);
    assert_eq!(config.patterns(true).unwrap(), [""]);
    assert_eq!(
        SudokuConfig {
            padding_min: 150,
            padding_max: 20,
            ..Default::default()
        }
        .padding(),
        (100, 100)
    );
}

#[test]
fn every_byte_decodes_from_each_of_its_clue_sets() {
    let config = SudokuConfig {
        password: "synthetic".into(),
        custom_tables: vec!["xppvvvvx".into(), "".into()],
        ..Default::default()
    };
    let tables = config.tables().unwrap();
    assert_eq!(tables.len(), 2);
    for table in tables.iter() {
        for byte in 0..=255u8 {
            for hints in &table.encode[usize::from(byte)] {
                let mut reversed = *hints;
                reversed.reverse();
                assert_eq!(table.decode(reversed), Some(byte));
            }
        }
    }
    // Cached: the same tables come back.
    assert!(Arc::ptr_eq(&tables, &config.tables().unwrap()));
}
