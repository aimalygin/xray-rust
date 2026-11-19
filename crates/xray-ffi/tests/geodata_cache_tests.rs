//! The geodata cache is process-wide, so this file holds the one test that
//! reads its counters, in a test binary of its own.

use std::ffi::{CStr, CString};
use std::time::Duration;

use xray_config::{geodata_cache_stats, RETAINED_UNUSED_GEODATA_BYTES};
use xray_ffi::{
    xray_core_free, xray_core_load_config_json, xray_core_new,
    xray_core_replace_routing_policy_json, xray_core_set_geodata_search_dir_exclusive,
    xray_error_free, xray_error_message, XrayError, XrayStatus,
};

/// IPv6 CIDRs of a category whose compiled ranges exceed the 4 MiB kept for
/// unused categories: 32 bytes each.
const CIDRS: u64 = 140_000;

fn encode_varint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push(value as u8 | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn length_delimited(tag: u8, body: &[u8], output: &mut Vec<u8>) {
    output.push(tag);
    encode_varint(body.len() as u64, output);
    output.extend_from_slice(body);
}

/// A `geoip.dat` with code `BIG`: every other /64 of 2001:db8::/32, so that
/// no two ranges merge.
fn big_geoip_data() -> Vec<u8> {
    let mut geoip = Vec::new();
    length_delimited(0x0a, b"BIG", &mut geoip);
    for index in 0..CIDRS {
        let network = (0x2001_0db8_u128 << 96) | (u128::from(index * 2) << 64);
        let mut cidr = Vec::new();
        length_delimited(0x0a, &network.to_be_bytes(), &mut cidr);
        cidr.extend_from_slice(&[0x10, 64]);
        length_delimited(0x12, &cidr, &mut geoip);
    }
    let mut data = Vec::new();
    length_delimited(0x0a, &geoip, &mut data);
    data
}

fn take_error(error: &mut *mut XrayError) -> String {
    if error.is_null() {
        return String::new();
    }
    let message = unsafe { CStr::from_ptr(xray_error_message(*error)) }
        .to_string_lossy()
        .into_owned();
    unsafe { xray_error_free(*error) };
    *error = std::ptr::null_mut();
    message
}

#[test]
fn ffi_calls_that_drop_a_configuration_keep_the_cache_within_its_budget() {
    let dir = std::env::temp_dir().join(format!(
        "xray-ffi-geodata-cache-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("geoip.dat"), big_geoip_data()).unwrap();
    // A file that changed within two seconds of being opened is not cached
    // for the process.
    std::thread::sleep(Duration::from_millis(2_100));
    let dir_c = CString::new(dir.to_string_lossy().as_bytes()).unwrap();
    let rule = r#"{"type":"field","ip":["geoip:big"],"outboundTag":"direct"}"#;

    let mut error = std::ptr::null_mut();
    let core = unsafe { xray_core_new(&mut error) };
    assert!(!core.is_null());
    assert_eq!(
        unsafe { xray_core_set_geodata_search_dir_exclusive(core, dir_c.as_ptr(), &mut error) },
        XrayStatus::Ok
    );

    // The second rule fails after the first one compiled the category.
    let failing = CString::new(format!(
        r#"{{"outbounds":[{{"tag":"direct","protocol":"freedom"}}],"routing":{{"rules":[{rule},{{"type":"field","ip":["geoip:missing"],"outboundTag":"direct"}}]}}}}"#
    ))
    .unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, failing.as_ptr(), &mut error) },
        XrayStatus::ConfigError
    );
    assert!(take_error(&mut error).contains("MISSING"));
    let stats = geodata_cache_stats();
    assert_eq!(stats.misses, 1, "the category was compiled and cached");
    assert_eq!(stats.entries, 0, "and released with the failed load");

    // The core keeps the configuration it was loaded with, so the policy
    // that names the category comes with a replacement.
    let config = CString::new(
        r#"{"outbounds":[{"tag":"direct","protocol":"freedom"}],"routing":{"rules":[]}}"#,
    )
    .unwrap();
    assert_eq!(
        unsafe { xray_core_load_config_json(core, config.as_ptr(), &mut error) },
        XrayStatus::Ok,
        "{}",
        take_error(&mut error)
    );
    let replace = |rules: &str, error: &mut *mut XrayError| {
        let policy = CString::new(format!(r#"{{"routing":{{"rules":[{rules}]}}}}"#)).unwrap();
        unsafe { xray_core_replace_routing_policy_json(core, policy.as_ptr(), error) }
    };

    let rejected =
        format!(r#"{rule},{{"type":"field","ip":["geoip:big"],"outboundTag":"missing"}}"#);
    assert_eq!(replace(&rejected, &mut error), XrayStatus::ConfigError);
    assert!(take_error(&mut error).contains("missing"));
    let stats = geodata_cache_stats();
    assert_eq!((stats.misses, stats.hits), (2, 1));
    assert_eq!(
        stats.entries, 0,
        "the rejected policy's category is released"
    );

    assert_eq!(
        replace(rule, &mut error),
        XrayStatus::Ok,
        "{}",
        take_error(&mut error)
    );
    let stats = geodata_cache_stats();
    assert_eq!(stats.entries, 1);
    assert!(stats.referenced_bytes > RETAINED_UNUSED_GEODATA_BYTES);

    assert_eq!(
        replace("", &mut error),
        XrayStatus::Ok,
        "{}",
        take_error(&mut error)
    );
    assert_eq!(
        geodata_cache_stats().entries,
        0,
        "the replaced policy's category is released"
    );

    unsafe { xray_core_free(core) };
    std::fs::remove_dir_all(dir).unwrap();
}
