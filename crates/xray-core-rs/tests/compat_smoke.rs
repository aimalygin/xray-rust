use std::{env, path::Path};

#[test]
fn compat_smoke_xray_core_reference_checkout_is_available() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should be under workspace crates directory");
    let go_mod = workspace_root.join("Xray-core/go.mod");
    let reality = workspace_root.join("Xray-core/transport/internet/reality/reality.go");

    if env::var_os("XRAY_RUST_REQUIRE_XRAY_CORE").is_none() && !go_mod.exists() {
        eprintln!(
            "skipping Xray-core oracle smoke; set XRAY_RUST_REQUIRE_XRAY_CORE=1 to require it"
        );
        return;
    }

    assert!(go_mod.exists(), "missing Xray-core/go.mod oracle checkout");
    assert!(
        reality.exists(),
        "missing Xray-core/transport/internet/reality/reality.go oracle file"
    );
}
