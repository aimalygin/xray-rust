use std::{env, path::Path, process::Command};

const XRAY_CORE_REFERENCE_REVISION: &str = "5ca6f4b7d4dc20a881d4330e498892697627ec0c";

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
    let checkout = go_mod.parent().expect("go.mod has a checkout parent");
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(checkout)
        .output()
        .expect("read Xray-core oracle revision");
    assert!(
        output.status.success(),
        "git rev-parse failed for Xray-core"
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        XRAY_CORE_REFERENCE_REVISION,
        "Xray-core oracle checkout is not the pinned v26.7.28 revision"
    );
}
