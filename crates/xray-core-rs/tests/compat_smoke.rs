use std::path::Path;

#[test]
fn xray_core_reference_checkout_is_available() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crate should be under workspace crates directory");

    assert!(workspace_root.join("Xray-core/go.mod").exists());
    assert!(workspace_root
        .join("Xray-core/transport/internet/reality/reality.go")
        .exists());
}
