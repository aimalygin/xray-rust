#[test]
fn workspace_exports_version() {
    assert_eq!(xray_core_rs::version(), env!("CARGO_PKG_VERSION"));
}
