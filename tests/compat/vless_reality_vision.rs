use std::process::Command;

#[test]
#[ignore = "requires local Go toolchain and completed REALITY network connector"]
fn rust_client_can_connect_to_go_xray_vless_reality_vision_server() {
    let status = Command::new("go")
        .arg("test")
        .arg("./testing/scenarios")
        .arg("-run")
        .arg("TestVlessXtlsVisionReality")
        .current_dir("Xray-core")
        .status()
        .expect("go test should start");

    assert!(status.success());
}
