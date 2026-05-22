use tokio::time::{timeout, Duration};

#[tokio::test]
#[ignore = "requires local Go toolchain, Xray-core checkout, and loopback process execution"]
async fn rust_socks_client_reaches_echo_server_through_local_xray_vless_tcp() {
    timeout(Duration::from_secs(120), run_local_xray_vless_interop())
        .await
        .unwrap();
}

async fn run_local_xray_vless_interop() {
    let xray_checkout = resolve_xray_checkout();
    let _xray = start_xray_vless_server(&xray_checkout).await;
}
