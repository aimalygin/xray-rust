use xray_config::parse_xray_json;
use xray_core_rs::{Core, CoreState};

#[tokio::test]
async fn core_starts_and_stops_from_config() {
    let raw = include_str!("../../../tests/fixtures/configs/vless_reality_vision.json");
    let parsed = parse_xray_json(raw).unwrap();
    let mut core = Core::new(parsed.config).unwrap();

    assert_eq!(core.state(), CoreState::Created);
    core.start().await.unwrap();
    assert_eq!(core.state(), CoreState::Running);
    core.stop().await.unwrap();
    assert_eq!(core.state(), CoreState::Stopped);
}
