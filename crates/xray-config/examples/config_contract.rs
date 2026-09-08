fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&xray_config::tooling::configuration_contract()).unwrap()
    );
}
