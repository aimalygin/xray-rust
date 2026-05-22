use xray_transport::{
    reality::validate_reality_client_hello_metadata,
    reality_connector::{RealityClientHelloRequest, RealityTlsSessionProvider},
    RustlsRealityTlsSessionProvider,
};

#[test]
fn rustls_reality_provider_prepares_valid_zero_session_clienthello() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let session = provider
        .create_session(RealityClientHelloRequest {
            server_name: "www.example.com",
            fingerprint: "chrome",
        })
        .expect("chrome REALITY session should be created");
    let prepared = session
        .prepared_client_hello()
        .expect("prepared ClientHello should be available");
    let validation = validate_reality_client_hello_metadata(&prepared)
        .expect("prepared ClientHello should satisfy REALITY metadata contract");

    assert_eq!(prepared.fingerprint, "chrome");
    assert_eq!(prepared.session_id_offset, validation.session_id_offset);
    assert_eq!(
        &prepared.raw_client_hello[prepared.session_id_offset..prepared.session_id_offset + 32],
        &[0u8; 32]
    );
}

#[test]
fn rustls_reality_provider_rejects_non_chrome_fingerprint() {
    let provider = RustlsRealityTlsSessionProvider::new();

    let result = provider.create_session(RealityClientHelloRequest {
        server_name: "www.example.com",
        fingerprint: "firefox",
    });

    assert!(matches!(
        result,
        Err(xray_transport::reality::RealityError::UnsupportedRealityFingerprint(fingerprint))
            if fingerprint == "firefox"
    ));
}
