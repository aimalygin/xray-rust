import Foundation
import XCTest
import XrayAppleShared
@testable import XrayMobileAdapter

final class XrayProfileImporterTests: XCTestCase {
    private func fixture(_ name: String) throws -> String {
        var root = URL(fileURLWithPath: #filePath).resolvingSymlinksInPath()
        for _ in 0..<5 { root.deleteLastPathComponent() }
        return try String(contentsOf: root.appendingPathComponent("tests/fixtures/profile-import/\(name)"), encoding: .utf8)
    }

    func testNativeHysteriaImportPreservesUnicodeAndPassesMobilePreflight() throws {
        let profile = try XrayProfileImporter.profile(from: fixture("hysteria2.txt"), format: .hysteria2)
        XCTAssertEqual(profile.name, "Test ✓")
        XCTAssertEqual(profile.serverAddress, "Server.Example.")
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any])
        let proxy = try XCTUnwrap((root["outbounds"] as? [[String: Any]])?.first)
        let stream = try XCTUnwrap(proxy["streamSettings"] as? [String: Any])
        XCTAssertEqual((stream["hysteriaSettings"] as? [String: Any])?["auth"] as? String, "user:p@ss:+✓")
        try XrayMobileDNSPreflight.validate(profile.configJSON)
        _ = try XrayCore(configJSON: profile.configJSON)
        XCTAssertFalse(String(reflecting: profile).contains("user:"))
        XCTAssertFalse(String(describing: profile).contains("Server"))
        let client = profile.clientProfile(providerBundleIdentifier: "example.test.tunnel")
        XCTAssertEqual(client.configJSON, profile.configJSON)
        XCTAssertEqual(client.providerBundleIdentifier, "example.test.tunnel")
    }

    func testNativeWireguardImportPreservesPeersAndRealDNS() throws {
        let profile = try XrayProfileImporter.profile(from: fixture("wireguard.conf"), format: .wireguard, name: "Tunnel 🔑")
        XCTAssertEqual(profile.name, "Tunnel 🔑")
        XCTAssertEqual(profile.serverAddress, "First.Example.")
        XCTAssertTrue(profile.configJSON.contains("preSharedKey"))
        XCTAssertTrue(profile.configJSON.contains("198.51.100.7/32"))
        XCTAssertFalse(profile.configJSON.contains("fakeIp"))
        try XrayMobileDNSPreflight.validate(profile.configJSON)
        _ = try XrayCore(configJSON: profile.configJSON)
    }

    func testNativeErrorsNeverQuoteCredentialsAndDNSCanBeSuppliedExplicitly() throws {
        for text in ["hy2://secret@server.example?insecure=1", "hy2://secret%FF@server.example"] {
            XCTAssertThrowsError(try XrayProfileImporter.profile(from: text, format: .hysteria2)) {
                XCTAssertFalse(String(reflecting: $0).contains("secret"))
            }
        }
        let text = try fixture("wireguard.conf").replacingOccurrences(of: "DNS = 192.0.2.53, 2001:db8::53\n", with: "")
        XCTAssertThrowsError(try XrayProfileImporter.profile(from: text, format: .wireguard))
        let profile = try XrayProfileImporter.profile(from: text, format: .wireguard, dnsServers: ["192.0.2.54"])
        XCTAssertTrue(profile.configJSON.contains("192.0.2.54"))
    }

    func testCapabilitiesAreCheckedBeforeCallingNativeImport() throws {
        let all: XrayFFICapabilities = [.profileImport, .hysteria2Outbound, .wireguardOutbound]
        for info in [
            XrayFFIInfo(version: .init(major: 1, minor: 4), capabilities: all),
            XrayFFIInfo(version: .init(major: 2, minor: 5), capabilities: all),
            XrayFFIInfo(version: .init(major: 1, minor: 5), capabilities: [.hysteria2Outbound]),
            XrayFFIInfo(version: .init(major: 1, minor: 5), capabilities: [.profileImport]),
        ] {
            XCTAssertThrowsError(try XrayProfileImporter.importProfile(text: "secret", format: .hysteria2,
                name: nil, dnsServers: [], info: info, nativeImport: { _ in
                    XCTFail("unsupported capability invoked native import"); return Data()
                })) { XCTAssertEqual($0 as? XrayProfileImportError, .unavailable) }
        }
        XCTAssertTrue(XrayCore.ffiInfo.supportsProfileImport(.hysteria2))
        XCTAssertTrue(XrayCore.ffiInfo.supportsProfileImport(.wireguard))
        let hysteriaOnly = XrayFFIInfo(version: .init(major: 1, minor: 6), capabilities: [.profileImport, .hysteria2Outbound])
        XCTAssertTrue(hysteriaOnly.supportsProfileImport(.hysteria2))
        XCTAssertFalse(hysteriaOnly.supportsProfileImport(.wireguard))
    }

    func testOversizedInputAndMalformedNativeResponsesAreRedacted() throws {
        XCTAssertThrowsError(try XrayProfileImporter.importProfile(text: String(repeating: "🔑", count: 17000),
            format: .hysteria2, name: nil, dnsServers: [], info: XrayCore.ffiInfo, nativeImport: { _ in
                XCTFail("oversized input invoked native import"); return Data()
            })) { XCTAssertEqual($0 as? XrayProfileImportError, .invalidInput) }
        for response in [Data("{secret".utf8), Data([0xff]),
            Data(#"{"schemaVersion":2,"name":"secret","serverAddress":"secret","configJSON":"secret"}"#.utf8)] {
            XCTAssertThrowsError(try XrayProfileImporter.importProfile(text: "secret", format: .hysteria2,
                name: nil, dnsServers: [], info: XrayCore.ffiInfo, nativeImport: { _ in response })) {
                XCTAssertEqual($0 as? XrayProfileImportError, .invalidResult)
                XCTAssertFalse(String(reflecting: $0).contains("secret"))
            }
        }
    }
}
