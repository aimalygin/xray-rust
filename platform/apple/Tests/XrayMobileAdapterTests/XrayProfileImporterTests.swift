import Foundation
import XCTest
import XrayAppleShared
@testable import XrayMobileAdapter

final class XrayProfileImporterTests: XCTestCase {
    func testNativeSocksImportPreservesCredentialsAndPassesMobilePreflight() throws {
        let profile = try XrayProfileImporter.profile(from: fixture("socks.txt"), format: .socks)
        XCTAssertEqual(profile.name, "Test ✓")
        XCTAssertEqual(profile.serverAddress, "Socks.Example.")
        XCTAssertTrue(XrayCore.ffiInfo.supportsProfileImport(.socks))
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any])
        let settings = try XCTUnwrap((root["outbounds"] as? [[String: Any]])?.first?["settings"] as? [String: Any])
        XCTAssertEqual(settings["user"] as? String, "synthetic:user")
        XCTAssertEqual(settings["pass"] as? String, "p@ss:+✓")
        XCTAssertFalse(String(reflecting: profile).contains("synthetic"))
        try XrayMobileDNSPreflight.validate(profile.configJSON)
        _ = try XrayCore(configJSON: profile.configJSON)
        for text in ["socks://c3ludGhldGljOnBhc3M=@[2001:db8::7]:1080", "socks5://Og==@socks.example:1080"] {
            let imported = try XrayProfileImporter.profile(from: text, format: .socks)
            try XrayMobileDNSPreflight.validate(imported.configJSON)
            _ = try XrayCore(configJSON: imported.configJSON)
        }
        for text in ["socks://synthetic-secret:@socks.example:1080", "socks5://synthetic-secret:p@socks.example:1080?security=tls"] {
            XCTAssertThrowsError(try XrayProfileImporter.profile(from: text, format: .socks)) {
                XCTAssertFalse(String(reflecting: $0).contains("synthetic-secret"))
            }
        }
    }

    func testHttpImportRequiresItsOwnCapabilityAndMinorBeforeNative() throws {
        XCTAssertEqual(XrayFFICapabilities.httpProfileImport.rawValue, 1 << 27)
        let caps: XrayFFICapabilities = [.profileImport, .httpProfileImport]
        XCTAssertTrue(XrayFFIInfo(version: .init(major: 1, minor: 14), capabilities: caps).supportsProfileImport(.http))
        for info in [
            XrayFFIInfo(version: .init(major: 1, minor: 13), capabilities: caps),
            XrayFFIInfo(version: .init(major: 2, minor: 14), capabilities: caps),
            XrayFFIInfo(version: .init(major: 1, minor: 14), capabilities: [.profileImport]),
            XrayFFIInfo(version: .init(major: 1, minor: 14), capabilities: [.httpProfileImport]),
        ] {
            XCTAssertThrowsError(try XrayProfileImporter.importProfile(text: "secret", format: .http,
                name: nil, dnsServers: [], info: info, nativeImport: { _ in
                    XCTFail("unavailable HTTP import invoked native code"); return Data()
                })) { XCTAssertEqual($0 as? XrayProfileImportError, .unavailable) }
        }
    }

    func testSocksImportRequiresItsOwnCapabilityAndMinorBeforeNative() throws {
        let caps: XrayFFICapabilities = [.profileImport, .socksProfileImport]
        XCTAssertTrue(XrayFFIInfo(version: .init(major: 1, minor: 13), capabilities: caps).supportsProfileImport(.socks))
        for info in [
            XrayFFIInfo(version: .init(major: 1, minor: 12), capabilities: caps),
            XrayFFIInfo(version: .init(major: 2, minor: 13), capabilities: caps),
            XrayFFIInfo(version: .init(major: 1, minor: 13), capabilities: [.profileImport]),
            XrayFFIInfo(version: .init(major: 1, minor: 13), capabilities: [.socksProfileImport]),
        ] {
            XCTAssertThrowsError(try XrayProfileImporter.importProfile(text: "secret", format: .socks,
                name: nil, dnsServers: [], info: info, nativeImport: { _ in
                    XCTFail("unavailable SOCKS import invoked native code"); return Data()
                })) { XCTAssertEqual($0 as? XrayProfileImportError, .unavailable) }
        }
    }

    func testNativeHttpAndHttpsImportWithSafeTLSAndTCPDNS() throws {
        for (file, tls) in [("http.txt", false), ("https.txt", true)] {
            let profile = try XrayProfileImporter.profile(from: fixture(file), format: .http,
                dnsServers: ["192.0.2.53", "2001:db8::53"])
            XCTAssertEqual(profile.name, "Test ✓")
            XCTAssertEqual(profile.serverAddress, "Proxy.Example.")
            XCTAssertTrue(XrayCore.ffiInfo.supportsProfileImport(.http))
            let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any])
            let proxy = try XCTUnwrap((root["outbounds"] as? [[String: Any]])?.first)
            let settings = try XCTUnwrap(proxy["settings"] as? [String: Any])
            XCTAssertEqual(settings["user"] as? String, "synthetic-user")
            XCTAssertEqual(settings["pass"] as? String, "p@ss:+✓")
            let stream = try XCTUnwrap(proxy["streamSettings"] as? [String: Any])
            XCTAssertEqual(stream["security"] as? String, tls ? "tls" : "none")
            if tls {
                let security = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
                XCTAssertEqual(security["serverName"] as? String, "Proxy.Example.")
                XCTAssertEqual(security["alpn"] as? [String], ["http/1.1"])
                XCTAssertNil(security["allowInsecure"])
            }
            XCTAssertEqual((root["dns"] as? [String: Any])?["servers"] as? [String],
                ["tcp://192.0.2.53:53", "tcp://[2001:db8::53]:53"])
            XCTAssertFalse(String(reflecting: profile).contains("synthetic"))
            try XrayMobileDNSPreflight.validate(profile.configJSON)
            _ = try XrayCore(configJSON: profile.configJSON)
        }
        for text in ["http://proxy.example", "https://[2001:db8::7]", "https://synthetic@proxy.example"] {
            let profile = try XrayProfileImporter.profile(from: text, format: .http)
            try XrayMobileDNSPreflight.validate(profile.configJSON)
            _ = try XrayCore(configJSON: profile.configJSON)
        }
        for text in ["http://:synthetic-secret@proxy.example", "https://synthetic-secret:p@proxy.example?allowInsecure=1"] {
            XCTAssertThrowsError(try XrayProfileImporter.profile(from: text, format: .http)) {
                XCTAssertFalse(String(reflecting: $0).contains("synthetic-secret"))
            }
        }
    }

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

    func testNativeTrojanImportPreservesCredentialsAndPassesMobilePreflight() throws {
        let profile = try XrayProfileImporter.profile(from: "trojan://synthetic%3Apass+word@trojan.example?type=ws&path=%2Ftrojan#Test%20%E2%9C%93", format: .trojan)
        XCTAssertEqual(profile.name, "Test ✓")
        XCTAssertEqual(profile.serverAddress, "trojan.example")
        XCTAssertTrue(XrayCore.ffiInfo.supportsProfileImport(.trojan))
        XCTAssertTrue(profile.configJSON.contains("synthetic:pass+word"))
        XCTAssertFalse(String(reflecting: profile).contains("synthetic"))
        try XrayMobileDNSPreflight.validate(profile.configJSON)
        _ = try XrayCore(configJSON: profile.configJSON)
        let old = XrayFFIInfo(version: .init(major: 1, minor: 7), capabilities: [.profileImport, .hysteria2Outbound])
        XCTAssertFalse(old.supportsProfileImport(.trojan))
    }

    func testNativeVmessImportPreservesCredentialsAndPassesMobilePreflight() throws {
        let profile = try XrayProfileImporter.profile(from: "vmess://00112233-4455-6677-8899-aabbccddeeff@vmess.example?type=ws&path=%2Fvmess#Test%20%E2%9C%93", format: .vmess)
        XCTAssertEqual(profile.name, "Test ✓")
        XCTAssertEqual(profile.serverAddress, "vmess.example")
        XCTAssertTrue(XrayCore.ffiInfo.supportsProfileImport(.vmess))
        XCTAssertTrue(profile.configJSON.contains("00112233-4455-6677-8899-aabbccddeeff"))
        XCTAssertFalse(String(reflecting: profile).contains("00112233"))
        try XrayMobileDNSPreflight.validate(profile.configJSON)
        _ = try XrayCore(configJSON: profile.configJSON)
        let old = XrayFFIInfo(version: .init(major: 1, minor: 7), capabilities: [.profileImport, .hysteria2Outbound])
        XCTAssertFalse(old.supportsProfileImport(.vmess))
    }

    func testNativeShadowsocks2022ImportPreservesCredentialsAndPassesMobilePreflight() throws {
        let profile = try XrayProfileImporter.profile(from: "ss://2022-blake3-aes-128-gcm:AQEBAQEBAQEBAQEBAQEBAQ==@ss2022.example:8388#Test%20%E2%9C%93", format: .shadowsocks2022)
        XCTAssertEqual(profile.name, "Test ✓")
        XCTAssertEqual(profile.serverAddress, "ss2022.example")
        XCTAssertTrue(XrayCore.ffiInfo.supportsProfileImport(.shadowsocks2022))
        XCTAssertTrue(profile.configJSON.contains("AQEBAQEBAQEBAQEBAQEBAQ=="))
        XCTAssertFalse(String(reflecting: profile).contains("AQEB"))
        try XrayMobileDNSPreflight.validate(profile.configJSON)
        _ = try XrayCore(configJSON: profile.configJSON)
        let old = XrayFFIInfo(version: .init(major: 1, minor: 7), capabilities: [.profileImport, .hysteria2Outbound])
        XCTAssertFalse(old.supportsProfileImport(.shadowsocks2022))
    }

    func testNativeWireguardImportPreservesPeersAndRealDNS() throws {
        let profile = try XrayProfileImporter.profile(from: fixture("wireguard.conf"), format: .wireguard, name: "Tunnel 🔑")
        XCTAssertEqual(profile.name, "Tunnel 🔑")
        XCTAssertEqual(profile.serverAddress, "First.Example.")
        XCTAssertTrue(profile.configJSON.contains("preSharedKey"))
        XCTAssertTrue(profile.configJSON.contains("198.51.100.7/32"))
        XCTAssertFalse(profile.configJSON.contains("fakeIp"))
        let root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any])
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let settings = try XCTUnwrap(outbounds[1]["settings"] as? [String: Any])
        XCTAssertEqual(settings["remoteDNS"] as? [String], ["192.0.2.53", "2001:db8::53"])
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
