import XCTest
@testable import XrayAppleShared

final class XrayMobileDNSPreflightTests: XCTestCase {
    func testRejectsConfigWithoutAnyTunnelDNSSource() {
        assertError(.unavailable, configJSON: #"{"inbounds":[],"outbounds":[]}"#)
    }

    func testAcceptsConfiguredServer() {
        XCTAssertNoThrow(
            try XrayMobileDNSPreflight.validate(
                #"{"dns":{"servers":["1.1.1.1"]}}"#
            )
        )
    }

    func testAcceptsCustomExplicitDNSWithoutFakeIP() {
        XCTAssertNoThrow(
            try XrayMobileDNSPreflight.validate(
                #"{"inbounds":[],"outbounds":[]}"#,
                explicitDNS: .custom
            )
        )
    }

    func testRejectsInvalidExplicitDNS() {
        assertError(
            .unavailable,
            configJSON: #"{"dns":{"servers":["1.1.1.1"]}}"#,
            explicitDNS: .invalid
        )
    }

    func testRejectsCombiningExplicitDNSWithFakeIP() {
        assertError(
            .unavailable,
            configJSON: fakeIPConfig(),
            explicitDNS: .custom
        )
    }

    func testAcceptsPureFakeIPWithProxyDefaultAndIPOnlyFreedomRule() {
        XCTAssertNoThrow(
            try XrayMobileDNSPreflight.validate(
                fakeIPConfig(
                    rules: [[
                        "type": "field",
                        "inboundTag": ["tun-in"],
                        "ip": ["10.0.0.0/8"],
                        "outboundTag": "direct",
                    ]]
                )
            )
        )
    }

    func testRejectsPureFakeIPWithFreedomDefault() {
        assertError(
            .unsafeFakeIPFreedomRouting,
            configJSON: fakeIPConfig(freedomFirst: true)
        )
    }

    func testRejectsPureFakeIPWithTunDomainFreedomRule() {
        assertError(
            .unsafeFakeIPFreedomRouting,
            configJSON: fakeIPConfig(
                rules: [[
                    "type": "field",
                    "inboundTag": ["tun-in"],
                    "domain": ["geosite:ru"],
                    "outboundTag": "direct",
                ]]
            )
        )
    }

    func testConfiguredServerMakesFakeIPFreedomRoutingSafe() {
        XCTAssertNoThrow(
            try XrayMobileDNSPreflight.validate(
                fakeIPConfig(freedomFirst: true, dnsServers: ["1.1.1.1"])
            )
        )
    }

    func testRejectsEnabledFakeIPUnavailableForIPv6OnlyQueriesEvenWithServer() throws {
        let configJSON = try replacingDNSValue(
            in: fakeIPConfig(dnsServers: [["address": "192.0.2.53"]]),
            key: "queryStrategy",
            value: "UseIPv6"
        )

        assertError(.unavailable, configJSON: configJSON)
    }

    func testRejectsMalformedEnabledFakeIPPoolEvenWithServer() throws {
        let configJSON = try replacingFakeIPValue(
            in: fakeIPConfig(dnsServers: ["1.1.1.1"]),
            key: "ipv4Pool",
            value: "198.19.0.0/33"
        )

        assertError(.unavailable, configJSON: configJSON)
    }

    private func assertError(
        _ expected: XrayMobileDNSPreflightError,
        configJSON: String,
        explicitDNS: XrayMobileExplicitDNSConfiguration = .system,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try XrayMobileDNSPreflight.validate(configJSON, explicitDNS: explicitDNS),
            file: file,
            line: line
        ) { error in
            XCTAssertEqual(
                error as? XrayMobileDNSPreflightError,
                expected,
                file: file,
                line: line
            )
        }
    }

    private func fakeIPConfig(
        freedomFirst: Bool = false,
        rules: [[String: Any]] = [],
        dnsServers: [Any] = []
    ) -> String {
        let proxy: [String: Any] = ["protocol": "vless", "tag": "proxy"]
        let freedom: [String: Any] = ["protocol": "freedom", "tag": "direct"]
        let root: [String: Any] = [
            "dns": [
                "fakeIp": [
                    "enabled": true,
                    "ipv4Pool": "198.19.0.0/16",
                ],
                "servers": dnsServers,
            ],
            "inbounds": [["protocol": "tun", "tag": "tun-in"]],
            "outbounds": freedomFirst ? [freedom, proxy] : [proxy, freedom],
            "routing": ["rules": rules],
        ]
        let data = try! JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private func replacingDNSValue(
        in configJSON: String,
        key: String,
        value: Any
    ) throws -> String {
        var root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        var dns = try XCTUnwrap(root["dns"] as? [String: Any])
        dns[key] = value
        root["dns"] = dns
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private func replacingFakeIPValue(
        in configJSON: String,
        key: String,
        value: Any
    ) throws -> String {
        var root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        var dns = try XCTUnwrap(root["dns"] as? [String: Any])
        var fakeIP = try XCTUnwrap(dns["fakeIp"] as? [String: Any])
        fakeIP[key] = value
        dns["fakeIp"] = fakeIP
        root["dns"] = dns
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }
}
