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

    func testWireguardFakeIPRequiresDestinationDNS() {
        assertError(.unsafeFakeIPWireguardRouting,
                    configJSON: fakeIPConfig().replacingOccurrences(of: "vless", with: "wireguard"))
        XCTAssertNoThrow(try XrayMobileDNSPreflight.validate(
            fakeIPConfig(dnsServers: ["192.0.2.53"]).replacingOccurrences(of: "vless", with: "wireguard")
        ))
        XCTAssertNoThrow(try XrayMobileDNSPreflight.validate(
            fakeIPConfig().replacingOccurrences(of: "vless", with: "hysteria")
        ))
    }

    func testWireguardFakeIPRoutingDistinguishesDomainAndIPOnlyRules() {
        for matchers: [String: Any] in [[:], ["domain": ["domain:example"]],
                                      ["domains": ["domain:example"], "ip": ["192.0.2.0/24"]]] {
            var rule = matchers
            rule["outboundTag"] = "direct"
            rule["inboundTag"] = ["tun-in"]
            assertError(.unsafeFakeIPWireguardRouting, configJSON:
                fakeIPConfig(rules: [rule]).replacingOccurrences(of: "freedom", with: "wireguard"))
        }
        for rule: [String: Any] in [
            ["outboundTag": "direct", "ip": ["192.0.2.0/24"]],
            ["outboundTag": "direct", "domain": ["domain:example"], "inboundTag": ["socks-in"]],
        ] {
            XCTAssertNoThrow(try XrayMobileDNSPreflight.validate(
                fakeIPConfig(rules: [rule]).replacingOccurrences(of: "freedom", with: "wireguard")
            ))
        }
    }

    func testFakeIPChecksBalancerCandidatesAndFallbacks() {
        for balancer: [String: Any] in [
            ["tag": "pool", "selector": ["dir"]],
            ["tag": "pool", "selector": ["proxy"], "fallbackTag": "direct"],
        ] {
            for (name, error) in [("wireguard", XrayMobileDNSPreflightError.unsafeFakeIPWireguardRouting),
                                  ("freedom", .unsafeFakeIPFreedomRouting)] {
                assertError(error, configJSON: fakeIPConfig(
                    rules: [["balancerTag": "pool"]], balancers: [balancer]
                ).replacingOccurrences(of: "freedom", with: name))
            }
            for rule: [String: Any] in [
                ["balancerTag": "pool", "ip": ["192.0.2.0/24"]],
                ["balancerTag": "pool", "inboundTag": ["socks-in"]],
            ] {
                XCTAssertNoThrow(try XrayMobileDNSPreflight.validate(fakeIPConfig(
                    rules: [rule], balancers: [balancer]
                ).replacingOccurrences(of: "freedom", with: "wireguard")))
            }
        }
        XCTAssertNoThrow(try XrayMobileDNSPreflight.validate(fakeIPConfig(
            rules: [["balancerTag": "pool"]], balancers: [["tag": "pool", "selector": ["proxy"]]]
        )))
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
        dnsServers: [Any] = [],
        balancers: [[String: Any]] = []
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
            "routing": ["rules": rules, "balancers": balancers],
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
