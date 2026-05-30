import XCTest
@testable import XrayAppleShared

final class XrayClientProfileTests: XCTestCase {
    func testDefaultProviderBundleIdentifierUsesHostBundleIdentifier() {
        XCTAssertEqual(
            XrayClientProfile.defaultProviderBundleIdentifier(
                hostBundleIdentifier: "org.example.XrayClient"
            ),
            "org.example.XrayClient.Tunnel"
        )
    }

    func testMigratesLegacyDefaultProviderBundleIdentifier() {
        let profile = XrayClientProfile(
            name: "Xray",
            providerBundleIdentifier: "org.example.XrayClient.PacketTunnel",
            serverAddress: "xray-rust",
            configJSON: XrayClientProfile.directTunConfigJSON
        )

        XCTAssertEqual(
            profile.migratingLegacyDefaultProviderBundleIdentifier(
                hostBundleIdentifier: "org.example.XrayClient"
            ).providerBundleIdentifier,
            "org.example.XrayClient.Tunnel"
        )
    }

    func testStatsMessageRoundTrip() throws {
        let stats = XrayClientRuntimeStats(
            inboundPackets: 1,
            outboundPackets: 2,
            droppedPackets: 3
        )

        let data = try XrayTunnelProviderMessage.encodeStatsResponse(stats)

        XCTAssertEqual(
            try XrayTunnelProviderMessage.decodeStatsResponse(data),
            stats
        )
    }

    func testDefaultConfigIsJSONObject() throws {
        let data = Data(XrayClientProfile.directTunConfigJSON.utf8)
        let json = try JSONSerialization.jsonObject(with: data)

        XCTAssertTrue(json is [String: Any])
    }

    func testVlessURLImporterBuildsMobileRealityProfile() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: "vless://41dac315-fc32-4957-aded-6010b8f62fef@217.154.252.68:32134?type=tcp&encryption=none&security=reality&pbk=3jNx5A3WTFKhvCj3IPljaxbcBjCxhH2dVCNobKv_X1c&fp=chrome&sni=google.com&sid=1c5694e878&spx=%2F&pqv=ignored-for-now&flow=xtls-rprx-vision#other-port-test-xray-rust",
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "other-port-test-xray-rust")
        XCTAssertEqual(profile.providerBundleIdentifier, "org.example.XrayClient.Tunnel")
        XCTAssertEqual(profile.serverAddress, "217.154.252.68")

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let inbounds = try XCTUnwrap(root["inbounds"] as? [[String: Any]])
        XCTAssertEqual(inbounds.first?["tag"] as? String, "tun-in")
        XCTAssertEqual(inbounds.first?["protocol"] as? String, "tun")

        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds.count, 2)
        XCTAssertEqual(outbounds[0]["tag"] as? String, "proxy")
        XCTAssertEqual(outbounds[0]["protocol"] as? String, "vless")
        XCTAssertEqual(outbounds[1]["tag"] as? String, "direct")
        XCTAssertEqual(outbounds[1]["protocol"] as? String, "freedom")

        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        XCTAssertEqual(vnext.first?["address"] as? String, "217.154.252.68")
        XCTAssertEqual(vnext.first?["port"] as? Int, 32134)

        let users = try XCTUnwrap(vnext.first?["users"] as? [[String: Any]])
        XCTAssertEqual(users.first?["id"] as? String, "41dac315-fc32-4957-aded-6010b8f62fef")
        XCTAssertEqual(users.first?["encryption"] as? String, "none")
        XCTAssertEqual(users.first?["flow"] as? String, "xtls-rprx-vision")

        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "tcp")
        XCTAssertEqual(stream["security"] as? String, "reality")

        let reality = try XCTUnwrap(stream["realitySettings"] as? [String: Any])
        XCTAssertEqual(reality["serverName"] as? String, "google.com")
        XCTAssertEqual(reality["fingerprint"] as? String, "chrome")
        XCTAssertEqual(
            reality["publicKey"] as? String,
            "3jNx5A3WTFKhvCj3IPljaxbcBjCxhH2dVCNobKv_X1c"
        )
        XCTAssertEqual(reality["shortId"] as? String, "1c5694e878")
        XCTAssertEqual(reality["spiderX"] as? String, "/")
        XCTAssertNil(reality["pqv"])
    }

    func testVlessURLImporterRejectsUnsupportedSecurity() {
        XCTAssertThrowsError(
            try XrayVlessURLImporter.profile(
                from: "vless://41dac315-fc32-4957-aded-6010b8f62fef@example.com:443?type=tcp&security=tls&encryption=none"
            )
        ) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "Unsupported VLESS security `tls`. Expected `reality`."
            )
        }
    }
}
