import XCTest
@testable import XrayAppleShared

final class XrayClientProfileTests: XCTestCase {
    private static let sampleVlessURL = "vless://41dac315-fc32-4957-aded-6010b8f62fef@217.154.252.68:32134?type=tcp&encryption=none&security=reality&pbk=3jNx5A3WTFKhvCj3IPljaxbcBjCxhH2dVCNobKv_X1c&fp=chrome&sni=google.com&sid=1c5694e878&spx=%2F&pqv=ignored-for-now&flow=xtls-rprx-vision#other-port-test-xray-rust"

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
            droppedPackets: 3,
            tcpOpenEvents: 8,
            tcpOpenDurationMsTotal: 900,
            tcpOpenDurationMsMax: 300,
            tcpFirstByteEvents: 9,
            tcpFirstByteDurationMsTotal: 1_200,
            tcpFirstByteDurationMsMax: 400,
            tcp443OpenEvents: 5,
            tcp443OpenDurationMsTotal: 700,
            tcp443OpenDurationMsMax: 250,
            tcp443FirstByteEvents: 6,
            tcp443FirstByteDurationMsTotal: 1_000,
            tcp443FirstByteDurationMsMax: 500,
            udpRemoteOpenEvents: 4,
            udpRemoteUDP443OpenEvents: 5,
            udpRemoteWrittenBytes: 6,
            udpRemoteReadBytes: 7
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

    func testDebugLoggingDefaultsToDisabled() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertFalse(profile.debugLoggingEnabled)
    }

    func testTunFileDescriptorDefaultsToEnabled() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertTrue(profile.useTunFileDescriptor)
    }

    func testQuicBlockingDefaultsToDisabled() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertFalse(profile.blockQUIC)
    }

    func testTunRuntimeProfileDefaultsToDefault() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.tunRuntimeProfile, .default)
    }

    func testTunRuntimeProfileParsesMobilePlusAliases() throws {
        XCTAssertEqual(XrayTunRuntimeProfileSetting(configurationValue: "mobile-plus"), .mobilePlus)
        XCTAssertEqual(XrayTunRuntimeProfileSetting(configurationValue: "mobile_plus"), .mobilePlus)
        XCTAssertEqual(XrayTunRuntimeProfileSetting(configurationValue: "mobileplus"), .mobilePlus)
        XCTAssertEqual(XrayTunRuntimeProfileSetting.mobilePlus.displayName, "Mobile+")
    }

    func testProfileDecodesLegacyPayloadWithoutDebugLoggingFlag() throws {
        let legacyPayload = """
        {
          "id": "00000000-0000-0000-0000-000000000001",
          "name": "Legacy",
          "providerBundleIdentifier": "org.example.XrayClient.Tunnel",
          "serverAddress": "xray-rust",
          "configJSON": "{}"
        }
        """

        let profile = try JSONDecoder().decode(
            XrayClientProfile.self,
            from: Data(legacyPayload.utf8)
        )

        XCTAssertFalse(profile.debugLoggingEnabled)
        XCTAssertTrue(profile.useTunFileDescriptor)
        XCTAssertFalse(profile.blockQUIC)
        XCTAssertEqual(profile.tunRuntimeProfile, .default)
    }

    func testProfileEncodesDebugFlags() throws {
        let profile = XrayClientProfile(
            name: "Debug",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: "{}",
            debugLoggingEnabled: true,
            useTunFileDescriptor: false,
            blockQUIC: true,
            tunRuntimeProfile: .mobilePlus
        )

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile)) as? [String: Any]
        )

        XCTAssertEqual(root["debugLoggingEnabled"] as? Bool, true)
        XCTAssertEqual(root["useTunFileDescriptor"] as? Bool, false)
        XCTAssertEqual(root["blockQUIC"] as? Bool, true)
        XCTAssertEqual(root["tunRuntimeProfile"] as? String, "mobile-plus")
    }

    func testVlessURLImporterBuildsMobileRealityProfile() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
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

    func testVlessURLImporterExtractsURLFromPastedText() throws {
        let pastedText = "configuration url:\n\(Self.sampleVlessURL)\n"

        let profile = try XrayVlessURLImporter.profile(
            from: pastedText,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "other-port-test-xray-rust")
        XCTAssertEqual(profile.serverAddress, "217.154.252.68")
    }

    func testVlessURLImporterAcceptsSchemeLessAuthority() throws {
        let schemeLessURL = String(Self.sampleVlessURL.dropFirst("vless://".count))

        let profile = try XrayVlessURLImporter.profile(
            from: schemeLessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "other-port-test-xray-rust")
        XCTAssertEqual(profile.serverAddress, "217.154.252.68")
    }

    func testVlessURLImporterExtractsSchemeLessAuthorityFromPastedText() throws {
        let schemeLessURL = String(Self.sampleVlessURL.dropFirst("vless://".count))
        let pastedText = "configuration url:\n\(schemeLessURL)\n"

        let profile = try XrayVlessURLImporter.profile(
            from: pastedText,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "other-port-test-xray-rust")
        XCTAssertEqual(profile.serverAddress, "217.154.252.68")
    }

    func testVlessURLImporterAcceptsVisionUdp443Flow() throws {
        let url = Self.sampleVlessURL.replacingOccurrences(
            of: "flow=xtls-rprx-vision",
            with: "flow=xtls-rprx-vision-udp443"
        )

        let profile = try XrayVlessURLImporter.profile(
            from: url,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let users = try XCTUnwrap(vnext.first?["users"] as? [[String: Any]])
        XCTAssertEqual(users.first?["flow"] as? String, "xtls-rprx-vision-udp443")
    }

    func testVlessURLImporterDefaultsRealityFlowToVisionWhenOmitted() throws {
        let url = Self.sampleVlessURL.replacingOccurrences(
            of: "&flow=xtls-rprx-vision",
            with: ""
        )

        let profile = try XrayVlessURLImporter.profile(
            from: url,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let users = try XCTUnwrap(vnext.first?["users"] as? [[String: Any]])
        XCTAssertEqual(users.first?["flow"] as? String, "xtls-rprx-vision")
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
