import XCTest
@testable import XrayAppleShared

final class XrayClientProfileTests: XCTestCase {
    private static let sampleVlessURL = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:32134?type=tcp&encryption=none&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sni=example.com&sid=0123456789ab&spx=%2F&pqv=ignored-for-now&flow=xtls-rprx-vision#example-reality"
    private static let sampleXHTTPRealityURL = "vless://11111111-1111-4111-8111-111111111111@203.0.113.30:443?type=xhttp&encryption=none&security=reality&host=edge.example&path=%2Fxhttp&mode=packet-up&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sni=reality.example&sid=0123456789ab&spx=%2F#example-xhttp-reality"

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
            residentMemoryBytes: 12_345_678,
            threadCount: 17,
            runtimeIdentifier: "runtime-1",
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

    func testStatsMessageDecodesOlderResourceTelemetryAsDefaults() throws {
        let data = Data(
            #"{"inboundPackets":1,"outboundPackets":2,"droppedPackets":3}"#.utf8
        )

        let stats = try JSONDecoder().decode(XrayClientRuntimeStats.self, from: data)

        XCTAssertEqual(stats.residentMemoryBytes, 0)
        XCTAssertEqual(stats.threadCount, 0)
        XCTAssertEqual(stats.runtimeIdentifier, "")
    }

    func testCloseConnectionsResponseRoundTrip() throws {
        let data = try XrayTunnelProviderMessage.encodeCloseConnectionsResponse(17)

        XCTAssertEqual(
            try XrayTunnelProviderMessage.decodeCloseConnectionsResponse(data),
            17
        )
    }

    func testDefaultConfigIsJSONObject() throws {
        let data = Data(XrayClientProfile.directTunConfigJSON.utf8)
        let json = try JSONSerialization.jsonObject(with: data)

        XCTAssertTrue(json is [String: Any])
    }

    func testDefaultDirectConfigLeavesDNSForExplicitHostOverride() throws {
        let data = Data(XrayClientProfile.directTunConfigJSON.utf8)
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: data) as? [String: Any]
        )

        XCTAssertNil(root["dns"])
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds.first?["protocol"] as? String, "freedom")
    }

    @available(*, deprecated)
    func testLegacyDirectConfigMigrationCompatibilityAPIIsNoOp() {
        let legacyConfigJSON = """
        {
          "inbounds": [
            {
              "tag": "tun-in",
              "protocol": "tun",
              "listen": "127.0.0.1",
              "port": 0,
              "settings": {}
            }
          ],
          "outbounds": [
            {
              "tag": "direct",
              "protocol": "freedom",
              "settings": {}
            }
          ]
        }
        """
        let profile = XrayClientProfile(
            name: "Xray",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: legacyConfigJSON
        )

        let migrated = profile.addingFakeIPToLegacyDirectConfigIfNeeded()

        XCTAssertEqual(migrated, profile)
    }

    @available(*, deprecated)
    func testLegacyDirectConfigMigrationLeavesCustomConfigUntouched() {
        let customConfigJSON = #"{"inbounds":[]}"#
        let profile = XrayClientProfile(
            name: "Custom",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: customConfigJSON
        )

        let migrated = profile.addingFakeIPToLegacyDirectConfigIfNeeded()

        XCTAssertEqual(migrated.configJSON, customConfigJSON)
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

    func testTunRuntimeProfileDefaultsToDefault() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.tunRuntimeProfile, .default)
    }

    func testRegionalRoutingDefaultsToOff() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.regionalRoutingMode, .off)
        XCTAssertTrue(profile.regionalRoutingRegions.isEmpty)
    }

    func testFreshDefaultProfileUsesDefaultDNSWithoutManualFields() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.dnsTestMode, .defaultDNS)
        XCTAssertEqual(profile.dnsTestTransport, .classic)
        XCTAssertTrue(profile.dnsTestUpstream.isEmpty)
        XCTAssertFalse(XrayClientDNSTestMode.configuration.requiresUpstream)
        XCTAssertFalse(XrayClientDNSTestMode.defaultDNS.requiresUpstream)
        XCTAssertFalse(XrayClientDNSTestMode.fakeIP.requiresUpstream)
        XCTAssertTrue(XrayClientDNSTestMode.proxy.requiresUpstream)
    }

    func testFreshDefaultProfileEffectiveConfigPassesMobileDNSPreflight() throws {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )
        let sourceConfigJSON = profile.configJSON

        let effectiveConfigJSON = try profile.effectiveConfigJSON()

        XCTAssertNoThrow(try XrayMobileDNSPreflight.validate(effectiveConfigJSON))
        XCTAssertEqual(profile.configJSON, sourceConfigJSON)
    }

    func testDefaultDNSModeCodableValueIsStable() throws {
        let encoded = try JSONEncoder().encode(XrayClientDNSTestMode.defaultDNS)

        XCTAssertEqual(String(decoding: encoded, as: UTF8.self), #""default-dns""#)
        XCTAssertEqual(
            try JSONDecoder().decode(XrayClientDNSTestMode.self, from: encoded),
            .defaultDNS
        )
    }

    func testRealityVisionFlowModeDefaultsMissingFlowToBlocked() throws {
        var profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        )
        profile.configJSON = try Self.configJSONRemovingFirstVlessUserFlow(profile.configJSON)

        XCTAssertEqual(profile.realityVisionFlowMode, .blockUDP443)
    }

    func testUpdatingRealityVisionFlowModeAllowsUDP443() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        let updated = try profile.updatingRealityVisionFlowMode(.allowUDP443)

        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: updated.configJSON),
            XrayClientProfile.realityVisionUDP443Flow
        )
        XCTAssertEqual(updated.realityVisionFlowMode, .allowUDP443)
    }

    func testUpdatingRealityVisionFlowModeRestoresBlockedUDP443() throws {
        let url = Self.sampleVlessURL.replacingOccurrences(
            of: "flow=xtls-rprx-vision",
            with: "flow=xtls-rprx-vision-udp443"
        )
        let profile = try XrayVlessURLImporter.profile(
            from: url,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        let updated = try profile.updatingRealityVisionFlowMode(.blockUDP443)

        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: updated.configJSON),
            XrayClientProfile.defaultRealityVisionFlow
        )
        XCTAssertEqual(updated.realityVisionFlowMode, .blockUDP443)
    }

    func testRealityVisionFlowModeIsNilForNonRealityVlessConfig() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertNil(profile.realityVisionFlowMode)
    }

    func testRealityFingerprintModeReadsImportedFingerprint() throws {
        let url = Self.sampleVlessURL.replacingOccurrences(
            of: "fp=chrome",
            with: "fp=hellochrome_131"
        )
        let profile = try XrayVlessURLImporter.profile(
            from: url,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.realityFingerprintMode, .hellochrome131)
    }

    func testRealityFingerprintModeAcceptsXrayCoreV26728ExplicitAutoNames() {
        XCTAssertEqual(
            XrayRealityFingerprintMode(rawValue: "hellochrome_133"),
            .hellochrome133
        )
        XCTAssertEqual(
            XrayRealityFingerprintMode(rawValue: "hellofirefox_148"),
            .hellofirefox148
        )
        XCTAssertEqual(
            XrayRealityFingerprintMode(rawValue: "hellosafari_26_3"),
            .hellosafari263
        )
    }

    func testUpdatingRealityFingerprintModeChangesRealitySettings() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        let updated = try profile.updatingRealityFingerprintMode(.hellochrome131)

        XCTAssertEqual(
            try Self.firstRealityFingerprint(in: updated.configJSON),
            "hellochrome_131"
        )
        XCTAssertEqual(updated.realityFingerprintMode, .hellochrome131)
    }

    func testRealityFingerprintModeIsNilForNonRealityVlessConfig() {
        let profile = XrayClientProfile.defaultProfile(
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertNil(profile.realityFingerprintMode)
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
        XCTAssertEqual(profile.tunRuntimeProfile, .default)
        XCTAssertEqual(profile.dnsTestMode, .configuration)
        XCTAssertEqual(profile.dnsTestTransport, .classic)
        XCTAssertTrue(profile.dnsTestUpstream.isEmpty)
        XCTAssertEqual(profile.regionalRoutingMode, .off)
        XCTAssertTrue(profile.regionalRoutingRegions.isEmpty)
    }

    func testProfileEncodesRuntimeFlagsAndRegionalRoutingWithoutLegacyQuicOption() throws {
        let profile = XrayClientProfile(
            name: "Debug",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: "{}",
            debugLoggingEnabled: true,
            useTunFileDescriptor: false,
            tunRuntimeProfile: .mobilePlus,
            regionalRoutingMode: .bypassSelected,
            regionalRoutingRegions: [.russia, .iran],
            dnsTestMode: .proxy,
            dnsTestTransport: .routedTCP,
            dnsTestUpstream: "192.0.2.53:5353"
        )

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile)) as? [String: Any]
        )

        XCTAssertEqual(root["debugLoggingEnabled"] as? Bool, true)
        XCTAssertEqual(root["useTunFileDescriptor"] as? Bool, false)
        XCTAssertNil(root["blockQUIC"])
        XCTAssertEqual(root["tunRuntimeProfile"] as? String, "mobile-plus")
        XCTAssertEqual(root["dnsTestMode"] as? String, "proxy")
        XCTAssertEqual(root["dnsTestTransport"] as? String, "routed-tcp")
        XCTAssertEqual(root["dnsTestUpstream"] as? String, "192.0.2.53:5353")
        XCTAssertEqual(root["regionalRoutingMode"] as? String, "bypass-selected")
        XCTAssertEqual(root["regionalRoutingRegions"] as? [String], ["russia", "iran"])
    }

    func testEffectiveConfigLeavesBaseJSONByteForByteInConfigurationMode() throws {
        let baseConfigJSON = "  {\n  \"dns\": {\"servers\": [\"existing.example\"]}\n}\n"
        let profile = XrayClientProfile(
            name: "Config DNS",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: baseConfigJSON,
            dnsTestMode: .configuration,
            dnsTestTransport: .localTCP,
            dnsTestUpstream: "tcp://ignored.example"
        )

        XCTAssertEqual(try profile.effectiveConfigJSON(), baseConfigJSON)
        XCTAssertEqual(profile.configJSON, baseConfigJSON)
    }

    func testEffectiveConfigBuildsExactDefaultDNSPresetWithoutChangingSourceJSON() throws {
        let baseConfigJSON = #"{"dns":{"hosts":{"full:bootstrap.example":"192.0.2.1"},"tag":"dns-route"},"outbounds":[]}"#
        let profile = XrayClientProfile(
            name: "Default DNS",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: baseConfigJSON,
            dnsTestMode: .defaultDNS,
            dnsTestTransport: .localTCP,
            dnsTestUpstream: "tcp://ignored.example"
        )

        let effectiveRoot = try XCTUnwrap(
            try JSONSerialization.jsonObject(
                with: Data(profile.effectiveConfigJSON().utf8)
            ) as? NSDictionary
        )
        let expectedRoot: NSDictionary = [
            "dns": [
                "fakeIp": [
                    "enabled": true,
                    "ipv4Pool": "198.19.0.0/16",
                    "poolSize": 32_768,
                    "ttl": 60,
                ],
                "hosts": ["full:bootstrap.example": "192.0.2.1"],
                "queryStrategy": "UseIP",
                "servers": ["tcp://1.1.1.1"],
                "tag": "dns-route",
            ],
            "outbounds": [],
        ]

        XCTAssertEqual(effectiveRoot, expectedRoot)
        XCTAssertEqual(profile.configJSON, baseConfigJSON)
    }

    func testEffectiveConfigBuildsPureFakeDNSWhenUpstreamIsBlank() throws {
        let baseConfigJSON = #"{"dns":{"queryStrategy":"UseIPv6","servers":["old.example"],"hosts":{"full:old.example":"192.0.2.1"},"disableFallback":true},"outbounds":[]}"#
        let profile = XrayClientProfile(
            name: "FakeDNS",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: baseConfigJSON,
            dnsTestMode: .fakeIP,
            dnsTestTransport: .routedTCP,
            dnsTestUpstream: " \n\t "
        )

        let dns = try Self.dnsObject(in: profile.effectiveConfigJSON())
        let fakeIP = try XCTUnwrap(dns["fakeIp"] as? [String: Any])

        XCTAssertEqual(Set(dns.keys), Set(["fakeIp", "hosts", "queryStrategy"]))
        XCTAssertEqual(dns["queryStrategy"] as? String, "UseIPv6")
        XCTAssertNil(dns["servers"])
        XCTAssertEqual(
            dns["hosts"] as? [String: String],
            ["full:old.example": "192.0.2.1"]
        )
        XCTAssertEqual(fakeIP["enabled"] as? Bool, true)
        XCTAssertEqual(fakeIP["ipv4Pool"] as? String, "198.19.0.0/16")
        XCTAssertEqual(fakeIP["poolSize"] as? Int, 32768)
        XCTAssertEqual(fakeIP["ttl"] as? Int, 60)
        XCTAssertEqual(profile.configJSON, baseConfigJSON)
    }

    func testEffectiveConfigFormatsOptionalFakeDNSUpstreamForEveryTransport() throws {
        for (transport, expectedServer) in [
            (XrayClientDNSTestTransport.classic, "resolver.example:5353"),
            (.routedTCP, "tcp://resolver.example:5353"),
            (.localTCP, "tcp+local://resolver.example:5353"),
        ] {
            let profile = XrayClientProfile(
                name: "FakeDNS",
                providerBundleIdentifier: "org.example.XrayClient.Tunnel",
                serverAddress: "xray-rust",
                configJSON: #"{"outbounds":[]}"#,
                dnsTestMode: .fakeIP,
                dnsTestTransport: transport,
                dnsTestUpstream: " \nresolver.example:5353\t "
            )

            let dns = try Self.dnsObject(in: profile.effectiveConfigJSON())

            XCTAssertEqual(
                dns["servers"] as? [String],
                [expectedServer],
                "transport=\(transport.rawValue)"
            )
            XCTAssertNotNil(dns["fakeIp"], "transport=\(transport.rawValue)")
            XCTAssertEqual(dns["queryStrategy"] as? String, "UseIP")
        }
    }

    func testEffectiveConfigBuildsProxyDNSForEveryTransport() throws {
        let baseConfigJSON = #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"},"disableFallback":true},"outbounds":[]}"#
        for (transport, expectedServer) in [
            (XrayClientDNSTestTransport.classic, "[2001:db8::53]:5353"),
            (.routedTCP, "tcp://[2001:db8::53]:5353"),
            (.localTCP, "tcp+local://[2001:db8::53]:5353"),
        ] {
            let profile = XrayClientProfile(
                name: "DNS Proxy",
                providerBundleIdentifier: "org.example.XrayClient.Tunnel",
                serverAddress: "xray-rust",
                configJSON: baseConfigJSON,
                dnsTestMode: .proxy,
                dnsTestTransport: transport,
                dnsTestUpstream: " [2001:db8::53]:5353 "
            )

            let dns = try Self.dnsObject(in: profile.effectiveConfigJSON())

            XCTAssertEqual(Set(dns.keys), Set(["queryStrategy", "servers"]))
            XCTAssertEqual(dns["queryStrategy"] as? String, "UseIP")
            XCTAssertEqual(
                dns["servers"] as? [String],
                [expectedServer],
                "transport=\(transport.rawValue)"
            )
            XCTAssertNil(dns["fakeIp"])
            XCTAssertEqual(profile.configJSON, baseConfigJSON)
        }
    }

    func testEffectiveConfigPreservesDNSRoutingTagInGeneratedModes() throws {
        for mode in [XrayClientDNSTestMode.defaultDNS, .fakeIP, .proxy] {
            let profile = XrayClientProfile(
                name: "Tagged DNS",
                providerBundleIdentifier: "org.example.XrayClient.Tunnel",
                serverAddress: "xray-rust",
                configJSON: #"{"dns":{"tag":"dns-route"},"outbounds":[]}"#,
                dnsTestMode: mode,
                dnsTestTransport: .routedTCP,
                dnsTestUpstream: "192.0.2.53"
            )

            let dns = try Self.dnsObject(in: profile.effectiveConfigJSON())
            XCTAssertEqual(dns["tag"] as? String, "dns-route", "mode=\(mode.rawValue)")
        }
    }

    func testEffectiveConfigPreservesSourceQueryStrategyInGeneratedModes() throws {
        let profile = XrayClientProfile(
            name: "IPv4 DNS",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: #"{"dns":{"queryStrategy":"UseIPv4"},"outbounds":[]}"#,
            dnsTestMode: .fakeIP,
            dnsTestTransport: .routedTCP,
            dnsTestUpstream: "192.0.2.53"
        )

        let dns = try Self.dnsObject(in: profile.effectiveConfigJSON())

        XCTAssertEqual(dns["queryStrategy"] as? String, "UseIPv4")
    }

    func testEffectiveConfigDefaultsQueryStrategyWhenSourceOmitsIt() throws {
        let profile = XrayClientProfile(
            name: "Unpinned DNS",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: #"{"dns":{"tag":"dns-route"},"outbounds":[]}"#,
            dnsTestMode: .fakeIP,
            dnsTestTransport: .routedTCP,
            dnsTestUpstream: "192.0.2.53"
        )

        let dns = try Self.dnsObject(in: profile.effectiveConfigJSON())

        XCTAssertEqual(dns["queryStrategy"] as? String, "UseIP")
    }

    func testEffectiveConfigBracketsBareIPv6ForTCPTransports() throws {
        for (transport, expectedServer) in [
            (XrayClientDNSTestTransport.routedTCP, "tcp://[2001:db8::53]"),
            (.localTCP, "tcp+local://[2001:db8::53]"),
        ] {
            let profile = XrayClientProfile(
                name: "IPv6 DNS Proxy",
                providerBundleIdentifier: "org.example.XrayClient.Tunnel",
                serverAddress: "xray-rust",
                configJSON: #"{"outbounds":[]}"#,
                dnsTestMode: .proxy,
                dnsTestTransport: transport,
                dnsTestUpstream: "2001:db8::53"
            )

            let dns = try Self.dnsObject(in: profile.effectiveConfigJSON())
            XCTAssertEqual(
                dns["servers"] as? [String],
                [expectedServer],
                "transport=\(transport.rawValue)"
            )
        }
    }

    func testEffectiveConfigRejectsProxyWithoutExplicitUpstream() {
        let profile = XrayClientProfile(
            name: "DNS Proxy",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: #"{"outbounds":[]}"#,
            dnsTestMode: .proxy,
            dnsTestUpstream: " \n "
        )

        XCTAssertThrowsError(try profile.effectiveConfigJSON()) { error in
            XCTAssertEqual(
                error as? XrayClientDNSTestConfigurationError,
                .missingUpstream
            )
        }
    }

    func testEffectiveConfigRejectsUpstreamSchemeInGeneratedModes() {
        for mode in [XrayClientDNSTestMode.fakeIP, .proxy] {
            let profile = XrayClientProfile(
                name: "DNS Test",
                providerBundleIdentifier: "org.example.XrayClient.Tunnel",
                serverAddress: "xray-rust",
                configJSON: #"{"outbounds":[]}"#,
                dnsTestMode: mode,
                dnsTestTransport: .routedTCP,
                dnsTestUpstream: "tcp://resolver.example"
            )

            XCTAssertThrowsError(try profile.effectiveConfigJSON()) { error in
                XCTAssertEqual(
                    error as? XrayClientDNSTestConfigurationError,
                    .upstreamMustNotIncludeScheme,
                    "mode=\(mode.rawValue)"
                )
            }
        }
    }

    func testEffectiveConfigRejectsNonObjectRootInGeneratedModes() {
        for mode in [XrayClientDNSTestMode.fakeIP, .proxy] {
            let profile = XrayClientProfile(
                name: "DNS Test",
                providerBundleIdentifier: "org.example.XrayClient.Tunnel",
                serverAddress: "xray-rust",
                configJSON: "[]",
                dnsTestMode: mode,
                dnsTestUpstream: "192.0.2.53"
            )

            XCTAssertThrowsError(try profile.effectiveConfigJSON()) { error in
                XCTAssertEqual(
                    error as? XrayClientDNSTestConfigurationError,
                    .rootIsNotObject,
                    "mode=\(mode.rawValue)"
                )
            }
        }
    }

    func testEffectiveConfigComposesDNSTestModeBeforeRegionalRouting() throws {
        var profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        ).updatingRegionalRouting(mode: .bypassSelected, regions: [.china])
        let baseConfigJSON = profile.configJSON
        profile.dnsTestMode = .proxy
        profile.dnsTestTransport = .routedTCP
        profile.dnsTestUpstream = "192.0.2.53"

        let effectiveConfigJSON = try profile.effectiveConfigJSON()
        let dns = try Self.dnsObject(in: effectiveConfigJSON)
        let rules = try Self.routingRules(in: effectiveConfigJSON)

        XCTAssertEqual(dns["queryStrategy"] as? String, "UseIPv4")
        XCTAssertEqual(dns["servers"] as? [String], ["tcp://192.0.2.53"])
        XCTAssertEqual(rules[0]["domain"] as? [String], ["geosite:cn"])
        XCTAssertEqual(rules[0]["outboundTag"] as? String, "direct")
        XCTAssertEqual(profile.configJSON, baseConfigJSON)
    }

    func testEffectiveConfigReturnsBaseConfigWhenRegionalRoutingIsOff() throws {
        let profile = XrayClientProfile(
            name: "Plain",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: XrayClientProfile.directTunConfigJSON,
            regionalRoutingMode: .off,
            regionalRoutingRegions: [.russia]
        )

        XCTAssertEqual(try profile.effectiveConfigJSON(), XrayClientProfile.directTunConfigJSON)
    }

    func testEffectiveConfigBypassesSelectedRegionsBeforeExistingRules() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        ).updatingRegionalRouting(mode: .bypassSelected, regions: [.russia, .iran])

        let rules = try Self.routingRules(in: profile.effectiveConfigJSON())

        XCTAssertEqual(rules[0]["outboundTag"] as? String, "direct")
        XCTAssertEqual(rules[0]["domain"] as? [String], ["geosite:category-ru", "geosite:category-ir"])
        XCTAssertNil(rules[0]["ip"])
        XCTAssertEqual(rules[1]["outboundTag"] as? String, "direct")
        XCTAssertEqual(rules[1]["ip"] as? [String], ["geoip:ru", "geoip:ir"])
        XCTAssertNil(rules[1]["domain"])
        XCTAssertEqual(rules[2]["ip"] as? [String], ["geoip:private", "127.0.0.0/8", "fd00::/8"])
    }

    func testEffectiveConfigProxiesOnlySelectedRegionsThenFallsBackToDirect() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        ).updatingRegionalRouting(mode: .proxyOnlySelected, regions: [.china])

        let rules = try Self.routingRules(in: profile.effectiveConfigJSON())

        XCTAssertEqual(rules[0]["outboundTag"] as? String, "proxy")
        XCTAssertEqual(rules[0]["domain"] as? [String], ["geosite:cn"])
        XCTAssertEqual(rules[1]["outboundTag"] as? String, "proxy")
        XCTAssertEqual(rules[1]["ip"] as? [String], ["geoip:cn"])
        let lastRule = try XCTUnwrap(rules.last)
        XCTAssertEqual(lastRule["outboundTag"] as? String, "direct")
        XCTAssertNil(lastRule["domain"])
        XCTAssertNil(lastRule["ip"])
    }

    func testEffectiveConfigRejectsRegionalRoutingWhenRequiredOutboundIsMissing() {
        let profile = XrayClientProfile(
            name: "Direct",
            providerBundleIdentifier: "org.example.XrayClient.Tunnel",
            serverAddress: "xray-rust",
            configJSON: XrayClientProfile.directTunConfigJSON,
            regionalRoutingMode: .proxyOnlySelected,
            regionalRoutingRegions: [.china]
        )

        XCTAssertThrowsError(try profile.effectiveConfigJSON()) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "Regional routing requires an outbound tagged `proxy`."
            )
        }
    }

    func testVlessURLImporterBuildsMobileRealityProfile() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "example-reality")
        XCTAssertEqual(profile.providerBundleIdentifier, "org.example.XrayClient.Tunnel")
        XCTAssertEqual(profile.serverAddress, "203.0.113.10")

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let inbounds = try XCTUnwrap(root["inbounds"] as? [[String: Any]])
        XCTAssertEqual(inbounds.first?["tag"] as? String, "tun-in")
        XCTAssertEqual(inbounds.first?["protocol"] as? String, "tun")

        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let fakeIP = try XCTUnwrap(dns["fakeIp"] as? [String: Any])
        XCTAssertEqual(fakeIP["enabled"] as? Bool, true)
        XCTAssertEqual(fakeIP["ipv4Pool"] as? String, "198.19.0.0/16")
        XCTAssertEqual(fakeIP["poolSize"] as? Int, 32768)
        XCTAssertEqual(fakeIP["ttl"] as? Int, 60)

        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds.count, 2)
        XCTAssertEqual(outbounds[0]["tag"] as? String, "proxy")
        XCTAssertEqual(outbounds[0]["protocol"] as? String, "vless")
        XCTAssertEqual(outbounds[1]["tag"] as? String, "direct")
        XCTAssertEqual(outbounds[1]["protocol"] as? String, "freedom")

        let routing = try XCTUnwrap(root["routing"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
        XCTAssertEqual(rules.count, 1)
        XCTAssertEqual(
            rules[0]["ip"] as? [String],
            ["geoip:private", "127.0.0.0/8", "fd00::/8"]
        )
        XCTAssertNil(rules[0]["domain"])
        XCTAssertFalse(profile.configJSON.contains("captive.apple.com"))

        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        XCTAssertEqual(vnext.first?["address"] as? String, "203.0.113.10")
        XCTAssertEqual(vnext.first?["port"] as? Int, 32134)

        let users = try XCTUnwrap(vnext.first?["users"] as? [[String: Any]])
        XCTAssertEqual(users.first?["id"] as? String, "11111111-1111-4111-8111-111111111111")
        XCTAssertEqual(users.first?["encryption"] as? String, "none")
        XCTAssertEqual(users.first?["flow"] as? String, "xtls-rprx-vision")

        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "tcp")
        XCTAssertEqual(stream["security"] as? String, "reality")

        let reality = try XCTUnwrap(stream["realitySettings"] as? [String: Any])
        XCTAssertEqual(reality["serverName"] as? String, "example.com")
        XCTAssertEqual(reality["fingerprint"] as? String, "chrome")
        XCTAssertEqual(
            reality["publicKey"] as? String,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        XCTAssertEqual(reality["shortId"] as? String, "0123456789ab")
        XCTAssertEqual(reality["spiderX"] as? String, "/")
        XCTAssertEqual(reality["mldsa65Verify"] as? String, "ignored-for-now")
    }

    func testVlessURLImporterBuildsPlainXHTTPProfileFromDoubleEncodedExtra() throws {
        let extraJSON = #"{"noGRPCHeader":false,"scMaxConcurrentPosts":100,"scMaxEachPostBytes":"500000","scMinPostsIntervalMs":"60","xmux":{"cMaxReuseTimes":0,"hKeepAlivePeriod":0,"hMaxRequestTimes":"600-900","hMaxReusableSecs":"1800-3000","maxConnections":16},"xPaddingBytes":"100-1000"}"#
        let encodedOnce = try XCTUnwrap(
            extraJSON.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let encodedTwice = try XCTUnwrap(
            encodedOnce.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let url = "vless://11111111-1111-4111-8111-111111111111@203.0.113.20:80"
            + "?type=xhttp&host=edge.example&path=%2F&mode=packet-up"
            + "&extra=\(encodedTwice)&security=none"
            + "#Legacy%20XHTTP%20sample"

        let profile = try XrayVlessURLImporter.profile(
            from: url,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "Legacy XHTTP sample")
        XCTAssertEqual(profile.serverAddress, "203.0.113.20")
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "xhttp")
        XCTAssertEqual(stream["security"] as? String, "none")
        XCTAssertNil(stream["realitySettings"])

        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        XCTAssertEqual(xhttp["host"] as? String, "edge.example")
        XCTAssertEqual(xhttp["path"] as? String, "/")
        XCTAssertEqual(xhttp["mode"] as? String, "packet-up")
        let extra = try XCTUnwrap(xhttp["extra"] as? [String: Any])
        XCTAssertEqual(extra["noGRPCHeader"] as? Bool, false)
        XCTAssertEqual(extra["scMaxConcurrentPosts"] as? Int, 100)
        XCTAssertEqual(extra["scMaxEachPostBytes"] as? String, "500000")
        XCTAssertEqual(extra["scMinPostsIntervalMs"] as? String, "60")
        XCTAssertEqual(extra["xPaddingBytes"] as? String, "100-1000")
        let xmux = try XCTUnwrap(extra["xmux"] as? [String: Any])
        XCTAssertEqual(xmux["cMaxReuseTimes"] as? Int, 0)
        XCTAssertEqual(xmux["hKeepAlivePeriod"] as? Int, 0)
        XCTAssertEqual(xmux["hMaxRequestTimes"] as? String, "600-900")
        XCTAssertEqual(xmux["hMaxReusableSecs"] as? String, "1800-3000")
        XCTAssertEqual(xmux["maxConnections"] as? Int, 16)

        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let users = try XCTUnwrap(vnext[0]["users"] as? [[String: Any]])
        XCTAssertNil(users[0]["flow"])
    }

    func testVlessURLImporterAcceptsSingleEncodedXHTTPExtra() throws {
        let extraJSON = #"{"noGRPCHeader":false,"xmux":{"maxConnections":16}}"#
        let encoded = try XCTUnwrap(
            extraJSON.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let url = "vless://11111111-1111-4111-8111-111111111111@203.0.113.20:80"
            + "?type=xhttp&security=none&mode=packet-up&extra=\(encoded)"

        let profile = try XrayVlessURLImporter.profile(from: url)
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        let extra = try XCTUnwrap(xhttp["extra"] as? [String: Any])
        let xmux = try XCTUnwrap(extra["xmux"] as? [String: Any])
        XCTAssertEqual(xmux["maxConnections"] as? Int, 16)
    }

    func testVlessURLImporterCanonicalizesSplitHTTPAndDefaultsMode() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: "vless://11111111-1111-4111-8111-111111111111@203.0.113.20:80?type=splithttp&security=none"
        )
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "xhttp")
        XCTAssertEqual(stream["security"] as? String, "none")
        XCTAssertEqual(xhttp["host"] as? String, "")
        XCTAssertEqual(xhttp["path"] as? String, "")
        XCTAssertEqual(xhttp["mode"] as? String, "auto")
        XCTAssertNil(xhttp["extra"])
    }

    func testVlessURLImporterBuildsXHTTPTLSProfileWithoutLosingFields() throws {
        let extraJSON = #"{"noGRPCHeader":false,"xmux":{"maxConnections":4}}"#
        let encodedOnce = try XCTUnwrap(
            extraJSON.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let encodedTwice = try XCTUnwrap(
            encodedOnce.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let url = "vless://11111111-1111-4111-8111-111111111111@203.0.113.21:443"
            + "?type=xhttp&security=tls&host=cdn.example&path=%2Fupload&mode=stream-up"
            + "&sni=origin.example&fp=hellochrome_120&alpn=h2%2Chttp%2F1.1"
            + "&allowInsecure=1&extra=\(encodedTwice)"

        let profile = try XrayVlessURLImporter.profile(from: url)
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "xhttp")
        XCTAssertEqual(stream["security"] as? String, "tls")
        XCTAssertNil(stream["realitySettings"])

        let tls = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
        XCTAssertEqual(tls["serverName"] as? String, "origin.example")
        XCTAssertEqual(tls["fingerprint"] as? String, "hellochrome_120")
        XCTAssertEqual(tls["alpn"] as? [String], ["h2", "http/1.1"])
        XCTAssertEqual(tls["allowInsecure"] as? Bool, true)

        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        XCTAssertEqual(xhttp["host"] as? String, "cdn.example")
        XCTAssertEqual(xhttp["path"] as? String, "/upload")
        XCTAssertEqual(xhttp["mode"] as? String, "stream-up")
        let extra = try XCTUnwrap(xhttp["extra"] as? [String: Any])
        XCTAssertEqual(extra["noGRPCHeader"] as? Bool, false)
        let xmux = try XCTUnwrap(extra["xmux"] as? [String: Any])
        XCTAssertEqual(xmux["maxConnections"] as? Int, 4)

        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let users = try XCTUnwrap(vnext[0]["users"] as? [[String: Any]])
        XCTAssertNil(users[0]["flow"])
    }

    func testVlessURLImporterCanonicalizesSplitHTTPTLSAndMaterializesDefaults() throws {
        let profile = try XrayVlessURLImporter.profile(
            from: "vless://11111111-1111-4111-8111-111111111111@tls-endpoint.example:443?type=splithttp&security=tls"
        )
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        let tls = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "xhttp")
        XCTAssertEqual(stream["security"] as? String, "tls")
        XCTAssertEqual(tls["serverName"] as? String, "tls-endpoint.example")
        XCTAssertEqual(tls["fingerprint"] as? String, "chrome")
        XCTAssertNil(tls["alpn"])
        XCTAssertNil(tls["allowInsecure"])
    }

    func testVlessURLImporterParsesSupportedTLSAllowInsecureSpellings() throws {
        for (rawValue, expected) in [
            ("0", false),
            ("false", false),
            ("FALSE", false),
            ("1", true),
            ("true", true),
            ("TRUE", true),
        ] {
            let url = "vless://11111111-1111-4111-8111-111111111111@example.com:443"
                + "?type=xhttp&security=tls&allowInsecure=\(rawValue)"
            let profile = try XrayVlessURLImporter.profile(from: url)
            let root = try XCTUnwrap(
                try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
            )
            let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
            let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
            let tls = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
            XCTAssertEqual(tls["allowInsecure"] as? Bool, expected, rawValue)
        }
    }

    func testVlessURLImporterBuildsXHTTPRealityProfileWithoutLosingFields() throws {
        let extra = try XCTUnwrap(
            #"{"xPaddingBytes":"100-200"}"#.addingPercentEncoding(
                withAllowedCharacters: .alphanumerics
            )
        )
        let url = "vless://11111111-1111-4111-8111-111111111111@203.0.113.30:443"
            + "?type=splithttp&security=reality&host=edge.example&path=%2Freality&mode=stream-one"
            + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=hellochrome_131"
            + "&sni=reality.example&sid=0123456789ab&spx=%2Fcrawl&pqv=post-quantum-key"
            + "&alpn=h2&extra=\(extra)"

        let profile = try XrayVlessURLImporter.profile(from: url)
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "xhttp")
        XCTAssertEqual(stream["security"] as? String, "reality")
        XCTAssertNil(stream["tlsSettings"])

        let reality = try XCTUnwrap(stream["realitySettings"] as? [String: Any])
        XCTAssertEqual(reality["serverName"] as? String, "reality.example")
        XCTAssertEqual(reality["fingerprint"] as? String, "hellochrome_131")
        XCTAssertEqual(
            reality["publicKey"] as? String,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )
        XCTAssertEqual(reality["shortId"] as? String, "0123456789ab")
        XCTAssertEqual(reality["spiderX"] as? String, "/crawl")
        XCTAssertEqual(reality["mldsa65Verify"] as? String, "post-quantum-key")

        let xhttp = try XCTUnwrap(stream["xhttpSettings"] as? [String: Any])
        XCTAssertEqual(xhttp["host"] as? String, "edge.example")
        XCTAssertEqual(xhttp["path"] as? String, "/reality")
        XCTAssertEqual(xhttp["mode"] as? String, "stream-one")
        let decodedExtra = try XCTUnwrap(xhttp["extra"] as? [String: Any])
        XCTAssertEqual(decodedExtra["xPaddingBytes"] as? String, "100-200")

        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let users = try XCTUnwrap(vnext[0]["users"] as? [[String: Any]])
        XCTAssertNil(users[0]["flow"])
        XCTAssertNil(reality["alpn"])
    }

    func testVlessURLImporterDefaultsRealitySNIAndAcceptsPresentEmptyShortID() throws {
        let url = "vless://11111111-1111-4111-8111-111111111111@reality-endpoint.example:443"
            + "?type=xhttp&security=reality"
            + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sid="

        let profile = try XrayVlessURLImporter.profile(from: url)
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        let reality = try XCTUnwrap(stream["realitySettings"] as? [String: Any])
        XCTAssertEqual(reality["serverName"] as? String, "reality-endpoint.example")
        XCTAssertEqual(reality["shortId"] as? String, "")
    }

    func testVlessURLImporterRejectsExplicitEmptyXHTTPRealitySNIAndFingerprint() {
        let baseURL = "vless://11111111-1111-4111-8111-111111111111@example.com:443"
            + "?type=xhttp&security=reality"
            + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid="
        for (field, otherField) in [("sni", "fp=chrome"), ("fp", "sni=example.com")] {
            XCTAssertThrowsError(
                try XrayVlessURLImporter.profile(
                    from: baseURL + "&\(otherField)&\(field)="
                ),
                field
            ) { error in
                XCTAssertEqual(
                    error as? XrayVlessURLImportError,
                    .unsupportedQueryValue(
                        name: field,
                        value: "",
                        expected: "non-empty"
                    )
                )
            }
        }
    }

    func testVlessURLImporterPreservesRawRealitySNIAndShortIDRequirements() {
        let withoutSNI = Self.sampleVlessURL.replacingOccurrences(
            of: "&sni=example.com",
            with: ""
        )
        XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: withoutSNI)) { error in
            XCTAssertEqual(error as? XrayVlessURLImportError, .missingQueryValue("sni"))
        }

        let emptyShortID = Self.sampleVlessURL.replacingOccurrences(
            of: "sid=0123456789ab",
            with: "sid="
        )
        XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: emptyShortID)) { error in
            XCTAssertEqual(error as? XrayVlessURLImportError, .missingQueryValue("sid"))
        }
    }

    func testXHTTPRealityDoesNotExposeOrAcquireRealityVisionFlow() throws {
        let profile = try XrayVlessURLImporter.profile(from: Self.sampleXHTTPRealityURL)

        let migrated = profile.addingDefaultRealityVisionFlowIfMissing()

        XCTAssertEqual(migrated.configJSON, profile.configJSON)
        XCTAssertNil(migrated.realityVisionFlowMode)
        XCTAssertThrowsError(
            try profile.updatingRealityVisionFlowMode(.allowUDP443)
        ) { error in
            XCTAssertEqual(
                error as? XrayRealityVisionFlowError,
                .missingRealityVlessUser
            )
        }
        XCTAssertEqual(profile.realityFingerprintMode, .chrome)

        let updatedFingerprint = try profile.updatingRealityFingerprintMode(.hellochrome131)
        XCTAssertEqual(updatedFingerprint.realityFingerprintMode, .hellochrome131)
        XCTAssertNil(updatedFingerprint.realityVisionFlowMode)
        XCTAssertNil(try Self.firstVlessUserFlow(in: updatedFingerprint.configJSON))
    }

    func testVlessURLImporterRejectsInvalidXHTTPExtraWithoutRecursiveDecoding() throws {
        let encodedObject = try XCTUnwrap(
            "{}".addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let encodedTwice = try XCTUnwrap(
            encodedObject.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let encodedThreeTimes = try XCTUnwrap(
            encodedTwice.addingPercentEncoding(withAllowedCharacters: .alphanumerics)
        )
        let invalidValues = ["", "%5B%5D", "null", "7", "%7Bbroken", encodedThreeTimes]

        for value in invalidValues {
            let url = "vless://11111111-1111-4111-8111-111111111111@203.0.113.20:80"
                + "?type=xhttp&security=none&extra=\(value)"
            XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url), value) { error in
                XCTAssertEqual(error as? XrayVlessURLImportError, .invalidXHTTPExtra)
                if !value.isEmpty {
                    XCTAssertFalse(error.localizedDescription.contains(value))
                }
            }
        }
    }

    func testVlessURLImporterBoundsXHTTPExtraBeforeJSONParsing() {
        let oversized = String(repeating: "a", count: 64 * 1024 + 1)
        let url = "vless://11111111-1111-4111-8111-111111111111@203.0.113.20:80"
            + "?type=xhttp&security=none&extra=\(oversized)"

        XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url)) { error in
            XCTAssertEqual(error as? XrayVlessURLImportError, .xhttpExtraTooLarge)
        }
    }

    func testVlessURLImporterRejectsUnsupportedXHTTPCombinations() {
        for (query, expectedDescription) in [
            (
                "type=xhttp&security=xtls",
                "Unsupported VLESS security `xtls`. Expected `none or tls or reality`."
            ),
            (
                "type=xhttp&security=none&mode=burst",
                "Unsupported VLESS mode `burst`. Expected `auto or packet-up or stream-up or stream-one`."
            ),
            (
                "type=xhttp&security=none&flow=xtls-rprx-vision",
                "Unsupported VLESS flow `xtls-rprx-vision`. Expected `empty`."
            ),
        ] {
            let url = "vless://11111111-1111-4111-8111-111111111111@203.0.113.20:80?\(query)"
            XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url)) { error in
                XCTAssertEqual(error.localizedDescription, expectedDescription)
            }
        }
    }

    func testVlessURLImporterRejectsInvalidXHTTPTLSFields() {
        let cases = [
            (
                "sni=",
                "Unsupported VLESS sni ``. Expected `non-empty`."
            ),
            (
                "fp=",
                "Unsupported VLESS fp ``. Expected `non-empty`."
            ),
            (
                "alpn=",
                "Unsupported VLESS alpn ``. Expected `comma-separated values without spaces or empty entries`."
            ),
            (
                "alpn=h2%2C%2Chttp%2F1.1",
                "Unsupported VLESS alpn `h2,,http/1.1`. Expected `comma-separated values without spaces or empty entries`."
            ),
            (
                "alpn=h2%2C%20http%2F1.1",
                "Unsupported VLESS alpn `h2, http/1.1`. Expected `comma-separated values without spaces or empty entries`."
            ),
            (
                "allowInsecure=yes",
                "Unsupported VLESS allowInsecure `yes`. Expected `0 or 1 or false or true`."
            ),
            (
                "allowInsecure=",
                "Unsupported VLESS allowInsecure ``. Expected `0 or 1 or false or true`."
            ),
        ]

        for (field, expectedDescription) in cases {
            let url = "vless://11111111-1111-4111-8111-111111111111@example.com:443"
                + "?type=xhttp&security=tls&\(field)"
            XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url), field) { error in
                XCTAssertEqual(error.localizedDescription, expectedDescription)
            }
        }
    }

    func testVlessURLImporterRejectsRealityOnlyFieldsOnXHTTPTLS() {
        for field in ["pbk=value", "sid=", "spx=%2F", "pqv=value"] {
            let name = String(field.prefix(while: { $0 != "=" }))
            let url = "vless://11111111-1111-4111-8111-111111111111@example.com:443"
                + "?type=xhttp&security=tls&\(field)"
            XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url), field) { error in
                XCTAssertEqual(
                    error as? XrayVlessURLImportError,
                    .unsupportedQueryParameter(name)
                )
            }
        }
    }

    func testVlessURLImporterRejectsMissingXHTTPRealityRequiredFields() {
        let requiredFields = [
            ("pbk", "pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            ("fp", "fp=chrome"),
            ("sid", "sid=0123456789ab"),
        ]

        for (missingName, _) in requiredFields {
            let fields = requiredFields
                .filter { $0.0 != missingName }
                .map(\.1)
                .joined(separator: "&")
            let url = "vless://11111111-1111-4111-8111-111111111111@example.com:443"
                + "?type=xhttp&security=reality&\(fields)"
            XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url), missingName) { error in
                XCTAssertEqual(
                    error as? XrayVlessURLImportError,
                    .missingQueryValue(missingName)
                )
            }
        }
    }

    func testVlessURLImporterValidatesRealityOnlyTLSCompatibilityFields() throws {
        let baseURL = "vless://11111111-1111-4111-8111-111111111111@example.com:443"
            + "?type=xhttp&security=reality"
            + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sid="

        XCTAssertNoThrow(try XrayVlessURLImporter.profile(from: baseURL + "&alpn=h2"))

        for field in ["alpn=http%2F1.1", "alpn=h2%2Chttp%2F1.1"] {
            XCTAssertThrowsError(
                try XrayVlessURLImporter.profile(from: baseURL + "&\(field)"),
                field
            ) { error in
                guard case let .unsupportedQueryValue(name, _, expected) =
                    error as? XrayVlessURLImportError
                else {
                    return XCTFail("Unexpected error: \(error)")
                }
                XCTAssertEqual(name, "alpn")
                XCTAssertEqual(expected, "h2 or absent for Reality")
            }
        }

        for field in ["allowInsecure=0", "allowInsecure=false", "allowInsecure=1"] {
            XCTAssertThrowsError(
                try XrayVlessURLImporter.profile(from: baseURL + "&\(field)"),
                field
            ) { error in
                XCTAssertEqual(
                    error as? XrayVlessURLImportError,
                    .unsupportedQueryParameter("allowInsecure")
                )
            }
        }
    }

    func testVlessURLImporterFailsClosedForUnsupportedSecurityParametersWithoutLeakingValues() {
        let secretValue = "sensitive-security-material"
        for security in ["none", "tls", "reality"] {
            for name in ["pcs", "vcn", "ech", "echQuery"] {
                var query = "type=xhttp&security=\(security)&\(name)=\(secretValue)"
                if security == "reality" {
                    query += "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sid="
                }
                let url = "vless://11111111-1111-4111-8111-111111111111@example.com:443?\(query)"
                XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url), name) { error in
                    XCTAssertEqual(
                        error as? XrayVlessURLImportError,
                        .unsupportedQueryParameter(name)
                    )
                    XCTAssertFalse(error.localizedDescription.contains(secretValue))
                }
            }
        }
    }

    func testVlessURLImporterRejectsDuplicateXHTTPSecurityCriticalFields() {
        let duplicates = [
            ("security", "security=tls&security=tls"),
            ("sni", "security=tls&sni=one.example&sni=two.example"),
            ("fp", "security=tls&fp=chrome&fp=firefox"),
            ("alpn", "security=tls&alpn=h2&alpn=http%2F1.1"),
            ("allowInsecure", "security=tls&allowInsecure=0&allowInsecure=1"),
            ("extra", "security=none&extra=%7B%7D&extra=%7B%7D"),
            (
                "pbk",
                "security=reality&pbk=first&pbk=second&fp=chrome&sid="
            ),
            (
                "sid",
                "security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sid=&sid=01"
            ),
        ]

        for (name, fields) in duplicates {
            let url = "vless://11111111-1111-4111-8111-111111111111@example.com:443"
                + "?type=xhttp&\(fields)"
            XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url), name) { error in
                XCTAssertEqual(
                    error as? XrayVlessURLImportError,
                    .duplicateQueryValue(name)
                )
            }
        }
    }

    func testVlessURLImporterExtractsURLFromPastedText() throws {
        let pastedText = "configuration url:\n\(Self.sampleVlessURL)\n"

        let profile = try XrayVlessURLImporter.profile(
            from: pastedText,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "example-reality")
        XCTAssertEqual(profile.serverAddress, "203.0.113.10")
    }

    func testVlessURLImporterAcceptsSchemeLessAuthority() throws {
        let schemeLessURL = String(Self.sampleVlessURL.dropFirst("vless://".count))

        let profile = try XrayVlessURLImporter.profile(
            from: schemeLessURL,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "example-reality")
        XCTAssertEqual(profile.serverAddress, "203.0.113.10")
    }

    func testVlessURLImporterExtractsSchemeLessAuthorityFromPastedText() throws {
        let schemeLessURL = String(Self.sampleVlessURL.dropFirst("vless://".count))
        let pastedText = "configuration url:\n\(schemeLessURL)\n"

        let profile = try XrayVlessURLImporter.profile(
            from: pastedText,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        XCTAssertEqual(profile.name, "example-reality")
        XCTAssertEqual(profile.serverAddress, "203.0.113.10")
    }

    func testVlessURLImporterAcceptsRawTransportAlias() throws {
        let url = Self.sampleVlessURL.replacingOccurrences(of: "type=tcp", with: "type=raw")

        let profile = try XrayVlessURLImporter.profile(
            from: url,
            hostBundleIdentifier: "org.example.XrayClient"
        )

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "tcp")
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

    func testVlessURLImporterPreservesMissingRealityFlow() throws {
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
        XCTAssertNil(users.first?["flow"])
    }

    func testImportedConfigEnablesSniffingAndPinsDnsToIPv4() throws {
        let url = "vless://49c1a053-d257-466d-a900-048ff5173866@203.0.113.7:443"
            + "?flow=xtls-rprx-vision&type=tcp&security=reality&fp=chrome"
            + "&sni=example.com&pbk=3jNx5A3WTFKhvCj3IPljaxbcBjCxhH2dVCNobKv_X1c&sid=1c5694e878"

        let profile = try XrayVlessURLImporter.profile(
            from: url,
            providerBundleIdentifier: "com.example.tunnel",
            hostBundleIdentifier: "com.example"
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )

        let inbounds = try XCTUnwrap(root["inbounds"] as? [[String: Any]])
        let sniffing = try XCTUnwrap(inbounds.first?["sniffing"] as? [String: Any])
        XCTAssertEqual(sniffing["enabled"] as? Bool, true)
        XCTAssertEqual(sniffing["destOverride"] as? [String], ["http", "tls", "quic"])
        XCTAssertEqual(sniffing["metadataOnly"] as? Bool, false)

        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        XCTAssertEqual(dns["queryStrategy"] as? String, "UseIPv4")
    }

    private static func routingRules(in configJSON: String) throws -> [[String: Any]] {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        let routing = try XCTUnwrap(root["routing"] as? [String: Any])
        return try XCTUnwrap(routing["rules"] as? [[String: Any]])
    }

    private static func dnsObject(in configJSON: String) throws -> [String: Any] {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        return try XCTUnwrap(root["dns"] as? [String: Any])
    }

    private static func firstVlessUserFlow(in configJSON: String) throws -> String? {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let users = try XCTUnwrap(vnext.first?["users"] as? [[String: Any]])
        return users.first?["flow"] as? String
    }

    private static func firstRealityFingerprint(in configJSON: String) throws -> String? {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        let reality = try XCTUnwrap(stream["realitySettings"] as? [String: Any])
        return reality["fingerprint"] as? String
    }

    private static func configJSONRemovingFirstVlessUserFlow(_ configJSON: String) throws -> String {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        var mutableRoot = root
        var outbounds = try XCTUnwrap(mutableRoot["outbounds"] as? [[String: Any]])
        var settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        var vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        var users = try XCTUnwrap(vnext[0]["users"] as? [[String: Any]])
        users[0].removeValue(forKey: "flow")
        vnext[0]["users"] = users
        settings["vnext"] = vnext
        outbounds[0]["settings"] = settings
        mutableRoot["outbounds"] = outbounds

        let encoded = try JSONSerialization.data(
            withJSONObject: mutableRoot,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        return try XCTUnwrap(String(data: encoded, encoding: .utf8))
    }

    func testVlessURLImporterRejectsUnsupportedSecurity() {
        XCTAssertThrowsError(
            try XrayVlessURLImporter.profile(
                from: "vless://11111111-1111-4111-8111-111111111111@example.com:443?type=tcp&security=tls&encryption=none"
            )
        ) { error in
            XCTAssertEqual(
                error.localizedDescription,
                "Unsupported VLESS security `tls`. Expected `reality`."
            )
        }
    }
}
