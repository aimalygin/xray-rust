import XCTest
import XrayAppleShared
@testable import XrayAppleClient

@available(macOS 13.0, *)
@MainActor
final class XrayClientViewModelTests: XCTestCase {
    func testImportVlessURLIfPresentAppliesTrimmedURL() throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON,
                debugLoggingEnabled: true,
                tunRuntimeProfile: .throughput,
                regionalRoutingMode: .bypassSelected,
                regionalRoutingRegions: [.russia],
                dnsTestMode: .proxy,
                dnsTestTransport: .routedTCP,
                dnsTestUpstream: "192.0.2.53:5353"
            )
        )
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )

        XCTAssertTrue(viewModel.importVlessURLIfPresent("  \n\(Self.sampleVlessURL)\n  "))

        XCTAssertEqual(viewModel.profile.name, "example-reality")
        XCTAssertEqual(
            viewModel.profile.providerBundleIdentifier,
            "org.example.XrayClientTv.Tunnel"
        )
        XCTAssertEqual(viewModel.profile.serverAddress, "203.0.113.10")
        XCTAssertTrue(viewModel.profile.debugLoggingEnabled)
        XCTAssertEqual(viewModel.profile.tunRuntimeProfile, .throughput)
        XCTAssertEqual(viewModel.profile.regionalRoutingMode, .bypassSelected)
        XCTAssertEqual(viewModel.profile.regionalRoutingRegions, [.russia])
        XCTAssertEqual(viewModel.profile.dnsTestMode, .proxy)
        XCTAssertEqual(viewModel.profile.dnsTestTransport, .routedTCP)
        XCTAssertEqual(viewModel.profile.dnsTestUpstream, "192.0.2.53:5353")

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(
                with: Data(viewModel.profile.configJSON.utf8)
            ) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds.first?["protocol"] as? String, "vless")
    }

    func testImportXHTTPRealityValidatesAndSavesWithoutVisionFlow() throws {
        let store = try makeStore()
        let initialProfile = XrayClientProfile(
            name: "Existing",
            providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
            serverAddress: "old-server",
            configJSON: XrayClientProfile.directTunConfigJSON
        )
        try store.save(initialProfile)
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )

        XCTAssertTrue(viewModel.importVlessURL(Self.sampleXHTTPRealityURL))
        XCTAssertNil(viewModel.lastErrorMessage)
        XCTAssertEqual(viewModel.profile.name, "example-xhttp-reality")
        XCTAssertEqual(viewModel.profile.serverAddress, "203.0.113.30")
        XCTAssertNil(viewModel.realityVisionFlowMode)
        XCTAssertEqual(viewModel.realityFingerprintMode, .chrome)
        XCTAssertNil(try Self.firstVlessUserFlow(in: viewModel.profile.configJSON))

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(
                with: Data(viewModel.profile.configJSON.utf8)
            ) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        XCTAssertEqual(stream["network"] as? String, "xhttp")
        XCTAssertEqual(stream["security"] as? String, "reality")
        XCTAssertEqual(store.load().configJSON, viewModel.profile.configJSON)

        let reloadedViewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )
        XCTAssertNil(reloadedViewModel.realityVisionFlowMode)
        XCTAssertNil(try Self.firstVlessUserFlow(in: reloadedViewModel.profile.configJSON))
        XCTAssertEqual(reloadedViewModel.profile.configJSON, viewModel.profile.configJSON)
        XCTAssertEqual(store.load().configJSON, viewModel.profile.configJSON)
    }

    func testImportVlessURLIfPresentIgnoresBlankInput() throws {
        let store = try makeStore()
        let initialProfile = XrayClientProfile(
            name: "Existing",
            providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
            serverAddress: "old-server",
            configJSON: XrayClientProfile.directTunConfigJSON
        )
        try store.save(initialProfile)
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )

        XCTAssertFalse(viewModel.importVlessURLIfPresent("  \n  "))

        XCTAssertEqual(viewModel.profile, initialProfile)
    }

    func testImportVlessURLIfPresentRejectsTruncatedInput() throws {
        let store = try makeStore()
        let initialProfile = XrayClientProfile(
            name: "Existing",
            providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
            serverAddress: "old-server",
            configJSON: XrayClientProfile.directTunConfigJSON
        )
        try store.save(initialProfile)
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )

        XCTAssertFalse(
            viewModel.importVlessURLIfPresent(
                "tail-only-fragment&flow=xtls-rprx-vision#example-reality"
            )
        )

        XCTAssertEqual(viewModel.profile, initialProfile)
        XCTAssertEqual(store.load(), initialProfile)
        XCTAssertEqual(
            viewModel.lastErrorMessage,
            "Pasted text is not a complete VLESS URL."
        )
    }

    func testConnectNormalizesSavedRealityConfigWithoutFlow() async throws {
        let store = try makeStore()
        let configWithoutFlow = try Self.configJSONWithoutFlow()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "203.0.113.10",
                configJSON: configWithoutFlow,
                debugLoggingEnabled: true,
                dnsTestMode: .defaultDNS
            )
        )
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        await viewModel.connectOrDisconnect()

        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: startedProfile.configJSON),
            "xtls-rprx-vision"
        )
        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: store.load().configJSON),
            "xtls-rprx-vision"
        )
    }

    func testSetRealityVisionFlowModeSavesUpdatedProfile() throws {
        let store = try makeStore()
        let importedProfile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        )
        try store.save(importedProfile)
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )

        viewModel.setRealityVisionFlowMode(.allowUDP443)

        XCTAssertEqual(viewModel.realityVisionFlowMode, .allowUDP443)
        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: viewModel.profile.configJSON),
            XrayClientProfile.realityVisionUDP443Flow
        )
        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: store.load().configJSON),
            XrayClientProfile.realityVisionUDP443Flow
        )
        XCTAssertNil(viewModel.lastErrorMessage)
    }

    func testSetRealityFingerprintModeSavesUpdatedProfile() throws {
        let store = try makeStore()
        let importedProfile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        )
        try store.save(importedProfile)
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )

        viewModel.setRealityFingerprintMode(.hellochrome131)

        XCTAssertEqual(viewModel.realityFingerprintMode, .hellochrome131)
        XCTAssertEqual(
            try Self.firstRealityFingerprint(in: viewModel.profile.configJSON),
            "hellochrome_131"
        )
        XCTAssertEqual(
            try Self.firstRealityFingerprint(in: store.load().configJSON),
            "hellochrome_131"
        )
        XCTAssertNil(viewModel.lastErrorMessage)
    }

    func testConnectImportsPendingVlessURLBeforeStartingTunnel() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON,
                debugLoggingEnabled: true,
                useTunFileDescriptor: true,
                dnsTestMode: .defaultDNS
            )
        )
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        let didAcceptPendingURL = await viewModel.connectOrDisconnect(
            importingVlessURLIfPresent: Self.sampleVlessURL
        )

        XCTAssertTrue(didAcceptPendingURL)

        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        XCTAssertEqual(startedProfile.serverAddress, "203.0.113.10")
        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: startedProfile.configJSON),
            "xtls-rprx-vision"
        )
        XCTAssertEqual(store.load().serverAddress, "203.0.113.10")
    }

    func testConnectStartsSavedProfileWhenPendingInputIsBlank() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON,
                dnsTestMode: .defaultDNS
            )
        )
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        let didAcceptPendingURL = await viewModel.connectOrDisconnect(
            importingVlessURLIfPresent: " \n "
        )

        XCTAssertTrue(didAcceptPendingURL)
        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        XCTAssertEqual(startedProfile.serverAddress, "old-server")
        XCTAssertEqual(viewModel.profile.serverAddress, "old-server")
        XCTAssertEqual(store.load().serverAddress, "old-server")
        XCTAssertNil(viewModel.lastErrorMessage)
    }

    func testConnectRejectsTruncatedPendingInputWithoutStartingSavedProfile() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON
            )
        )
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        let didAcceptPendingURL = await viewModel.connectOrDisconnect(
            importingVlessURLIfPresent: "none&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome"
        )

        XCTAssertFalse(didAcceptPendingURL)
        XCTAssertNil(tunnelController.startedProfile)
        XCTAssertEqual(viewModel.profile.serverAddress, "old-server")
        XCTAssertEqual(store.load().serverAddress, "old-server")
        XCTAssertEqual(
            viewModel.lastErrorMessage,
            "Pasted text is not a complete VLESS URL."
        )
    }

    func testConnectDoesNotStartOldProfileWhenFullPendingVlessURLImportFails() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON
            )
        )
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        let didAcceptPendingURL = await viewModel.connectOrDisconnect(
            importingVlessURLIfPresent: "vless://not-a-uuid@203.0.113.10:32134?type=tcp"
        )

        XCTAssertFalse(didAcceptPendingURL)
        XCTAssertNil(tunnelController.startedProfile)
        XCTAssertEqual(viewModel.profile.serverAddress, "old-server")
        XCTAssertEqual(store.load().serverAddress, "old-server")
        XCTAssertEqual(
            viewModel.lastErrorMessage,
            "Invalid VLESS user id `not-a-uuid`."
        )
    }

    func testConnectStartsTunnelWithEffectiveRegionalRoutingConfigWithoutSavingGeneratedRules() async throws {
        let store = try makeStore()
        let importedProfile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        )
        var routableProfile = importedProfile.updatingRegionalRouting(
            mode: .bypassSelected,
            regions: [.china]
        )
        routableProfile.dnsTestMode = .defaultDNS
        try store.save(routableProfile)
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController,
            geodataSearchDirectory: Self.geodataDirectoryURL
        )

        await viewModel.connectOrDisconnect()

        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        XCTAssertNotEqual(startedProfile.configJSON, routableProfile.configJSON)
        XCTAssertEqual(try Self.firstRoutingRuleDomains(in: startedProfile.configJSON), ["geosite:cn"])
        XCTAssertEqual(store.load().configJSON, routableProfile.configJSON)
    }

    func testConnectStartsTunnelWithEffectiveDNSConfigWithoutChangingSourceJSON() async throws {
        let store = try makeStore()
        var importedProfile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        )
        importedProfile.dnsTestMode = .proxy
        importedProfile.dnsTestTransport = .routedTCP
        importedProfile.dnsTestUpstream = "192.0.2.53:5353"
        let sourceConfigJSON = importedProfile.configJSON
        try store.save(importedProfile)
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        await viewModel.connectOrDisconnect()

        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        let startedDNS = try Self.dnsObject(in: startedProfile.configJSON)
        XCTAssertEqual(startedDNS["queryStrategy"] as? String, "UseIPv4")
        XCTAssertEqual(startedDNS["servers"] as? [String], ["tcp://192.0.2.53:5353"])
        XCTAssertNil(startedDNS["fakeIp"])
        XCTAssertEqual(store.load().configJSON, sourceConfigJSON)
        XCTAssertEqual(store.load().dnsTestMode, .proxy)
        XCTAssertEqual(viewModel.profile.configJSON, sourceConfigJSON)
        XCTAssertNil(viewModel.lastErrorMessage)
    }

    func testConnectRejectsDNSProxyWithoutUpstreamBeforeStartingTunnel() async throws {
        let store = try makeStore()
        var importedProfile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        )
        importedProfile.dnsTestMode = .proxy
        try store.save(importedProfile)
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        await viewModel.connectOrDisconnect()

        XCTAssertNil(tunnelController.startedProfile)
        XCTAssertEqual(
            viewModel.lastErrorMessage,
            "DNS proxy test mode requires an upstream host or IP."
        )
    }

    func testConnectRejectsConfigJSONWithoutMobileDNSBeforeStartingTunnel() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "No DNS",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON
            )
        )
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        await viewModel.connectOrDisconnect()

        XCTAssertNil(tunnelController.startedProfile)
        XCTAssertEqual(
            viewModel.lastErrorMessage,
            XrayMobileDNSPreflightError.unavailable.localizedDescription
        )
    }

    func testConnectRejectsFakeDNSWithoutUpstreamAndDomainFreedomRule() async throws {
        let store = try makeStore()
        var profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        ).updatingRegionalRouting(mode: .bypassSelected, regions: [.russia])
        profile.dnsTestMode = .fakeIP
        profile.dnsTestUpstream = ""
        try store.save(profile)
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController,
            geodataSearchDirectory: Self.geodataDirectoryURL
        )

        await viewModel.connectOrDisconnect()

        XCTAssertNil(tunnelController.startedProfile)
        XCTAssertEqual(
            viewModel.lastErrorMessage,
            XrayMobileDNSPreflightError.unsafeFakeIPFreedomRouting.localizedDescription
        )
    }

    func testConnectDefaultDNSPresetPassesMobilePreflight() async throws {
        let store = try makeStore()
        var profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        )
        profile.dnsTestMode = .defaultDNS
        try store.save(profile)
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        await viewModel.connectOrDisconnect()

        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        let dns = try Self.dnsObject(in: startedProfile.configJSON)
        XCTAssertNotNil(dns["fakeIp"])
        XCTAssertEqual(dns["servers"] as? [String], ["tcp://1.1.1.1"])
        XCTAssertNil(viewModel.lastErrorMessage)
    }

    func testConnectAcceptsConfirmedManualFakeDNSRegionalRoutingCombination() async throws {
        let store = try makeStore()
        var profile = try XrayVlessURLImporter.profile(
            from: Self.sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        ).updatingRegionalRouting(mode: .bypassSelected, regions: [.russia])
        profile.dnsTestMode = .fakeIP
        profile.dnsTestTransport = .routedTCP
        profile.dnsTestUpstream = "1.1.1.1"
        try store.save(profile)
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController,
            geodataSearchDirectory: Self.geodataDirectoryURL
        )

        await viewModel.connectOrDisconnect()

        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        let dns = try Self.dnsObject(in: startedProfile.configJSON)
        XCTAssertNotNil(dns["fakeIp"])
        XCTAssertEqual(dns["servers"] as? [String], ["tcp://1.1.1.1"])
        XCTAssertEqual(
            try Self.firstRoutingRuleDomains(in: startedProfile.configJSON),
            ["geosite:category-ru"]
        )
        XCTAssertNil(viewModel.lastErrorMessage)
    }

    func testConnectSurfacesAsynchronousTunnelStartupFailure() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON,
                dnsTestMode: .defaultDNS
            )
        )
        let tunnelController = MockTunnelController()
        tunnelController.startError = MockTunnelStartupError(
            message: "VPN failed to start: DNS configuration is unavailable."
        )
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )

        await viewModel.connectOrDisconnect()

        XCTAssertNotNil(tunnelController.startedProfile)
        XCTAssertEqual(viewModel.connectionStatus, .disconnected)
        XCTAssertEqual(
            viewModel.lastErrorMessage,
            "VPN failed to start: DNS configuration is unavailable."
        )
        XCTAssertFalse(viewModel.isBusy)
    }

    func testObservedConnectedDisconnectingDisconnectedSurfacesProviderError() async throws {
        let store = try makeStore()
        let tunnelController = StatusObservingMockTunnelController(status: .connected)
        tunnelController.disconnectError = NSError(
            domain: "org.xrayrust.tests.provider",
            code: 2,
            userInfo: [NSLocalizedDescriptionKey: "Packet pump failed."]
        )
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )
        await waitUntil("status observation subscription") {
            tunnelController.statusUpdatesRequested
        }
        await waitUntil("initial connected status") {
            viewModel.connectionStatus == .connected
        }

        tunnelController.emit(.disconnecting)
        tunnelController.emit(.disconnected)

        await waitUntil("unexpected disconnect error") {
            viewModel.lastErrorMessage == "VPN disconnected: Packet pump failed."
        }
        XCTAssertEqual(viewModel.connectionStatus, .disconnected)
        XCTAssertEqual(tunnelController.disconnectErrorRequests, 1)
    }

    func testCloseActiveConnectionsRequestsProviderAndRefreshesStats() async throws {
        let store = try makeStore()
        let tunnelController = StatusObservingMockTunnelController(status: .connected)
        tunnelController.runtimeStatsResponse = XrayClientRuntimeStats(
            inboundPackets: 11,
            outboundPackets: 13,
            droppedPackets: 0,
            activeTCPFlows: 0,
            activeUDPFlows: 0
        )
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )
        await waitUntil("initial connected status") {
            viewModel.connectionStatus == .connected
        }

        await viewModel.closeActiveConnections()

        XCTAssertEqual(tunnelController.closeConnectionsRequests, 1)
        XCTAssertEqual(viewModel.lastClosedConnections, 1)
        XCTAssertEqual(viewModel.runtimeStats, tunnelController.runtimeStatsResponse)
        XCTAssertFalse(viewModel.isBusy)
        XCTAssertNil(viewModel.lastErrorMessage)
    }

    func testPersistentObserverDoesNotOverwriteExactStartupFailure() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON,
                dnsTestMode: .defaultDNS
            )
        )
        let tunnelController = StatusObservingMockTunnelController(status: .disconnected)
        tunnelController.disconnectError = NSError(
            domain: "org.xrayrust.tests.provider",
            code: 3,
            userInfo: [NSLocalizedDescriptionKey: "Delayed generic disconnect."]
        )
        tunnelController.startAction = { [weak tunnelController] in
            tunnelController?.emit(.connected)
            tunnelController?.emit(.disconnecting)
            tunnelController?.emit(.disconnected)
            try await Task.sleep(nanoseconds: 20_000_000)
            throw MockTunnelStartupError(message: "Exact startup failure.")
        }
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController
        )
        await waitUntil("status observation subscription") {
            tunnelController.statusUpdatesRequested
        }

        await viewModel.connectOrDisconnect()

        await waitUntil("delayed disconnect error fetch") {
            tunnelController.disconnectErrorRequests == 1
        }
        XCTAssertEqual(viewModel.lastErrorMessage, "Exact startup failure.")
        XCTAssertEqual(viewModel.connectionStatus, .disconnected)
    }

    private func waitUntil(
        _ description: String,
        condition: @MainActor () -> Bool,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        for _ in 0 ..< 500 {
            if condition() {
                return
            }
            try? await Task.sleep(nanoseconds: 1_000_000)
        }
        XCTFail("Timed out waiting for \(description)", file: file, line: line)
    }

    private func makeStore() throws -> XrayClientProfileStore {
        let suiteName = "org.xrayrust.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        return XrayClientProfileStore(
            defaults: defaults,
            key: "profile",
            secureConfigStore: TestSecureConfigStore()
        )
    }

    private static var geodataDirectoryURL: URL {
        let workingDirectoryURLs = [
            ProcessInfo.processInfo.environment["PWD"],
            FileManager.default.currentDirectoryPath
        ]
            .compactMap { $0 }
            .map { URL(fileURLWithPath: $0) }

        let packageDirectoryURL = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        let candidateURLs = workingDirectoryURLs.flatMap {
            [
                $0.appendingPathComponent("XrayClient/dat"),
                $0.appendingPathComponent("platform/apple/XrayClient/dat")
            ]
        } + [
            packageDirectoryURL.appendingPathComponent("XrayClient/dat")
        ]

        return candidateURLs.first(where: containsGeodataFiles)
            ?? packageDirectoryURL.appendingPathComponent("XrayClient/dat")
    }

    private static func containsGeodataFiles(_ directoryURL: URL) -> Bool {
        let fileManager = FileManager.default
        let geositeURL = directoryURL.appendingPathComponent("geosite.dat")
        let geoipURL = directoryURL.appendingPathComponent("geoip.dat")
        return fileManager.fileExists(atPath: geositeURL.path)
            && fileManager.fileExists(atPath: geoipURL.path)
    }

    private static func dnsObject(in configJSON: String) throws -> [String: Any] {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        return try XCTUnwrap(root["dns"] as? [String: Any])
    }

    private static func configJSONWithoutFlow() throws -> String {
        let profile = try XrayVlessURLImporter.profile(
            from: sampleVlessURL,
            hostBundleIdentifier: "org.example.XrayClientTv"
        )
        let data = Data(profile.configJSON.utf8)
        var root = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        var outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        var settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        var vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        var users = try XCTUnwrap(vnext[0]["users"] as? [[String: Any]])
        users[0].removeValue(forKey: "flow")
        vnext[0]["users"] = users
        settings["vnext"] = vnext
        outbounds[0]["settings"] = settings
        root["outbounds"] = outbounds

        let encoded = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        return try XCTUnwrap(String(data: encoded, encoding: .utf8))
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

    private static func firstRoutingRuleDomains(in configJSON: String) throws -> [String]? {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        let routing = try XCTUnwrap(root["routing"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
        return rules.first?["domain"] as? [String]
    }

    private static let sampleVlessURL = "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:32134?type=tcp&encryption=none&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sni=example.com&sid=0123456789ab&spx=%2F&flow=xtls-rprx-vision#example-reality"
    private static let sampleXHTTPRealityURL = "vless://11111111-1111-4111-8111-111111111111@203.0.113.30:443?type=xhttp&encryption=none&security=reality&host=edge.example&path=%2Fxhttp&mode=packet-up&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sni=reality.example&sid=0123456789ab&spx=%2F#example-xhttp-reality"
}

private final class TestSecureConfigStore: XraySecureConfigStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]

    func store(configJSON: String, reference: String) throws {
        lock.lock()
        values[reference] = configJSON
        lock.unlock()
    }

    func configJSON(reference: String) throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        return values[reference]
    }

    func remove(reference: String) throws {
        lock.lock()
        values.removeValue(forKey: reference)
        lock.unlock()
    }
}

@available(macOS 13.0, *)
@MainActor
private final class MockTunnelController: XrayClientTunnelControlling {
    private(set) var startedProfile: XrayClientProfile?
    var startError: Error?

    func currentStatus() async -> XrayClientConnectionStatus {
        .disconnected
    }

    func start(profile: XrayClientProfile) async throws {
        startedProfile = profile
        if let startError {
            throw startError
        }
    }

    func stop() async throws {}

    func runtimeStats() async throws -> XrayClientRuntimeStats? {
        nil
    }
}

@available(macOS 13.0, *)
@MainActor
private final class StatusObservingMockTunnelController: XrayClientTunnelControlling {
    private let statusStream: AsyncStream<XrayClientConnectionStatus>
    private let statusContinuation: AsyncStream<XrayClientConnectionStatus>.Continuation

    private(set) var startedProfile: XrayClientProfile?
    private(set) var statusUpdatesRequested = false
    private(set) var disconnectErrorRequests = 0
    private(set) var closeConnectionsRequests = 0
    var status: XrayClientConnectionStatus
    var disconnectError: Error?
    var runtimeStatsResponse: XrayClientRuntimeStats?
    var startAction: (@MainActor () async throws -> Void)?

    init(status: XrayClientConnectionStatus) {
        self.status = status
        var capturedContinuation: AsyncStream<XrayClientConnectionStatus>.Continuation?
        statusStream = AsyncStream(bufferingPolicy: .unbounded) { continuation in
            capturedContinuation = continuation
        }
        guard let capturedContinuation else {
            preconditionFailure("AsyncStream must synchronously provide its continuation")
        }
        statusContinuation = capturedContinuation
    }

    func currentStatus() async -> XrayClientConnectionStatus {
        status
    }

    func statusUpdates() async -> AsyncStream<XrayClientConnectionStatus> {
        statusUpdatesRequested = true
        statusContinuation.yield(status)
        return statusStream
    }

    func lastDisconnectError() async -> Error? {
        disconnectErrorRequests += 1
        return disconnectError
    }

    func start(profile: XrayClientProfile) async throws {
        startedProfile = profile
        try await startAction?()
    }

    func stop() async throws {
        emit(.disconnecting)
        emit(.disconnected)
    }

    func runtimeStats() async throws -> XrayClientRuntimeStats? {
        runtimeStatsResponse
    }

    func closeActiveConnections() async throws -> UInt64 {
        closeConnectionsRequests += 1
        return 1
    }

    func emit(_ status: XrayClientConnectionStatus) {
        self.status = status
        statusContinuation.yield(status)
    }

    deinit {
        statusContinuation.finish()
    }
}

private struct MockTunnelStartupError: LocalizedError {
    let message: String

    var errorDescription: String? {
        message
    }
}
