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
                regionalRoutingRegions: [.russia]
            )
        )
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: MockTunnelController()
        )

        XCTAssertTrue(viewModel.importVlessURLIfPresent("  \n\(Self.sampleVlessURL)\n  "))

        XCTAssertEqual(viewModel.profile.name, "other-port-test-xray-rust")
        XCTAssertEqual(
            viewModel.profile.providerBundleIdentifier,
            "org.example.XrayClientTv.Tunnel"
        )
        XCTAssertEqual(viewModel.profile.serverAddress, "217.154.252.68")
        XCTAssertTrue(viewModel.profile.debugLoggingEnabled)
        XCTAssertEqual(viewModel.profile.tunRuntimeProfile, .throughput)
        XCTAssertEqual(viewModel.profile.regionalRoutingMode, .bypassSelected)
        XCTAssertEqual(viewModel.profile.regionalRoutingRegions, [.russia])

        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(
                with: Data(viewModel.profile.configJSON.utf8)
            ) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        XCTAssertEqual(outbounds.first?["protocol"] as? String, "vless")
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

    func testConnectNormalizesSavedRealityConfigWithoutFlow() async throws {
        let store = try makeStore()
        let configWithoutFlow = try Self.configJSONWithoutFlow()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "217.154.252.68",
                configJSON: configWithoutFlow,
                debugLoggingEnabled: true
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

    func testConnectImportsPendingVlessURLBeforeStartingTunnel() async throws {
        let store = try makeStore()
        try store.save(
            XrayClientProfile(
                name: "Existing",
                providerBundleIdentifier: "org.example.XrayClientTv.Tunnel",
                serverAddress: "old-server",
                configJSON: XrayClientProfile.directTunConfigJSON,
                debugLoggingEnabled: true,
                useTunFileDescriptor: true
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
        XCTAssertEqual(startedProfile.serverAddress, "217.154.252.68")
        XCTAssertEqual(
            try Self.firstVlessUserFlow(in: startedProfile.configJSON),
            "xtls-rprx-vision"
        )
        XCTAssertEqual(store.load().serverAddress, "217.154.252.68")
    }

    func testConnectIgnoresNonVlessPendingTextAndStartsSavedProfile() async throws {
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
            importingVlessURLIfPresent: "none&security=reality"
        )

        XCTAssertTrue(didAcceptPendingURL)
        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        XCTAssertEqual(startedProfile.serverAddress, "old-server")
        XCTAssertEqual(viewModel.profile.serverAddress, "old-server")
        XCTAssertEqual(store.load().serverAddress, "old-server")
        XCTAssertNil(viewModel.lastErrorMessage)
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
            importingVlessURLIfPresent: "vless://not-a-uuid@217.154.252.68:32134?type=tcp"
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
        ).updatingRegionalRouting(mode: .bypassSelected, regions: [.china])
        try store.save(importedProfile)
        let tunnelController = MockTunnelController()
        let viewModel = XrayClientViewModel(
            store: store,
            tunnelController: tunnelController,
            geodataSearchDirectory: Self.geodataDirectoryURL
        )

        await viewModel.connectOrDisconnect()

        let startedProfile = try XCTUnwrap(tunnelController.startedProfile)
        XCTAssertNotEqual(startedProfile.configJSON, importedProfile.configJSON)
        XCTAssertEqual(try Self.firstRoutingRuleDomains(in: startedProfile.configJSON), ["geosite:cn"])
        XCTAssertEqual(store.load().configJSON, importedProfile.configJSON)
    }

    private func makeStore() throws -> XrayClientProfileStore {
        let suiteName = "org.xrayrust.tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        return XrayClientProfileStore(
            defaults: defaults,
            key: "profile"
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

    private static func firstRoutingRuleDomains(in configJSON: String) throws -> [String]? {
        let root = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(configJSON.utf8)) as? [String: Any]
        )
        let routing = try XCTUnwrap(root["routing"] as? [String: Any])
        let rules = try XCTUnwrap(routing["rules"] as? [[String: Any]])
        return rules.first?["domain"] as? [String]
    }

    private static let sampleVlessURL = "vless://41dac315-fc32-4957-aded-6010b8f62fef@217.154.252.68:32134?type=tcp&encryption=none&security=reality&pbk=3jNx5A3WTFKhvCj3IPljaxbcBjCxhH2dVCNobKv_X1c&fp=chrome&sni=google.com&sid=1c5694e878&spx=%2F&flow=xtls-rprx-vision#other-port-test-xray-rust"
}

@available(macOS 13.0, *)
@MainActor
private final class MockTunnelController: XrayClientTunnelControlling {
    private(set) var startedProfile: XrayClientProfile?

    func currentStatus() async -> XrayClientConnectionStatus {
        .disconnected
    }

    func start(profile: XrayClientProfile) async throws {
        startedProfile = profile
    }

    func stop() async throws {}

    func runtimeStats() async throws -> XrayClientRuntimeStats? {
        nil
    }
}
