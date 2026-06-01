import Foundation
import XrayAppleShared

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
@MainActor
public final class XrayClientViewModel: ObservableObject {
    @Published public var profile: XrayClientProfile
    @Published public private(set) var connectionStatus: XrayClientConnectionStatus = .unknown
    @Published public private(set) var runtimeStats: XrayClientRuntimeStats?
    @Published public private(set) var lastErrorMessage: String?
    @Published public private(set) var isBusy = false

    private let store: XrayClientProfileStore
    private let tunnelController: any XrayClientTunnelControlling

    public init(
        store: XrayClientProfileStore = XrayClientProfileStore(),
        tunnelController: (any XrayClientTunnelControlling)? = nil
    ) {
        self.store = store
        let loadedProfile = store.load()
        let migratedProfile = loadedProfile.migratingLegacyDefaultProviderBundleIdentifier()
        let preparedProfile = migratedProfile.addingDefaultRealityVisionFlowIfMissing()
        if preparedProfile != loadedProfile {
            XrayAppleLog.info(
                "ClientViewModel",
                "Prepared loaded profile provider=\(preparedProfile.providerBundleIdentifier) configBytes=\(preparedProfile.configJSON.utf8.count)"
            )
            do {
                try store.save(preparedProfile)
            } catch {
                XrayAppleLog.error(
                    "ClientViewModel",
                    "Failed to persist prepared profile: \(error.localizedDescription)"
                )
            }
        }
        self.profile = preparedProfile
        self.tunnelController = tunnelController ?? NetworkExtensionTunnelController()
        XrayAppleLog.info(
            "ClientViewModel",
            "Loaded profile name=\(profile.name) provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count) debugLogging=\(profile.debugLoggingEnabled) useTunFileDescriptor=\(profile.useTunFileDescriptor) blockQUIC=\(profile.blockQUIC)"
        )
    }

    public func refresh() async {
        XrayAppleLog.info("ClientViewModel", "Refreshing tunnel status")
        connectionStatus = await tunnelController.currentStatus()
        XrayAppleLog.info(
            "ClientViewModel",
            "Tunnel status is \(connectionStatus.displayName)"
        )
        guard connectionStatus == .connected else {
            runtimeStats = nil
            return
        }

        do {
            runtimeStats = try await tunnelController.runtimeStats()
            if let runtimeStats {
                XrayAppleLog.info(
                    "ClientViewModel",
                    "Runtime stats inbound=\(runtimeStats.inboundPackets) outbound=\(runtimeStats.outboundPackets) dropped=\(runtimeStats.droppedPackets)"
                )
            } else {
                XrayAppleLog.info("ClientViewModel", "Runtime stats are unavailable")
            }
        } catch {
            runtimeStats = nil
            XrayAppleLog.error(
                "ClientViewModel",
                "Failed to fetch runtime stats: \(error.localizedDescription)"
            )
        }
    }

    public func saveProfile() {
        normalizeProfileIfNeeded()
        XrayAppleLog.info(
            "ClientViewModel",
            "Saving profile name=\(profile.name) provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count) debugLogging=\(profile.debugLoggingEnabled) useTunFileDescriptor=\(profile.useTunFileDescriptor) blockQUIC=\(profile.blockQUIC)"
        )
        do {
            try store.save(profile)
            lastErrorMessage = nil
            XrayAppleLog.info("ClientViewModel", "Profile saved")
        } catch {
            lastErrorMessage = error.localizedDescription
            XrayAppleLog.error(
                "ClientViewModel",
                "Failed to save profile: \(error.localizedDescription)"
            )
        }
    }

    @discardableResult
    public func importVlessURL(_ rawURL: String) -> Bool {
        XrayAppleLog.info(
            "ClientViewModel",
            "Importing VLESS URL bytes=\(rawURL.utf8.count)"
        )
        do {
            var importedProfile = try XrayVlessURLImporter.profile(
                from: rawURL,
                providerBundleIdentifier: profile.providerBundleIdentifier
            )
            importedProfile = importedProfile.addingDefaultRealityVisionFlowIfMissing()
            importedProfile.debugLoggingEnabled = profile.debugLoggingEnabled
            importedProfile.useTunFileDescriptor = profile.useTunFileDescriptor
            importedProfile.blockQUIC = profile.blockQUIC
            XrayAppleLog.info(
                "ClientViewModel",
                "Imported VLESS profile name=\(importedProfile.name) provider=\(importedProfile.providerBundleIdentifier) server=\(importedProfile.serverAddress) configBytes=\(importedProfile.configJSON.utf8.count)"
            )
            try XrayConfigValidator.validate(importedProfile.configJSON)
            XrayAppleLog.info("ClientViewModel", "Imported VLESS config validated")
            profile = importedProfile
            try store.save(importedProfile)
            lastErrorMessage = nil
            XrayAppleLog.info("ClientViewModel", "Imported VLESS profile saved")
            return true
        } catch {
            lastErrorMessage = error.localizedDescription
            XrayAppleLog.error(
                "ClientViewModel",
                "Failed to import VLESS URL: \(error.localizedDescription)"
            )
            return false
        }
    }

    @discardableResult
    public func importVlessURLIfPresent(_ rawURL: String) -> Bool {
        let trimmedURL = rawURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedURL.isEmpty else {
            return false
        }
        return importVlessURL(trimmedURL)
    }

    public func connectOrDisconnect() async {
        guard !isBusy else {
            XrayAppleLog.info("ClientViewModel", "Ignoring connect action while busy")
            return
        }

        isBusy = true
        defer { isBusy = false }

        do {
            if connectionStatus.isActive {
                XrayAppleLog.info(
                    "ClientViewModel",
                    "Stopping tunnel from status \(connectionStatus.displayName)"
                )
                try await tunnelController.stop()
            } else {
                normalizeProfileIfNeeded()
                XrayAppleLog.info(
                    "ClientViewModel",
                    "Starting tunnel provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count) debugLogging=\(profile.debugLoggingEnabled) useTunFileDescriptor=\(profile.useTunFileDescriptor) blockQUIC=\(profile.blockQUIC)"
                )
                try XrayConfigValidator.validate(profile.configJSON)
                XrayAppleLog.info("ClientViewModel", "Config validation passed before start")
                try store.save(profile)
                XrayAppleLog.info("ClientViewModel", "Profile saved before start")
                try await tunnelController.start(profile: profile)
                XrayAppleLog.info("ClientViewModel", "Start tunnel request returned")
            }
            lastErrorMessage = nil
            await refresh()
        } catch {
            lastErrorMessage = error.localizedDescription
            XrayAppleLog.error(
                "ClientViewModel",
                "Connect action failed: \(error.localizedDescription)"
            )
            await refresh()
        }
    }

    @discardableResult
    public func connectOrDisconnect(importingVlessURLIfPresent rawURL: String) async -> Bool {
        let trimmedURL = rawURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if connectionStatus.isActive {
            if !trimmedURL.isEmpty {
                XrayAppleLog.info(
                    "ClientViewModel",
                    "Skipping pending VLESS URL import while tunnel is active; disconnect will run first"
                )
            }
            await connectOrDisconnect()
            return true
        }

        if trimmedURL.isEmpty {
            XrayAppleLog.info("ClientViewModel", "Connect action has no pending VLESS URL")
        } else if !Self.looksLikeVlessURL(trimmedURL) {
            XrayAppleLog.info(
                "ClientViewModel",
                "Ignoring pending text that is not a full VLESS URL bytes=\(trimmedURL.utf8.count)"
            )
        } else {
            XrayAppleLog.info(
                "ClientViewModel",
                "Connect action has pending VLESS URL bytes=\(trimmedURL.utf8.count)"
            )
            guard importVlessURL(trimmedURL) else {
                XrayAppleLog.info(
                    "ClientViewModel",
                    "Connect action aborted because pending VLESS URL import failed"
                )
                return false
            }
        }

        await connectOrDisconnect()
        return true
    }

    private static func looksLikeVlessURL(_ text: String) -> Bool {
        if text.range(of: "vless://", options: .caseInsensitive) != nil {
            return true
        }

        return text.range(
            of: #"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@"#,
            options: .regularExpression
        ) != nil
    }

    private func normalizeProfileIfNeeded() {
        let normalizedProfile = profile.addingDefaultRealityVisionFlowIfMissing()
        guard normalizedProfile != profile else {
            return
        }
        profile = normalizedProfile
        XrayAppleLog.info(
            "ClientViewModel",
            "Normalized profile configBytes=\(profile.configJSON.utf8.count)"
        )
    }
}
