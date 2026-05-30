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
        if migratedProfile != loadedProfile {
            XrayAppleLog.info(
                "ClientViewModel",
                "Migrated provider bundle id from \(loadedProfile.providerBundleIdentifier) to \(migratedProfile.providerBundleIdentifier)"
            )
            do {
                try store.save(migratedProfile)
            } catch {
                XrayAppleLog.error(
                    "ClientViewModel",
                    "Failed to persist migrated profile: \(error.localizedDescription)"
                )
            }
        }
        self.profile = migratedProfile
        self.tunnelController = tunnelController ?? NetworkExtensionTunnelController()
        XrayAppleLog.info(
            "ClientViewModel",
            "Loaded profile name=\(profile.name) provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count)"
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
        XrayAppleLog.info(
            "ClientViewModel",
            "Saving profile name=\(profile.name) provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count)"
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

    public func importVlessURL(_ rawURL: String) {
        XrayAppleLog.info(
            "ClientViewModel",
            "Importing VLESS URL bytes=\(rawURL.utf8.count)"
        )
        do {
            let importedProfile = try XrayVlessURLImporter.profile(
                from: rawURL,
                providerBundleIdentifier: profile.providerBundleIdentifier
            )
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
        } catch {
            lastErrorMessage = error.localizedDescription
            XrayAppleLog.error(
                "ClientViewModel",
                "Failed to import VLESS URL: \(error.localizedDescription)"
            )
        }
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
                XrayAppleLog.info(
                    "ClientViewModel",
                    "Starting tunnel provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count)"
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
}
