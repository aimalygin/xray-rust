import Foundation
import XrayAppleShared

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension

private struct XrayUncheckedSendable<Value>: @unchecked Sendable {
    let value: Value
}
#endif

@MainActor
public protocol XrayClientTunnelControlling: AnyObject {
    func currentStatus() async -> XrayClientConnectionStatus
    func start(profile: XrayClientProfile) async throws
    func stop() async throws
    func runtimeStats() async throws -> XrayClientRuntimeStats?
}

#if canImport(NetworkExtension)
@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
struct XrayTunnelSecureConfigTransaction {
    let reference: String

    private let secureConfigStore: XraySecureConfigStoring
    private let previousConfigJSON: String?

    init(
        secureConfigStore: XraySecureConfigStoring,
        configJSON: String,
        reference: String
    ) throws {
        self.secureConfigStore = secureConfigStore
        self.reference = reference
        previousConfigJSON = try secureConfigStore.configJSON(reference: reference)
        try secureConfigStore.store(configJSON: configJSON, reference: reference)
    }

    func commit(removingObsoleteReference obsoleteReference: String?) {
        guard let obsoleteReference, obsoleteReference != reference else {
            return
        }
        do {
            try secureConfigStore.remove(reference: obsoleteReference)
        } catch {
            XrayAppleLog.error(
                "TunnelController",
                "Failed to remove obsolete secure tunnel configuration: \(error.localizedDescription)"
            )
        }
    }

    func rollback() {
        do {
            if let previousConfigJSON {
                try secureConfigStore.store(
                    configJSON: previousConfigJSON,
                    reference: reference
                )
            } else {
                try secureConfigStore.remove(reference: reference)
            }
        } catch {
            XrayAppleLog.error(
                "TunnelController",
                "Failed to roll back secure tunnel configuration: \(error.localizedDescription)"
            )
        }
    }
}

@MainActor
@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
struct XrayTunnelManagerSnapshot {
    let localizedDescription: String?
    let protocolConfiguration: NEVPNProtocol?
    let isEnabled: Bool
    let isOnDemandEnabled: Bool
    let onDemandRules: [NEOnDemandRule]?

    init(manager: NETunnelProviderManager) {
        localizedDescription = manager.localizedDescription
        protocolConfiguration = manager.protocolConfiguration?.copy() as? NEVPNProtocol
        isEnabled = manager.isEnabled
        isOnDemandEnabled = manager.isOnDemandEnabled
        onDemandRules = manager.onDemandRules?.compactMap {
            $0.copy() as? NEOnDemandRule
        }
    }

    func restore(to manager: NETunnelProviderManager) {
        manager.localizedDescription = localizedDescription
        manager.protocolConfiguration = protocolConfiguration?.copy() as? NEVPNProtocol
        manager.isEnabled = isEnabled
        manager.isOnDemandEnabled = isOnDemandEnabled
        manager.onDemandRules = onDemandRules?.compactMap {
            $0.copy() as? NEOnDemandRule
        }
    }
}

@MainActor
@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
struct XrayTunnelManagerPreferencesTransaction {
    enum RollbackKind: Equatable {
        case restoreExisting
        case removeNew
    }

    typealias PersistManager = @MainActor (NETunnelProviderManager) async throws -> Void
    typealias RemoveManager = @MainActor (NETunnelProviderManager) async throws -> Void

    let rollbackKind: RollbackKind

    private let manager: NETunnelProviderManager
    private let snapshot: XrayTunnelManagerSnapshot?
    private let persistManager: PersistManager
    private let removeManager: RemoveManager

    init(manager: NETunnelProviderManager, wasPersisted: Bool) {
        self.init(
            manager: manager,
            wasPersisted: wasPersisted,
            persistManager: { manager in
                try await manager.saveToPreferencesAsync()
                try await manager.loadFromPreferencesAsync()
            },
            removeManager: { manager in
                try await manager.removeFromPreferencesAsync()
            }
        )
    }

    init(
        manager: NETunnelProviderManager,
        wasPersisted: Bool,
        persistManager: @escaping PersistManager,
        removeManager: @escaping RemoveManager
    ) {
        self.manager = manager
        snapshot = wasPersisted ? XrayTunnelManagerSnapshot(manager: manager) : nil
        rollbackKind = wasPersisted ? .restoreExisting : .removeNew
        self.persistManager = persistManager
        self.removeManager = removeManager
    }

    func rollback() async throws {
        switch rollbackKind {
        case .restoreExisting:
            guard let snapshot else {
                preconditionFailure("A persisted manager transaction must have a snapshot")
            }
            snapshot.restore(to: manager)
            try await persistManager(manager)
        case .removeNew:
            try await removeManager(manager)
        }
    }
}

@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
public final class NetworkExtensionTunnelController: XrayClientTunnelControlling {
    private let managerDescription: String
    private let secureConfigStore: XraySecureConfigStoring

    public init(
        managerDescription: String = "Xray Rust",
        secureConfigStore: XraySecureConfigStoring = XrayKeychainConfigStore()
    ) {
        self.managerDescription = managerDescription
        self.secureConfigStore = secureConfigStore
    }

    public func currentStatus() async -> XrayClientConnectionStatus {
        do {
            guard let manager = try await loadManager() else {
                XrayAppleLog.info("TunnelController", "No saved tunnel manager; status disconnected")
                return .disconnected
            }
            let status = XrayClientConnectionStatus(manager.connection.status)
            XrayAppleLog.info(
                "TunnelController",
                "Loaded tunnel manager status=\(status.displayName)"
            )
            return status
        } catch {
            XrayAppleLog.error(
                "TunnelController",
                "Failed to load tunnel status: \(error.localizedDescription)"
            )
            return .unknown
        }
    }

    public func start(profile: XrayClientProfile) async throws {
        XrayAppleLog.info(
            "TunnelController",
            "Preparing start provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count) debugLogging=\(profile.debugLoggingEnabled) useTunFileDescriptor=\(profile.useTunFileDescriptor) tunRuntimeProfile=\(profile.tunRuntimeProfile.rawValue)"
        )
        do {
            let existingManager = try await loadManager()
            let obsoleteReference = Self.configReference(from: existingManager)
            let manager = existingManager ?? NETunnelProviderManager()
            let preferencesTransaction = XrayTunnelManagerPreferencesTransaction(
                manager: manager,
                wasPersisted: existingManager != nil
            )
            let configReference = XraySecureConfigReference.tunnel(profile.id)
            let secureTransaction = try XrayTunnelSecureConfigTransaction(
                secureConfigStore: secureConfigStore,
                configJSON: profile.configJSON,
                reference: configReference
            )
            do {
                try await configure(
                    manager: manager,
                    for: profile,
                    configReference: configReference
                )
                if let session = manager.connection as? NETunnelProviderSession {
                    XrayAppleLog.info("TunnelController", "Calling NETunnelProviderSession.startTunnel")
                    try session.startTunnel(
                        options: Self.startTunnelOptions(
                            for: profile,
                            configReference: configReference
                        )
                    )
                    XrayAppleLog.info("TunnelController", "NETunnelProviderSession.startTunnel returned")
                } else {
                    XrayAppleLog.info("TunnelController", "Calling NEVPNConnection.startVPNTunnel")
                    try manager.connection.startVPNTunnel()
                    XrayAppleLog.info("TunnelController", "NEVPNConnection.startVPNTunnel returned")
                }
                secureTransaction.commit(removingObsoleteReference: obsoleteReference)
            } catch {
                let preferencesRestored = await Self.rollbackFailedStart(
                    preferencesTransaction: preferencesTransaction,
                    secureRollback: secureTransaction.rollback
                )
                if !preferencesRestored {
                    XrayAppleLog.error(
                        "TunnelController",
                        "Failed to restore tunnel preferences; retaining the new secure configuration so the saved manager never points to a missing reference"
                    )
                }
                throw error
            }
        } catch {
            XrayAppleLog.error(
                "TunnelController",
                "Start request failed: \(error.localizedDescription)"
            )
            throw error
        }
    }

    public func stop() async throws {
        XrayAppleLog.info("TunnelController", "Preparing stop")
        guard let manager = try await loadManager() else {
            XrayAppleLog.info("TunnelController", "No saved tunnel manager to stop")
            return
        }
        if let session = manager.connection as? NETunnelProviderSession {
            XrayAppleLog.info("TunnelController", "Stopping NETunnelProviderSession")
            session.stopTunnel()
        } else {
            XrayAppleLog.info("TunnelController", "Stopping NEVPNConnection")
            manager.connection.stopVPNTunnel()
        }
    }

    public func runtimeStats() async throws -> XrayClientRuntimeStats? {
        XrayAppleLog.info("TunnelController", "Requesting runtime stats")
        guard let manager = try await loadManager(),
              let session = manager.connection as? NETunnelProviderSession
        else {
            XrayAppleLog.info("TunnelController", "Runtime stats unavailable: no provider session")
            return nil
        }

        let request = Data(XrayTunnelProviderMessage.statsRequest.utf8)
        let response = try await session.sendProviderMessageAsync(request)
        guard let response else {
            XrayAppleLog.info("TunnelController", "Runtime stats unavailable: empty response")
            return nil
        }
        let stats = try XrayTunnelProviderMessage.decodeStatsResponse(response)
        XrayAppleLog.info(
            "TunnelController",
            "Runtime stats response inbound=\(stats.inboundPackets) outbound=\(stats.outboundPackets) dropped=\(stats.droppedPackets)"
        )
        return stats
    }

    private func configure(
        manager: NETunnelProviderManager,
        for profile: XrayClientProfile,
        configReference: String
    ) async throws {
        XrayAppleLog.info(
            "TunnelController",
            "Configuring NETunnelProviderManager"
        )
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = profile.providerBundleIdentifier
        tunnelProtocol.serverAddress = profile.serverAddress
        tunnelProtocol.providerConfiguration = [
            XrayTunnelProviderMessage.providerConfigReferenceKey: configReference,
            XrayTunnelProviderMessage.providerDebugLoggingKey: profile.debugLoggingEnabled,
            XrayTunnelProviderMessage.providerUseTunFileDescriptorKey: profile.useTunFileDescriptor,
            XrayTunnelProviderMessage.providerTunRuntimeProfileKey: profile.tunRuntimeProfile.rawValue,
        ]

        manager.localizedDescription = managerDescription
        manager.protocolConfiguration = tunnelProtocol
        manager.isEnabled = true

        XrayAppleLog.info(
            "TunnelController",
            "Saving preferences description=\(managerDescription) provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) debugLogging=\(profile.debugLoggingEnabled) useTunFileDescriptor=\(profile.useTunFileDescriptor) tunRuntimeProfile=\(profile.tunRuntimeProfile.rawValue)"
        )
        try await manager.saveToPreferencesAsync()
        XrayAppleLog.info("TunnelController", "Saved preferences; reloading")
        try await manager.loadFromPreferencesAsync()
        XrayAppleLog.info("TunnelController", "Reloaded preferences")
    }

    @discardableResult
    static func rollbackFailedStart(
        preferencesTransaction: XrayTunnelManagerPreferencesTransaction,
        secureRollback: @MainActor () -> Void
    ) async -> Bool {
        do {
            try await preferencesTransaction.rollback()
        } catch {
            XrayAppleLog.error(
                "TunnelController",
                "Failed to roll back tunnel preferences: \(error.localizedDescription)"
            )
            return false
        }
        secureRollback()
        return true
    }

    private static func configReference(
        from manager: NETunnelProviderManager?
    ) -> String? {
        guard let tunnelProtocol = manager?.protocolConfiguration as? NETunnelProviderProtocol
        else {
            return nil
        }
        return tunnelProtocol.providerConfiguration?[
            XrayTunnelProviderMessage.providerConfigReferenceKey
        ] as? String
    }

    static func startTunnelOptions(
        for profile: XrayClientProfile,
        configReference: String
    ) -> [String: NSObject] {
        [
            XrayTunnelProviderMessage.configReferenceOptionKey: configReference as NSString,
            XrayTunnelProviderMessage.debugLoggingOptionKey: NSNumber(
                value: profile.debugLoggingEnabled
            ),
            XrayTunnelProviderMessage.useTunFileDescriptorOptionKey: NSNumber(
                value: profile.useTunFileDescriptor
            ),
            XrayTunnelProviderMessage.tunRuntimeProfileOptionKey: profile
                .tunRuntimeProfile
                .rawValue as NSString,
        ]
    }

    private func loadManager() async throws -> NETunnelProviderManager? {
        let managers = try await Self.loadAllManagers()
        let manager = managers.first { $0.localizedDescription == managerDescription }
        XrayAppleLog.info(
            "TunnelController",
            "Loaded \(managers.count) tunnel manager(s); targetFound=\(manager != nil)"
        )
        return manager
    }

    private static func loadAllManagers() async throws -> [NETunnelProviderManager] {
        let result: XrayUncheckedSendable<[NETunnelProviderManager]> =
            try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(
                    returning: XrayUncheckedSendable(value: managers ?? [])
                )
            }
        }
        return result.value
    }
}

@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
private extension NETunnelProviderSession {
    func sendProviderMessageAsync(_ messageData: Data) async throws -> Data? {
        try await withCheckedThrowingContinuation { continuation in
            do {
                try sendProviderMessage(messageData) { response in
                    continuation.resume(returning: response)
                }
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }
}

@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
private extension NETunnelProviderManager {
    func saveToPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            saveToPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume()
            }
        }
    }

    func loadFromPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            loadFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume()
            }
        }
    }

    func removeFromPreferencesAsync() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            removeFromPreferences { error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume()
            }
        }
    }
}

@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
private extension XrayClientConnectionStatus {
    init(_ status: NEVPNStatus) {
        switch status {
        case .invalid:
            self = .invalid
        case .disconnected:
            self = .disconnected
        case .connecting:
            self = .connecting
        case .connected:
            self = .connected
        case .reasserting:
            self = .reasserting
        case .disconnecting:
            self = .disconnecting
        @unknown default:
            self = .unknown
        }
    }
}
#else
@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
public final class NetworkExtensionTunnelController: XrayClientTunnelControlling {
    public init(
        managerDescription: String = "Xray Rust",
        secureConfigStore: XraySecureConfigStoring = XrayKeychainConfigStore()
    ) {}

    public func currentStatus() async -> XrayClientConnectionStatus {
        .unknown
    }

    public func start(profile: XrayClientProfile) async throws {
        throw CocoaError(.featureUnsupported)
    }

    public func stop() async throws {}

    public func runtimeStats() async throws -> XrayClientRuntimeStats? {
        nil
    }
}
#endif
