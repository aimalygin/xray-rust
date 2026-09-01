import Foundation
import XrayAppleShared

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension

private struct XrayUncheckedSendable<Value>: @unchecked Sendable {
    let value: Value
}

private final class XrayNotificationObserverCancellation: @unchecked Sendable {
    private let notificationCenter: NotificationCenter
    private let lock = NSLock()
    private var observer: NSObjectProtocol?

    init(notificationCenter: NotificationCenter) {
        self.notificationCenter = notificationCenter
    }

    func install(_ observer: NSObjectProtocol) {
        lock.lock()
        self.observer = observer
        lock.unlock()
    }

    func cancel() {
        lock.lock()
        let observer = observer
        self.observer = nil
        lock.unlock()
        if let observer {
            notificationCenter.removeObserver(observer)
        }
    }

    deinit {
        cancel()
    }
}

enum XrayTunnelStartupError: LocalizedError, Equatable {
    case failed(reason: String?)
    case timedOut(seconds: Int)

    var errorDescription: String? {
        switch self {
        case let .failed(reason):
            if let reason, !reason.isEmpty {
                return "VPN failed to start: \(reason)"
            }
            return "VPN failed to start. Check the Tunnel extension logs for details."
        case let .timedOut(seconds):
            return "VPN did not finish starting within \(seconds) seconds."
        }
    }
}

private enum XrayTunnelStartupWaitResult: Sendable {
    case connected
    case failed
    case monitoringEnded
    case timedOut
}

@MainActor
@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
private final class XrayTunnelStatusMonitor {
    let statusChanges: AsyncStream<XrayClientConnectionStatus>

    private let notificationCenter: NotificationCenter
    private let continuation: AsyncStream<XrayClientConnectionStatus>.Continuation
    private var observer: NSObjectProtocol?

    init(
        connection: NEVPNConnection,
        notificationCenter: NotificationCenter = .default
    ) {
        self.notificationCenter = notificationCenter

        var capturedContinuation: AsyncStream<XrayClientConnectionStatus>.Continuation?
        statusChanges = AsyncStream(bufferingPolicy: .bufferingNewest(16)) {
            capturedContinuation = $0
        }
        guard let capturedContinuation else {
            preconditionFailure("AsyncStream must synchronously provide its continuation")
        }
        continuation = capturedContinuation

        observer = notificationCenter.addObserver(
            forName: .NEVPNStatusDidChange,
            object: connection,
            queue: .main
        ) { [weak connection, continuation] _ in
            guard let connection else {
                return
            }
            continuation.yield(XrayClientConnectionStatus(connection.status))
        }
    }

    deinit {
        if let observer {
            notificationCenter.removeObserver(observer)
        }
        continuation.finish()
    }
}
#endif

@MainActor
public protocol XrayClientTunnelControlling: AnyObject {
    func currentStatus() async -> XrayClientConnectionStatus
    func statusUpdates() async -> AsyncStream<XrayClientConnectionStatus>
    func lastDisconnectError() async -> Error?
    func start(profile: XrayClientProfile) async throws
    func stop() async throws
    func runtimeStats() async throws -> XrayClientRuntimeStats?
    func closeActiveConnections() async throws -> UInt64
}

public extension XrayClientTunnelControlling {
    func statusUpdates() async -> AsyncStream<XrayClientConnectionStatus> {
        AsyncStream { continuation in
            continuation.finish()
        }
    }

    func lastDisconnectError() async -> Error? {
        nil
    }

    func closeActiveConnections() async throws -> UInt64 {
        0
    }
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
    private static let startupTimeoutSeconds = 30

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

    public func statusUpdates() async -> AsyncStream<XrayClientConnectionStatus> {
        let loadedManager: NETunnelProviderManager?
        let managerLoadFailed: Bool
        do {
            loadedManager = try await loadManager()
            managerLoadFailed = false
        } catch {
            loadedManager = nil
            managerLoadFailed = true
            XrayAppleLog.error(
                "TunnelController",
                "Failed to load the initial tunnel status: \(error.localizedDescription)"
            )
        }

        let notificationCenter = NotificationCenter.default
        let managerDescription = managerDescription
        var capturedContinuation: AsyncStream<XrayClientConnectionStatus>.Continuation?
        let stream = AsyncStream(
            bufferingPolicy: .bufferingNewest(16)
        ) { continuation in
            capturedContinuation = continuation
        }
        guard let continuation = capturedContinuation else {
            preconditionFailure("AsyncStream must synchronously provide its continuation")
        }
        let cancellation = XrayNotificationObserverCancellation(
            notificationCenter: notificationCenter
        )
        let observer = notificationCenter.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { notification in
            guard let connection = notification.object as? NEVPNConnection,
                  connection.manager.localizedDescription == managerDescription
            else {
                return
            }
            continuation.yield(XrayClientConnectionStatus(connection.status))
        }
        cancellation.install(observer)
        continuation.onTermination = { _ in
            cancellation.cancel()
        }

        // There is no suspension between observer registration and this read.
        // A transition before registration is reflected by the snapshot; one
        // after registration is delivered by the notification observer.
        if let loadedManager {
            continuation.yield(
                XrayClientConnectionStatus(loadedManager.connection.status)
            )
        } else {
            continuation.yield(managerLoadFailed ? .unknown : .disconnected)
        }
        return stream
    }

    public func lastDisconnectError() async -> Error? {
        do {
            guard let manager = try await loadManager() else {
                return nil
            }
            return await Self.lastDisconnectError(for: manager.connection)
        } catch {
            XrayAppleLog.error(
                "TunnelController",
                "Failed to load the last disconnect error: \(error.localizedDescription)"
            )
            return nil
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
            let connection: NEVPNConnection
            let statusMonitor: XrayTunnelStatusMonitor
            do {
                try await configure(
                    manager: manager,
                    for: profile,
                    configReference: configReference
                )
                connection = manager.connection
                statusMonitor = XrayTunnelStatusMonitor(connection: connection)
                if let session = connection as? NETunnelProviderSession {
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
                    try connection.startVPNTunnel()
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

            XrayAppleLog.info(
                "TunnelController",
                "Waiting for tunnel startup status=\(XrayClientConnectionStatus(connection.status).displayName) timeoutSeconds=\(Self.startupTimeoutSeconds)"
            )
            // `waitForStartup` consumes only the monitor's stream. Keep the
            // owner alive explicitly so ARC cannot remove its notification
            // observer while the asynchronous wait is still in progress.
            defer { withExtendedLifetime(statusMonitor) {} }
            do {
                try await Self.waitForStartup(
                    statusAfterStartRequest: XrayClientConnectionStatus(connection.status),
                    statusChanges: statusMonitor.statusChanges,
                    timeoutNanoseconds: UInt64(Self.startupTimeoutSeconds) * 1_000_000_000,
                    timeoutSecondsForMessage: Self.startupTimeoutSeconds,
                    lastDisconnectError: {
                        await Self.lastDisconnectError(for: connection)
                    }
                )
                XrayAppleLog.info("TunnelController", "Tunnel reached connected status")
            } catch {
                if error is CancellationError {
                    XrayAppleLog.info(
                        "TunnelController",
                        "Tunnel startup wait was cancelled; stopping the pending connection"
                    )
                    connection.stopVPNTunnel()
                } else if let startupError = error as? XrayTunnelStartupError,
                          case .timedOut = startupError
                {
                    XrayAppleLog.error(
                        "TunnelController",
                        "Tunnel startup timed out; stopping the pending connection"
                    )
                    connection.stopVPNTunnel()
                }
                throw error
            }
        } catch {
            XrayAppleLog.error(
                "TunnelController",
                "Tunnel start failed: \(error.localizedDescription)"
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

    public func closeActiveConnections() async throws -> UInt64 {
        XrayAppleLog.info("TunnelController", "Requesting closure of active connections")
        guard let manager = try await loadManager(),
              let session = manager.connection as? NETunnelProviderSession
        else {
            XrayAppleLog.info("TunnelController", "Connection close unavailable: no provider session")
            return 0
        }

        let request = Data(XrayTunnelProviderMessage.closeConnectionsRequest.utf8)
        let response = try await session.sendProviderMessageAsync(request)
        guard let response else {
            XrayAppleLog.info("TunnelController", "Connection close unavailable: empty response")
            return 0
        }
        let count = try XrayTunnelProviderMessage.decodeCloseConnectionsResponse(response)
        XrayAppleLog.info(
            "TunnelController",
            "Provider accepted \(count) connection close request(s)"
        )
        return count
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

    static func waitForStartup(
        statusAfterStartRequest: XrayClientConnectionStatus,
        statusChanges: AsyncStream<XrayClientConnectionStatus>,
        timeoutNanoseconds: UInt64,
        timeoutSecondsForMessage: Int,
        lastDisconnectError: @escaping @MainActor () async -> Error?
    ) async throws {
        switch statusAfterStartRequest {
        case .connected:
            return
        case .invalid:
            let error = await lastDisconnectError()
            throw XrayTunnelStartupError.failed(reason: error?.localizedDescription)
        case .disconnected, .connecting, .reasserting, .disconnecting, .unknown:
            break
        }

        let result = await withTaskGroup(
            of: XrayTunnelStartupWaitResult.self,
            returning: XrayTunnelStartupWaitResult.self
        ) { group in
            group.addTask {
                for await status in statusChanges {
                    if Task.isCancelled {
                        return .monitoringEnded
                    }
                    switch status {
                    case .connected:
                        return .connected
                    case .invalid, .disconnected:
                        return .failed
                    case .connecting, .reasserting, .disconnecting, .unknown:
                        continue
                    }
                }
                return .monitoringEnded
            }
            group.addTask {
                do {
                    try await Task.sleep(nanoseconds: timeoutNanoseconds)
                    return .timedOut
                } catch {
                    return .monitoringEnded
                }
            }

            let firstResult = await group.next() ?? .monitoringEnded
            group.cancelAll()
            return firstResult
        }
        try Task.checkCancellation()

        switch result {
        case .connected:
            return
        case .failed, .monitoringEnded:
            let error = await lastDisconnectError()
            throw XrayTunnelStartupError.failed(reason: error?.localizedDescription)
        case .timedOut:
            throw XrayTunnelStartupError.timedOut(seconds: timeoutSecondsForMessage)
        }
    }

    private static func lastDisconnectError(
        for connection: NEVPNConnection
    ) async -> Error? {
        #if os(iOS)
        guard #available(iOS 16.0, *) else {
            return nil
        }
        #endif

        let result: XrayUncheckedSendable<Error?> = await withCheckedContinuation {
            continuation in
            connection.fetchLastDisconnectError { error in
                continuation.resume(
                    returning: XrayUncheckedSendable(value: error)
                )
            }
        }
        return result.value
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

    public func closeActiveConnections() async throws -> UInt64 {
        0
    }
}
#endif
