import Foundation
import XrayAppleShared

#if canImport(NetworkExtension)
import NetworkExtension
#endif

@MainActor
public protocol XrayClientTunnelControlling: AnyObject {
    func currentStatus() async -> XrayClientConnectionStatus
    func start(profile: XrayClientProfile) async throws
    func stop() async throws
    func runtimeStats() async throws -> XrayClientRuntimeStats?
}

#if canImport(NetworkExtension)
@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
public final class NetworkExtensionTunnelController: XrayClientTunnelControlling {
    private let managerDescription: String

    enum StartupProbePlatform {
        case iOS
        case tvOS
        case macOS
        case other

        static var current: StartupProbePlatform {
            #if os(iOS)
            return .iOS
            #elseif os(tvOS)
            return .tvOS
            #elseif os(macOS)
            return .macOS
            #else
            return .other
            #endif
        }
    }

    public init(managerDescription: String = "Xray Rust") {
        self.managerDescription = managerDescription
    }

    static func defaultStartupProbeEnabled(
        platform: StartupProbePlatform = .current
    ) -> Bool {
        platform != .tvOS
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
            "Preparing start provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) configBytes=\(profile.configJSON.utf8.count) debugLogging=\(profile.debugLoggingEnabled) useTunFileDescriptor=\(profile.useTunFileDescriptor) tunRuntimeProfile=\(profile.tunRuntimeProfile.rawValue) startupProbeEnabled=\(Self.defaultStartupProbeEnabled())"
        )
        do {
            let manager = try await configuredManager(for: profile)
            if let session = manager.connection as? NETunnelProviderSession {
                XrayAppleLog.info("TunnelController", "Calling NETunnelProviderSession.startTunnel")
                try session.startTunnel(options: Self.startTunnelOptions(for: profile))
                XrayAppleLog.info("TunnelController", "NETunnelProviderSession.startTunnel returned")
            } else {
                XrayAppleLog.info("TunnelController", "Calling NEVPNConnection.startVPNTunnel")
                try manager.connection.startVPNTunnel()
                XrayAppleLog.info("TunnelController", "NEVPNConnection.startVPNTunnel returned")
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

    private func configuredManager(for profile: XrayClientProfile) async throws -> NETunnelProviderManager {
        let existingManager = try await loadManager()
        XrayAppleLog.info(
            "TunnelController",
            existingManager == nil ? "Creating new NETunnelProviderManager" : "Reusing existing NETunnelProviderManager"
        )
        let manager = existingManager ?? NETunnelProviderManager()
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = profile.providerBundleIdentifier
        tunnelProtocol.serverAddress = profile.serverAddress
        tunnelProtocol.providerConfiguration = [
            XrayTunnelProviderMessage.providerConfigJSONKey: profile.configJSON,
            XrayTunnelProviderMessage.providerDebugLoggingKey: profile.debugLoggingEnabled,
            XrayTunnelProviderMessage.providerUseTunFileDescriptorKey: profile.useTunFileDescriptor,
            XrayTunnelProviderMessage.providerTunRuntimeProfileKey: profile.tunRuntimeProfile.rawValue,
            XrayTunnelProviderMessage.providerStartupProbeEnabledKey: Self
                .defaultStartupProbeEnabled(),
        ]

        manager.localizedDescription = managerDescription
        manager.protocolConfiguration = tunnelProtocol
        manager.isEnabled = true

        XrayAppleLog.info(
            "TunnelController",
            "Saving preferences description=\(managerDescription) provider=\(profile.providerBundleIdentifier) server=\(profile.serverAddress) debugLogging=\(profile.debugLoggingEnabled) useTunFileDescriptor=\(profile.useTunFileDescriptor) tunRuntimeProfile=\(profile.tunRuntimeProfile.rawValue) startupProbeEnabled=\(Self.defaultStartupProbeEnabled())"
        )
        try await manager.saveToPreferencesAsync()
        XrayAppleLog.info("TunnelController", "Saved preferences; reloading")
        try await manager.loadFromPreferencesAsync()
        XrayAppleLog.info("TunnelController", "Reloaded preferences")
        return manager
    }

    private static func startTunnelOptions(for profile: XrayClientProfile) -> [String: NSObject] {
        [
            XrayTunnelProviderMessage.configJSONOptionKey: profile.configJSON as NSString,
            XrayTunnelProviderMessage.debugLoggingOptionKey: NSNumber(
                value: profile.debugLoggingEnabled
            ),
            XrayTunnelProviderMessage.useTunFileDescriptorOptionKey: NSNumber(
                value: profile.useTunFileDescriptor
            ),
            XrayTunnelProviderMessage.tunRuntimeProfileOptionKey: profile
                .tunRuntimeProfile
                .rawValue as NSString,
            XrayTunnelProviderMessage.startupProbeEnabledOptionKey: NSNumber(
                value: Self.defaultStartupProbeEnabled()
            ),
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
        try await withCheckedThrowingContinuation { continuation in
            NETunnelProviderManager.loadAllFromPreferences { managers, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                continuation.resume(returning: managers ?? [])
            }
        }
    }
}

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
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

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
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
}

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
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
@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
public final class NetworkExtensionTunnelController: XrayClientTunnelControlling {
    public init(managerDescription: String = "Xray Rust") {}

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
