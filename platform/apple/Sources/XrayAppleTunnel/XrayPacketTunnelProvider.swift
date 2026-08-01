#if canImport(NetworkExtension)
import CoreFoundation
import Darwin
import Dispatch
import Foundation
@preconcurrency import NetworkExtension
import XrayAppleShared
import XrayMobileAdapter

public enum XrayPacketTunnelProviderError: Error, LocalizedError {
    case missingConfigJSON
    case invalidStartupProbeConfiguration
    case invalidDNSConfiguration
    case startSuperseded

    public var errorDescription: String? {
        switch self {
        case .missingConfigJSON:
            return "Missing Xray JSON configuration."
        case .invalidStartupProbeConfiguration:
            return "Startup probe requires an explicit HTTP or HTTPS URL and a valid timeout."
        case .invalidDNSConfiguration:
            return "DNS requires enabled dns.fakeIp, an IP-literal dns.servers upstream, or explicit IPv4 servers; fake-IP cannot be combined with explicit servers."
        case .startSuperseded:
            return "Tunnel start was superseded by a newer lifecycle request."
        }
    }
}

enum XrayPacketTunnelStartupProbeConfiguration: Equatable {
    case disabled
    case enabled(XrayStartupProbeOptions)
    case invalid

    var logDescription: String {
        switch self {
        case .disabled:
            return "disabled"
        case .enabled:
            return "enabled"
        case .invalid:
            return "invalid"
        }
    }

    var options: XrayStartupProbeOptions? {
        guard case let .enabled(options) = self else {
            return nil
        }
        return options
    }
}

enum XrayPacketTunnelDNSConfiguration: Equatable {
    case system
    case custom([String])
    case invalid

    var logDescription: String {
        switch self {
        case .system:
            return "system"
        case let .custom(servers):
            return "custom(\(servers.count))"
        case .invalid:
            return "invalid"
        }
    }
}

enum XrayPacketTunnelResolvedDNSConfiguration: Equatable {
    case localDNSAnchor
    case custom([String])

    var logDescription: String {
        switch self {
        case .localDNSAnchor:
            return "localDnsAnchor"
        case let .custom(servers):
            return "custom(\(servers.count))"
        }
    }
}

final class XrayPacketTunnelLifecycle<Resource> {
    struct Token: Equatable {
        fileprivate let generation: UInt64
    }

    private let lock = NSRecursiveLock()
    private let stopResource: (Resource) -> Void
    private var generation: UInt64 = 0
    private var activeResource: Resource?

    init(stopResource: @escaping (Resource) -> Void) {
        self.stopResource = stopResource
    }

    func beginStart() -> Token {
        lock.lock()
        defer { lock.unlock() }
        generation &+= 1
        if let activeResource {
            self.activeResource = nil
            stopResource(activeResource)
        }
        return Token(generation: generation)
    }

    func isCurrent(_ token: Token) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return token.generation == generation
    }

    @discardableResult
    func install(_ resource: Resource, for token: Token) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard token.generation == generation, activeResource == nil else {
            stopResource(resource)
            return false
        }
        activeResource = resource
        return true
    }

    @discardableResult
    func finishStart(for token: Token, _ body: () -> Void) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard token.generation == generation, activeResource != nil else {
            return false
        }
        body()
        return true
    }

    @discardableResult
    func cancelStart(_ token: Token) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard token.generation == generation else {
            return false
        }
        generation &+= 1
        return true
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        generation &+= 1
        if let activeResource {
            self.activeResource = nil
            stopResource(activeResource)
        }
    }

    @discardableResult
    func stop(ifCurrent token: Token) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard token.generation == generation else {
            return false
        }
        generation &+= 1
        if let activeResource {
            self.activeResource = nil
            stopResource(activeResource)
        }
        return true
    }

    func active() -> Resource? {
        lock.lock()
        defer { lock.unlock() }
        return activeResource
    }
}

private final class XrayWeakReference<Value: AnyObject>: @unchecked Sendable {
    weak var value: Value?

    init(_ value: Value) {
        self.value = value
    }
}

@available(iOSApplicationExtension 15.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
open class XrayPacketTunnelProvider: NEPacketTunnelProvider {
    private static let defaultStartupProbeTimeoutMs: UInt64 = 5_000
    private static let maximumStartupProbeTimeoutMs: UInt64 = 60_000
    private static let maximumCustomDNSServers = 8
    static let tunnelRemoteAddress = "198.18.0.1"
    private static let debugStatsHandler: @Sendable (XrayCore) -> Void = {
        logDebugStats($0)
    }

    private let debugStatsQueue = DispatchQueue(
        label: "org.xrayrust.apple.packet-tunnel.debug-stats"
    )
    private lazy var lifecycle = XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime> {
        $0.stop()
    }

    open override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let optionKeys = options?.keys.sorted().joined(separator: ",") ?? "none"
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "startTunnel invoked optionKeys=\(optionKeys)"
        )
        let lifecycleToken = lifecycle.beginStart()

        guard let resolvedConfig = Self.configJSON(
            options: options,
            protocolConfiguration: protocolConfiguration
        ) else {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error("PacketTunnelProvider", "Missing config JSON")
            completionHandler(XrayPacketTunnelProviderError.missingConfigJSON)
            return
        }
        if case .invalid = resolvedConfig.startupProbeConfiguration {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Invalid explicit startup probe configuration"
            )
            completionHandler(
                XrayPacketTunnelProviderError.invalidStartupProbeConfiguration
            )
            return
        }
        if case .invalid = resolvedConfig.dnsConfiguration {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Invalid explicit DNS server configuration"
            )
            completionHandler(XrayPacketTunnelProviderError.invalidDNSConfiguration)
            return
        }
        do {
            try Self.validateConfigBeforeApplyingNetworkSettings(resolvedConfig.json)
        } catch {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Config validation failed before network settings: \(error.localizedDescription)"
            )
            completionHandler(error)
            return
        }
        guard let resolvedDNSConfiguration = Self.resolvedDNSConfiguration(
            configJSON: resolvedConfig.json,
            explicit: resolvedConfig.dnsConfiguration
        ) else {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "DNS unavailable: enable dns.fakeIp, configure an IP-literal dns.servers upstream, or configure explicit IPv4 servers"
            )
            completionHandler(XrayPacketTunnelProviderError.invalidDNSConfiguration)
            return
        }
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "Resolved config source=\(resolvedConfig.source) bytes=\(resolvedConfig.json.utf8.count) debugLogging=\(resolvedConfig.debugLoggingEnabled) useTunFileDescriptor=\(resolvedConfig.useTunFileDescriptor) tunRuntimeProfile=\(resolvedConfig.tunRuntimeProfile.rawValue) startupProbe=\(resolvedConfig.startupProbeConfiguration.logDescription) dns=\(resolvedDNSConfiguration.logDescription)"
        )
        let diagnosticLogDirectory = Self.diagnosticLogDirectory(
            debugLoggingEnabled: resolvedConfig.debugLoggingEnabled
        )
        XrayAppleLog.configureFileLogging(directory: diagnosticLogDirectory)
        if resolvedConfig.debugLoggingEnabled {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Config summary \(Self.configSummary(resolvedConfig.json))"
            )
        }

        setTunnelNetworkSettings(
            Self.networkSettings(
                excludingServerAddress: resolvedConfig.serverAddress,
                resolvedDNSConfiguration: resolvedDNSConfiguration
            )
        ) { [weak self] error in
            guard let self else {
                XrayAppleLog.error("PacketTunnelProvider", "Provider released before network settings completed")
                completionHandler(CocoaError(.userCancelled))
                return
            }
            guard self.lifecycle.isCurrent(lifecycleToken) else {
                XrayAppleLog.info(
                    "PacketTunnelProvider",
                    "Ignoring superseded network settings callback"
                )
                completionHandler(XrayPacketTunnelProviderError.startSuperseded)
                return
            }
            if let error {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "setTunnelNetworkSettings failed: \(error.localizedDescription)"
                )
                _ = self.lifecycle.cancelStart(lifecycleToken)
                XrayAppleLog.configureFileLogging(directory: nil)
                completionHandler(error)
                return
            }
            XrayAppleLog.info("PacketTunnelProvider", "Tunnel network settings applied")

            do {
                let runtime = try self.makeRuntime(
                    resolvedConfig: resolvedConfig,
                    diagnosticLogDirectory: diagnosticLogDirectory,
                    lifecycleToken: lifecycleToken
                )
                guard self.lifecycle.install(runtime, for: lifecycleToken) else {
                    completionHandler(XrayPacketTunnelProviderError.startSuperseded)
                    return
                }
                let didFinish = self.lifecycle.finishStart(for: lifecycleToken) {
                    if resolvedConfig.debugLoggingEnabled {
                        runtime.startDebugStatsLogging(
                            queue: self.debugStatsQueue,
                            handler: Self.debugStatsHandler
                        )
                    }
                    XrayAppleLog.info(
                        "PacketTunnelProvider",
                        "startTunnel completed successfully"
                    )
                    completionHandler(nil)
                }
                if !didFinish {
                    completionHandler(XrayPacketTunnelProviderError.startSuperseded)
                }
            } catch {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "startTunnel failed: \(error.localizedDescription)"
                )
                if self.lifecycle.cancelStart(lifecycleToken) {
                    XrayAppleLog.configureFileLogging(directory: nil)
                }
                completionHandler(error)
            }
        }
    }

    open override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "stopTunnel invoked reason=\(reason.xrayDescription)"
        )
        lifecycle.stop()
        XrayAppleLog.configureFileLogging(directory: nil)
        completionHandler()
    }

    open override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "handleAppMessage bytes=\(messageData.count)"
        )
        guard String(data: messageData, encoding: .utf8) == XrayTunnelProviderMessage.statsRequest,
              let stats = try? lifecycle.active()?.core.stats()
        else {
            XrayAppleLog.info("PacketTunnelProvider", "App message ignored or stats unavailable")
            completionHandler?(nil)
            return
        }

        let runtimeStats = XrayClientRuntimeStats(
            inboundPackets: stats.inboundPackets,
            outboundPackets: stats.outboundPackets,
            droppedPackets: stats.droppedPackets,
            tcpOpenEvents: stats.tcpOpenEvents,
            tcpOpenDurationMsTotal: stats.tcpOpenDurationMsTotal,
            tcpOpenDurationMsMax: stats.tcpOpenDurationMsMax,
            tcpFirstByteEvents: stats.tcpFirstByteEvents,
            tcpFirstByteDurationMsTotal: stats.tcpFirstByteDurationMsTotal,
            tcpFirstByteDurationMsMax: stats.tcpFirstByteDurationMsMax,
            tcp443OpenEvents: stats.tcp443OpenEvents,
            tcp443OpenDurationMsTotal: stats.tcp443OpenDurationMsTotal,
            tcp443OpenDurationMsMax: stats.tcp443OpenDurationMsMax,
            tcp443FirstByteEvents: stats.tcp443FirstByteEvents,
            tcp443FirstByteDurationMsTotal: stats.tcp443FirstByteDurationMsTotal,
            tcp443FirstByteDurationMsMax: stats.tcp443FirstByteDurationMsMax,
            activeTCPFlows: stats.activeTCPFlows,
            activeUDPFlows: stats.activeUDPFlows,
            udpFlowLimit: stats.udpFlowLimit,
            udpBudgetDrops: stats.udpBudgetDrops,
            udpEvictedFlows: stats.udpEvictedFlows,
            udpChannelDroppedPackets: stats.udpChannelDroppedPackets,
            udpRemoteOpenEvents: stats.udpRemoteOpenEvents,
            udpRemoteUDP443OpenEvents: stats.udpRemoteUDP443OpenEvents,
            udpRemoteWrittenBytes: stats.udpRemoteWrittenBytes,
            udpRemoteReadBytes: stats.udpRemoteReadBytes,
            udpOpenErrors: stats.udpOpenErrors,
            udpVisionUDP443Rejections: stats.udpVisionUDP443Rejections,
            udpRemoteWriteErrors: stats.udpRemoteWriteErrors,
            udpRemoteReadErrors: stats.udpRemoteReadErrors,
            udpRemoteClosedEvents: stats.udpRemoteClosedEvents,
            udpQuicBlockedPackets: stats.udpQuicBlockedPackets,
            inboundQueueDepth: stats.inboundQueueDepth,
            outboundQueueDepth: stats.outboundQueueDepth,
            inboundQueueMaxPackets: stats.inboundQueueMaxPackets,
            outboundQueueMaxPackets: stats.outboundQueueMaxPackets,
            tunFdWriteBatches: stats.tunFdWriteBatches,
            tunFdWriteBatchPackets: stats.tunFdWriteBatchPackets,
            tunFdWriteBatchMaxPackets: stats.tunFdWriteBatchMaxPackets
        )
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "Returning stats inbound=\(runtimeStats.inboundPackets) outbound=\(runtimeStats.outboundPackets) dropped=\(runtimeStats.droppedPackets)"
        )
        completionHandler?(try? XrayTunnelProviderMessage.encodeStatsResponse(runtimeStats))
    }

    static func packetIOBackend(
        discoveredTunFileDescriptor: Int32?,
        useTunFileDescriptor: Bool = true
    ) -> XrayPacketTunnelIOBackend {
        guard useTunFileDescriptor, let discoveredTunFileDescriptor else {
            return .packetFlowPump
        }
        return .darwinUtunFileDescriptor(discoveredTunFileDescriptor)
    }

    struct ResolvedConfig {
        var json: String
        var source: String
        var serverAddress: String?
        var debugLoggingEnabled: Bool
        var useTunFileDescriptor: Bool
        var tunRuntimeProfile: XrayTunRuntimeProfileSetting
        var startupProbeConfiguration: XrayPacketTunnelStartupProbeConfiguration
        var dnsConfiguration: XrayPacketTunnelDNSConfiguration
    }

    static func configJSON(
        options: [String: NSObject]?,
        protocolConfiguration: NEVPNProtocol,
        secureConfigStore: XraySecureConfigStoring = XrayKeychainConfigStore()
    ) -> ResolvedConfig? {
        let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol
        let serverAddress = tunnelProtocol?.serverAddress
        let isDebugLoggingEnabled = debugLoggingEnabled(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let shouldUseTunFileDescriptor = tunFileDescriptorEnabled(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let selectedTunRuntimeProfile = tunRuntimeProfile(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let selectedStartupProbeConfiguration = startupProbeConfiguration(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let selectedDNSConfiguration = dnsConfiguration(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )

        let optionReference = stringValue(
            options?[XrayTunnelProviderMessage.configReferenceOptionKey]
        )
        let providerReference = stringValue(
            tunnelProtocol?.providerConfiguration?[
                XrayTunnelProviderMessage.providerConfigReferenceKey
            ]
        )
        guard let configReference = optionReference ?? providerReference else {
            return nil
        }
        let storedConfigJSON: String
        do {
            guard let storedConfig = try secureConfigStore.configJSON(
                reference: configReference
            ) else {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "Secure configuration reference could not be resolved"
                )
                return nil
            }
            storedConfigJSON = storedConfig
        } catch {
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Failed to load secure configuration: \(error.localizedDescription)"
            )
            return nil
        }
        let configJSON: String
        switch selectedDNSConfiguration {
        case .system:
            configJSON = XrayClientProfile.configJSONAddingFakeIPToLegacyDirectConfigIfNeeded(
                storedConfigJSON
            )
        case .custom, .invalid:
            configJSON = storedConfigJSON
        }
        return ResolvedConfig(
            json: configJSON,
            source: optionReference == nil ? "providerConfigurationReference" : "startOptionReference",
            serverAddress: serverAddress,
            debugLoggingEnabled: isDebugLoggingEnabled,
            useTunFileDescriptor: shouldUseTunFileDescriptor,
            tunRuntimeProfile: selectedTunRuntimeProfile,
            startupProbeConfiguration: selectedStartupProbeConfiguration,
            dnsConfiguration: selectedDNSConfiguration
        )
    }

    static func debugLoggingEnabled(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> Bool {
        if let optionValue = options?[XrayTunnelProviderMessage.debugLoggingOptionKey],
           let isEnabled = boolValue(optionValue) {
            return isEnabled
        }

        if let configurationValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerDebugLoggingKey
        ],
            let isEnabled = boolValue(configurationValue) {
            return isEnabled
        }

        return false
    }

    static func diagnosticLogDirectory(
        debugLoggingEnabled: Bool,
        baseDirectory: URL = FileManager.default.urls(
            for: .cachesDirectory,
            in: .userDomainMask
        ).first ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
    ) -> URL? {
        guard debugLoggingEnabled else {
            return nil
        }
        return baseDirectory
            .resolvingSymlinksInPath()
            .appendingPathComponent("XrayRustLogs", isDirectory: true)
    }

    static func configSummary(_ json: String) -> String {
        guard let data = json.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return "invalidJSON"
        }

        let inbounds = (root["inbounds"] as? [[String: Any]] ?? []).map { inbound in
            let tag = inbound["tag"] as? String ?? "untagged"
            let protocolName = inbound["protocol"] as? String ?? "unknown"
            return "\(tag):\(protocolName)"
        }

        let outbounds = (root["outbounds"] as? [[String: Any]] ?? []).map { outbound in
            outboundSummary(outbound)
        }

        let routing = root["routing"] as? [String: Any]
        let routingRules = (routing?["rules"] as? [Any])?.count ?? 0
        let dnsFakeIP = dnsFakeIPSummary(root)

        return "inbounds=\(inbounds.isEmpty ? "none" : inbounds.joined(separator: ",")) outbounds=\(outbounds.isEmpty ? "none" : outbounds.joined(separator: ", ")) routingRules=\(routingRules) dnsFakeIp=\(dnsFakeIP)"
    }

    private static func dnsFakeIPSummary(_ root: [String: Any]) -> String {
        let dns = root["dns"] as? [String: Any]
        let fakeIP = dns?["fakeIp"] as? [String: Any]
        return fakeIP?["enabled"] as? Bool == true ? "enabled" : "disabled"
    }

    private static func outboundSummary(_ outbound: [String: Any]) -> String {
        let tag = outbound["tag"] as? String ?? "untagged"
        let protocolName = outbound["protocol"] as? String ?? "unknown"
        guard protocolName == "vless" else {
            return "\(tag):\(protocolName)"
        }

        let settings = outbound["settings"] as? [String: Any]
        let vnext = settings?["vnext"] as? [[String: Any]]
        let firstServer = vnext?.first
        let users = firstServer?["users"] as? [[String: Any]]
        let flow = users?.first?["flow"] as? String ?? "none"
        let streamSettings = outbound["streamSettings"] as? [String: Any]
        let network = streamSettings?["network"] as? String ?? "unknown"
        let security = streamSettings?["security"] as? String ?? "unknown"

        return "\(tag):\(protocolName) network=\(network) security=\(security) flow=\(flow)"
    }

    static func tunFileDescriptorEnabled(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> Bool {
        if let optionValue = options?[XrayTunnelProviderMessage.useTunFileDescriptorOptionKey],
           let isEnabled = boolValue(optionValue) {
            return isEnabled
        }

        if let configurationValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerUseTunFileDescriptorKey
        ],
            let isEnabled = boolValue(configurationValue) {
            return isEnabled
        }

        return true
    }

    static func tunRuntimeProfile(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> XrayTunRuntimeProfileSetting {
        if let optionValue = options?[XrayTunnelProviderMessage.tunRuntimeProfileOptionKey],
           let profile = tunRuntimeProfileValue(optionValue) {
            return profile
        }

        if let configurationValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerTunRuntimeProfileKey
        ],
            let profile = tunRuntimeProfileValue(configurationValue) {
            return profile
        }

        return .default
    }

    static func startupProbeConfiguration(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> XrayPacketTunnelStartupProbeConfiguration {
        let enabledValue = options?[
            XrayTunnelProviderMessage.startupProbeEnabledOptionKey
        ] ?? providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeEnabledKey
        ]
        guard let enabledValue else {
            return .disabled
        }
        guard let isEnabled = boolValue(enabledValue) else {
            return .invalid
        }
        guard isEnabled else {
            return .disabled
        }

        let urlValue = options?[
            XrayTunnelProviderMessage.startupProbeURLOptionKey
        ] ?? providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeURLKey
        ]
        guard let url = stringValue(urlValue), isValidStartupProbeURL(url) else {
            return .invalid
        }
        let timeoutValue = options?[
            XrayTunnelProviderMessage.startupProbeTimeoutMsOptionKey
        ] ?? providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeTimeoutMsKey
        ]
        let timeoutMs: UInt64
        if let timeoutValue {
            guard let explicitTimeoutMs = uint64Value(timeoutValue),
                  explicitTimeoutMs <= maximumStartupProbeTimeoutMs
            else {
                return .invalid
            }
            timeoutMs = explicitTimeoutMs
        } else {
            timeoutMs = defaultStartupProbeTimeoutMs
        }
        let outboundTag: String?
        if let optionValue = options?[
            XrayTunnelProviderMessage.startupProbeOutboundTagOptionKey
        ] {
            guard let explicitOutboundTag = stringValue(optionValue) else {
                return .invalid
            }
            outboundTag = explicitOutboundTag
        } else if let providerValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeOutboundTagKey
        ] {
            guard let explicitOutboundTag = stringValue(providerValue) else {
                return .invalid
            }
            outboundTag = explicitOutboundTag
        } else {
            outboundTag = nil
        }

        return .enabled(
            XrayStartupProbeOptions(
                url: url,
                timeoutMs: timeoutMs,
                outboundTag: outboundTag
            )
        )
    }

    static func dnsConfiguration(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> XrayPacketTunnelDNSConfiguration {
        if let optionValue = options?[XrayTunnelProviderMessage.dnsServersOptionKey] {
            return dnsConfiguration(value: optionValue)
        }
        if let providerValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerDNSServersKey
        ] {
            return dnsConfiguration(value: providerValue)
        }
        return .system
    }

    static func networkSettings(
        excludingServerAddress serverAddress: String? = nil,
        resolvedDNSConfiguration: XrayPacketTunnelResolvedDNSConfiguration
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)
        settings.mtu = 1500

        let ipv4Settings = NEIPv4Settings(
            addresses: ["198.18.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        if let excludedRoute = ipv4ExcludedRoute(for: serverAddress) {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Excluding proxy server IPv4 route \(excludedRoute.destinationAddress)/32 from tunnel"
            )
            ipv4Settings.excludedRoutes = [excludedRoute]
        }
        settings.ipv4Settings = ipv4Settings

        // A full tunnel must install an explicit DNS destination. Otherwise
        // the system resolver can be routed into the tunnel and blackhole.
        // In locally handled DNS modes (fake-IP or raw forwarding) the
        // tunnel-local address is an interception anchor, not an upstream.
        let servers: [String]
        switch resolvedDNSConfiguration {
        case .localDNSAnchor:
            servers = [tunnelRemoteAddress]
        case let .custom(custom):
            servers = custom
        }
        let dnsSettings = NEDNSSettings(servers: servers)
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings
        return settings
    }

    static func resolvedDNSConfiguration(
        configJSON: String,
        explicit: XrayPacketTunnelDNSConfiguration
    ) -> XrayPacketTunnelResolvedDNSConfiguration? {
        let hasFakeIP = fakeIPDNSIsAvailable(configJSON)
        let hasIPLiteralUpstream = ipLiteralDNSUpstreamIsAvailable(configJSON)
        switch explicit {
        case let .custom(servers) where !hasFakeIP:
            return .custom(servers)
        case .custom:
            return nil
        case .invalid:
            return nil
        case .system:
            return hasFakeIP || hasIPLiteralUpstream ? .localDNSAnchor : nil
        }
    }

    static func validateConfigBeforeApplyingNetworkSettings(
        _ configJSON: String,
        geodataSearchDirectory: URL? = Bundle.main.resourceURL
    ) throws {
        _ = try XrayCore(
            configJSON: configJSON,
            geodataSearchDirectory: geodataSearchDirectory
        )
    }

    private static func fakeIPDNSIsAvailable(_ configJSON: String) -> Bool {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let dns = root["dns"] as? [String: Any],
              let fakeIP = dns["fakeIp"] as? [String: Any],
              Set(dns.keys).isSubset(of: ["fakeIp", "servers", "hosts"]),
              Set(fakeIP.keys).isSubset(of: ["enabled", "ipv4Pool", "ttl"]),
              isJSONBooleanTrue(fakeIP["enabled"]),
              let ipv4Pool = fakeIP["ipv4Pool"] as? String
        else {
            return false
        }
        if let ttl = fakeIP["ttl"], !isJSONUInt32(ttl) {
            return false
        }
        return isValidIPv4Pool(ipv4Pool)
    }

    private static func ipLiteralDNSUpstreamIsAvailable(_ configJSON: String) -> Bool {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let dns = root["dns"] as? [String: Any],
              let servers = dns["servers"] as? [Any]
        else {
            return false
        }
        return servers.contains { rawServer in
            guard let server = rawServer as? String else {
                return false
            }
            return isNonzeroIPLiteralDNSServer(server)
        }
    }

    private static func isNonzeroIPLiteralDNSServer(_ server: String) -> Bool {
        // Bare IP literals use the Rust parser's default DNS port 53.
        if isIPAddress(server, family: AF_INET) || isIPAddress(server, family: AF_INET6) {
            return true
        }

        // Brackets are required for an IPv6 SocketAddr with an explicit port.
        if server.first == "[", let closingBracket = server.lastIndex(of: "]") {
            let addressStart = server.index(after: server.startIndex)
            let portSeparator = server.index(after: closingBracket)
            guard portSeparator < server.endIndex,
                  server[portSeparator] == ":",
                  server.index(after: portSeparator) < server.endIndex,
                  closingBracket > addressStart,
                  isIPv6SocketAddressLiteral(String(server[addressStart..<closingBracket])),
                  let port = UInt16(server[server.index(after: portSeparator)...]),
                  port != 0
            else {
                return false
            }
            return true
        }

        // An unbracketed SocketAddr can only be IPv4; domain:port stays domain-only.
        guard let separator = server.lastIndex(of: ":"),
              !server[..<separator].contains(":"),
              isIPAddress(String(server[..<separator]), family: AF_INET),
              let port = UInt16(server[server.index(after: separator)...]),
              port != 0
        else {
            return false
        }
        return true
    }

    private static func isIPv6SocketAddressLiteral(_ address: String) -> Bool {
        if isIPAddress(address, family: AF_INET6) {
            return true
        }
        guard let scopeSeparator = address.lastIndex(of: "%"),
              scopeSeparator > address.startIndex,
              address.index(after: scopeSeparator) < address.endIndex,
              UInt32(address[address.index(after: scopeSeparator)...]) != nil
        else {
            return false
        }
        return isIPAddress(String(address[..<scopeSeparator]), family: AF_INET6)
    }

    private static func isJSONBooleanTrue(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else {
            return false
        }
        return number.boolValue
    }

    private static func isJSONUInt32(_ value: Any) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else {
            return false
        }
        let integerEncodings = "cislqCISLQ"
        guard let encoding = String(cString: number.objCType).first,
              integerEncodings.contains(encoding)
        else {
            return false
        }
        let numericValue = number.doubleValue
        return numericValue >= 0 && numericValue <= Double(UInt32.max)
    }

    private static func isValidIPv4Pool(_ value: String) -> Bool {
        let components = value.split(
            separator: "/",
            maxSplits: 1,
            omittingEmptySubsequences: false
        )
        guard let address = components.first,
              isIPAddress(String(address), family: AF_INET)
        else {
            return false
        }
        if components.count == 1 {
            return true
        }
        guard let prefix = UInt8(components[1]) else {
            return false
        }
        return prefix <= 32
    }

    private static func dnsConfiguration(value: Any) -> XrayPacketTunnelDNSConfiguration {
        let rawServers: [Any]
        switch value {
        case let values as NSArray:
            rawServers = values.map { $0 }
        case let value as NSString:
            rawServers = [String(value)]
        case let value as String:
            rawServers = [value]
        default:
            return .invalid
        }

        guard !rawServers.isEmpty, rawServers.count <= maximumCustomDNSServers else {
            return .invalid
        }

        var servers: [String] = []
        var seenServers = Set<String>()
        for rawServer in rawServers {
            guard let server = stringValue(rawServer),
                  isIPAddress(server, family: AF_INET)
            else {
                return .invalid
            }
            let identity = server.lowercased()
            if seenServers.insert(identity).inserted {
                servers.append(server)
            }
        }
        return servers.isEmpty ? .invalid : .custom(servers)
    }

    private static func isValidStartupProbeURL(_ rawURL: String) -> Bool {
        guard !rawURL.contains("#") else {
            return false
        }

        let remainder: Substring
        if rawURL.hasPrefix("https://") {
            remainder = rawURL.dropFirst("https://".count)
        } else if rawURL.hasPrefix("http://") {
            remainder = rawURL.dropFirst("http://".count)
        } else {
            return false
        }

        let authorityEnd = remainder.firstIndex { character in
            character == "/" || character == "?"
        } ?? remainder.endIndex
        let authority = remainder[..<authorityEnd]
        guard !authority.isEmpty,
              !authority.contains("@"),
              !authority.hasPrefix(":"),
              !authority.hasPrefix("["),
              !containsASCIIWhitespaceOrControl(authority)
        else {
            return false
        }

        let authorityParts = authority.split(
            separator: ":",
            maxSplits: 2,
            omittingEmptySubsequences: false
        )
        switch authorityParts.count {
        case 1:
            break
        case 2:
            let host = authorityParts[0]
            let port = authorityParts[1]
            guard !host.isEmpty,
                  !port.isEmpty,
                  port.unicodeScalars.allSatisfy({
                      $0.value >= 0x30 && $0.value <= 0x39
                  }),
                  UInt16(port) != nil
            else {
                return false
            }
        default:
            return false
        }

        let requestTarget = remainder[authorityEnd...]
        guard requestTarget.isEmpty
                || requestTarget.hasPrefix("/")
                || requestTarget.hasPrefix("?"),
              !containsASCIIWhitespaceOrControl(requestTarget)
        else {
            return false
        }
        return true
    }

    private static func containsASCIIWhitespaceOrControl(
        _ value: some StringProtocol
    ) -> Bool {
        value.unicodeScalars.contains { scalar in
            scalar.isASCII && (scalar.value <= 0x20 || scalar.value == 0x7F)
        }
    }

    private static func ipv4ExcludedRoute(for serverAddress: String?) -> NEIPv4Route? {
        guard let serverAddress, isIPAddress(serverAddress, family: AF_INET) else {
            return nil
        }
        return NEIPv4Route(
            destinationAddress: serverAddress,
            subnetMask: "255.255.255.255"
        )
    }

    private static func isIPAddress(_ address: String, family: Int32) -> Bool {
        var storage = sockaddr_storage()
        return withUnsafeMutablePointer(to: &storage) { pointer in
            address.withCString { rawAddress in
                inet_pton(family, rawAddress, pointer) == 1
            }
        }
    }

    private static func boolValue(_ value: Any) -> Bool? {
        switch value {
        case let value as Bool:
            return value
        case let value as NSNumber:
            return value.boolValue
        case let value as NSString:
            return boolValue(String(value))
        case let value as String:
            let normalizedValue = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            switch normalizedValue {
            case "1", "true", "yes":
                return true
            case "0", "false", "no":
                return false
            default:
                return nil
            }
        default:
            return nil
        }
    }

    private static func tunRuntimeProfileValue(_ value: Any) -> XrayTunRuntimeProfileSetting? {
        switch value {
        case let value as NSString:
            return XrayTunRuntimeProfileSetting(configurationValue: String(value))
        case let value as String:
            return XrayTunRuntimeProfileSetting(configurationValue: value)
        default:
            return nil
        }
    }

    private static func stringValue(_ value: Any?) -> String? {
        let raw: String?
        switch value {
        case let value as NSString:
            raw = String(value)
        case let value as String:
            raw = value
        default:
            raw = nil
        }

        let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }

    private static func uint64Value(_ value: Any?) -> UInt64? {
        switch value {
        case let value as NSNumber where value.int64Value > 0:
            return UInt64(value.int64Value)
        case let value as NSString:
            return uint64Value(String(value))
        case let value as String:
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return UInt64(trimmed).flatMap { $0 > 0 ? $0 : nil }
        default:
            return nil
        }
    }

    private func makeRuntime(
        resolvedConfig: ResolvedConfig,
        diagnosticLogDirectory: URL?,
        lifecycleToken: XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime>.Token
    ) throws -> XrayPacketTunnelRuntime {
        let backend = Self.packetIOBackend(
            discoveredTunFileDescriptor: XrayDarwinTunFileDescriptor.discoverUtunFileDescriptor(),
            useTunFileDescriptor: resolvedConfig.useTunFileDescriptor
        )
        XrayAppleLog.info("PacketTunnelProvider", "Creating XrayCore")
        let core: XrayCore
        let pump: XrayPacketTunnelPump?
        switch backend {
        case let .darwinUtunFileDescriptor(fd):
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Using Darwin utun file descriptor for packet I/O"
            )
            core = try XrayCore(
                configJSON: resolvedConfig.json,
                borrowedDarwinTunFileDescriptor: fd,
                collectTcpTimings: resolvedConfig.debugLoggingEnabled,
                tunRuntimeProfile: XrayCore.tunRuntimeProfile(
                    named: resolvedConfig.tunRuntimeProfile.rawValue
                ),
                geodataSearchDirectory: Bundle.main.resourceURL,
                startupProbe: resolvedConfig.startupProbeConfiguration.options,
                fileLogDirectory: diagnosticLogDirectory
            )
            pump = nil
        case .packetFlowPump:
            if resolvedConfig.useTunFileDescriptor {
                XrayAppleLog.info(
                    "PacketTunnelProvider",
                    "No Darwin utun fd found; using packetFlow pump for packet I/O"
                )
            } else {
                XrayAppleLog.info(
                    "PacketTunnelProvider",
                    "Darwin utun fd disabled; using packetFlow pump for packet I/O"
                )
            }
            core = try XrayCore(
                configJSON: resolvedConfig.json,
                collectTcpTimings: resolvedConfig.debugLoggingEnabled,
                tunRuntimeProfile: XrayCore.tunRuntimeProfile(
                    named: resolvedConfig.tunRuntimeProfile.rawValue
                ),
                geodataSearchDirectory: Bundle.main.resourceURL,
                startupProbe: resolvedConfig.startupProbeConfiguration.options,
                fileLogDirectory: diagnosticLogDirectory
            )
            let providerReference = XrayWeakReference(self)
            pump = XrayPacketTunnelPump(
                provider: self,
                core: core,
                terminalFailureHandler: { error in
                    providerReference.value?.handlePacketPumpTerminalFailure(
                        error,
                        lifecycleToken: lifecycleToken
                    )
                }
            )
        }

        do {
            XrayAppleLog.info("PacketTunnelProvider", "Starting XrayCore")
            try core.start()
            if let pump {
                XrayAppleLog.info("PacketTunnelProvider", "Starting packet pump")
                pump.start()
            }
            return XrayPacketTunnelRuntime(core: core, pump: pump)
        } catch {
            pump?.stop()
            try? core.stop()
            throw error
        }
    }

    private func handlePacketPumpTerminalFailure(
        _ error: XrayPacketTunnelPumpError,
        lifecycleToken: XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime>.Token
    ) {
        guard lifecycle.stop(ifCurrent: lifecycleToken) else {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Ignoring terminal failure from a superseded packet pump"
            )
            return
        }
        XrayAppleLog.error(
            "PacketTunnelProvider",
            "Packet pump failed permanently; cancelling the tunnel: \(error.localizedDescription)"
        )
        cancelTunnelWithError(error)
        XrayAppleLog.configureFileLogging(directory: nil)
    }

    private static func logDebugStats(_ core: XrayCore) {
        do {
            let stats = try core.stats()
            for message in stats.debugLogMessages() {
                XrayAppleLog.info("PacketTunnelProvider", message)
            }
            for event in try core.pollTcpSlowFlowEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollTcpFlowSummaryEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollTcpRemoteWriteSlowEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollTcpOpenErrorEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollUdpSlowFlowEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollUdpResponseGapEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollUdpQuicBlockedEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
        } catch {
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Failed to read debug stats: \(error.localizedDescription)"
            )
        }
    }
}

@available(iOSApplicationExtension 15.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
private final class XrayPacketTunnelRuntime {
    let core: XrayCore

    private let lock = NSLock()
    private var pump: XrayPacketTunnelPump?
    private var debugStatsTimer: DispatchSourceTimer?
    private var isStopped = false

    init(core: XrayCore, pump: XrayPacketTunnelPump?) {
        self.core = core
        self.pump = pump
    }

    func startDebugStatsLogging(
        queue: DispatchQueue,
        handler: @escaping @Sendable (XrayCore) -> Void
    ) {
        lock.lock()
        defer { lock.unlock() }
        guard !isStopped, debugStatsTimer == nil else {
            return
        }

        XrayAppleLog.info("PacketTunnelProvider", "Debug stats logging enabled")
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            guard let self, let core = self.runningCore() else {
                return
            }
            handler(core)
        }
        debugStatsTimer = timer
        timer.resume()
    }

    func stop() {
        let timer: DispatchSourceTimer?
        let pump: XrayPacketTunnelPump?
        lock.lock()
        if isStopped {
            lock.unlock()
            return
        }
        isStopped = true
        timer = debugStatsTimer
        debugStatsTimer = nil
        pump = self.pump
        self.pump = nil
        lock.unlock()

        timer?.setEventHandler {}
        timer?.cancel()
        pump?.stop()
        do {
            try core.stop()
            XrayAppleLog.info("PacketTunnelProvider", "XrayCore stopped")
        } catch {
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Failed to stop XrayCore: \(error.localizedDescription)"
            )
        }
    }

    private func runningCore() -> XrayCore? {
        lock.lock()
        defer { lock.unlock() }
        return isStopped ? nil : core
    }
}

enum XrayPacketTunnelIOBackend: Equatable {
    case darwinUtunFileDescriptor(Int32)
    case packetFlowPump
}

@available(iOSApplicationExtension 15.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
private extension NEProviderStopReason {
    var xrayDescription: String {
        switch self {
        case .none:
            return "none"
        case .userInitiated:
            return "userInitiated"
        case .providerFailed:
            return "providerFailed"
        case .noNetworkAvailable:
            return "noNetworkAvailable"
        case .unrecoverableNetworkChange:
            return "unrecoverableNetworkChange"
        case .providerDisabled:
            return "providerDisabled"
        case .authenticationCanceled:
            return "authenticationCanceled"
        case .configurationFailed:
            return "configurationFailed"
        case .idleTimeout:
            return "idleTimeout"
        case .configurationDisabled:
            return "configurationDisabled"
        case .configurationRemoved:
            return "configurationRemoved"
        case .superceded:
            return "superceded"
        case .userLogout:
            return "userLogout"
        case .userSwitch:
            return "userSwitch"
        case .connectionFailed:
            return "connectionFailed"
        case .sleep:
            return "sleep"
        case .appUpdate:
            return "appUpdate"
        case .internalError:
            return "internalError"
        @unknown default:
            return "unknown"
        }
    }
}
#endif
