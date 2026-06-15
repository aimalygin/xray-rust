#if canImport(NetworkExtension)
import Darwin
import Dispatch
import Foundation
import NetworkExtension
import XrayAppleShared
import XrayMobileAdapter

public enum XrayPacketTunnelProviderError: Error, LocalizedError {
    case missingConfigJSON

    public var errorDescription: String? {
        switch self {
        case .missingConfigJSON:
            return "Missing Xray JSON configuration."
        }
    }
}

@available(iOSApplicationExtension 16.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
open class XrayPacketTunnelProvider: NEPacketTunnelProvider {
    private var core: XrayCore?
    private var pump: XrayPacketTunnelPump?
    private var debugStatsTimer: DispatchSourceTimer?
    private let debugStatsQueue = DispatchQueue(
        label: "org.xrayrust.apple.packet-tunnel.debug-stats"
    )

    open override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let optionKeys = options?.keys.sorted().joined(separator: ",") ?? "none"
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "startTunnel invoked optionKeys=\(optionKeys)"
        )

        guard let resolvedConfig = Self.configJSON(
            options: options,
            protocolConfiguration: protocolConfiguration
        ) else {
            XrayAppleLog.error("PacketTunnelProvider", "Missing config JSON")
            completionHandler(XrayPacketTunnelProviderError.missingConfigJSON)
            return
        }
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "Resolved config source=\(resolvedConfig.source) bytes=\(resolvedConfig.json.utf8.count) debugLogging=\(resolvedConfig.debugLoggingEnabled) useTunFileDescriptor=\(resolvedConfig.useTunFileDescriptor) tunRuntimeProfile=\(resolvedConfig.tunRuntimeProfile.rawValue)"
        )
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "Config summary \(Self.configSummary(resolvedConfig.json))"
        )

        setTunnelNetworkSettings(
            Self.networkSettings(excludingServerAddress: resolvedConfig.serverAddress)
        ) { [weak self] error in
            guard let self else {
                XrayAppleLog.error("PacketTunnelProvider", "Provider released before network settings completed")
                completionHandler(CocoaError(.userCancelled))
                return
            }
            if let error {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "setTunnelNetworkSettings failed: \(error.localizedDescription)"
                )
                completionHandler(error)
                return
            }
            XrayAppleLog.info("PacketTunnelProvider", "Tunnel network settings applied")

            do {
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
                        )
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
                        )
                    )
                    pump = XrayPacketTunnelPump(
                        provider: self,
                        core: core
                    )
                }
                XrayAppleLog.info("PacketTunnelProvider", "Starting XrayCore")
                try core.start()
                if let pump {
                    XrayAppleLog.info("PacketTunnelProvider", "Starting packet pump")
                    pump.start()
                }

                self.core = core
                self.pump = pump
                if resolvedConfig.debugLoggingEnabled {
                    self.startDebugStatsLogging()
                } else {
                    self.stopDebugStatsLogging()
                }
                XrayAppleLog.info("PacketTunnelProvider", "startTunnel completed successfully")
                completionHandler(nil)
            } catch {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "startTunnel failed: \(error.localizedDescription)"
                )
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
        stopDebugStatsLogging()
        pump?.stop()
        pump = nil
        do {
            try core?.stop()
            XrayAppleLog.info("PacketTunnelProvider", "XrayCore stopped")
        } catch {
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Failed to stop XrayCore: \(error.localizedDescription)"
            )
        }
        core = nil
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
              let stats = try? core?.stats()
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

    private struct ResolvedConfig {
        var json: String
        var source: String
        var serverAddress: String?
        var debugLoggingEnabled: Bool
        var useTunFileDescriptor: Bool
        var tunRuntimeProfile: XrayTunRuntimeProfileSetting
    }

    private static func configJSON(
        options: [String: NSObject]?,
        protocolConfiguration: NEVPNProtocol
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

        if let configJSON = options?[XrayTunnelProviderMessage.configJSONOptionKey] as? String {
            return ResolvedConfig(
                json: configJSON,
                source: "startTunnelOptions",
                serverAddress: serverAddress,
                debugLoggingEnabled: isDebugLoggingEnabled,
                useTunFileDescriptor: shouldUseTunFileDescriptor,
                tunRuntimeProfile: selectedTunRuntimeProfile
            )
        }

        guard let configJSON = tunnelProtocol?.providerConfiguration?[
            XrayTunnelProviderMessage.providerConfigJSONKey
        ] as? String else {
            return nil
        }
        return ResolvedConfig(
            json: configJSON,
            source: "providerConfiguration",
            serverAddress: serverAddress,
            debugLoggingEnabled: isDebugLoggingEnabled,
            useTunFileDescriptor: shouldUseTunFileDescriptor,
            tunRuntimeProfile: selectedTunRuntimeProfile
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

        return "inbounds=\(inbounds.isEmpty ? "none" : inbounds.joined(separator: ",")) outbounds=\(outbounds.isEmpty ? "none" : outbounds.joined(separator: ", ")) routingRules=\(routingRules)"
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
        let address = firstServer?["address"] as? String ?? "unknown"
        let port = firstServer?["port"].map { "\($0)" } ?? "unknown"
        let users = firstServer?["users"] as? [[String: Any]]
        let flow = users?.first?["flow"] as? String ?? "none"
        let streamSettings = outbound["streamSettings"] as? [String: Any]
        let network = streamSettings?["network"] as? String ?? "unknown"
        let security = streamSettings?["security"] as? String ?? "unknown"

        return "\(tag):\(protocolName)@\(address):\(port) network=\(network) security=\(security) flow=\(flow)"
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

    static func networkSettings(excludingServerAddress serverAddress: String? = nil) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
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

        let dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings
        return settings
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

    private func startDebugStatsLogging() {
        stopDebugStatsLogging()

        XrayAppleLog.info("PacketTunnelProvider", "Debug stats logging enabled")
        let timer = DispatchSource.makeTimerSource(queue: debugStatsQueue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            do {
                guard let stats = try self.core?.stats() else {
                    XrayAppleLog.info("PacketTunnelProvider", "Debug stats unavailable: no core")
                    return
                }
                for message in stats.debugLogMessages() {
                    XrayAppleLog.info("PacketTunnelProvider", message)
                }
                for event in try self.core?.pollTcpSlowFlowEvents() ?? [] {
                    XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
                }
                for event in try self.core?.pollTcpFlowSummaryEvents() ?? [] {
                    XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
                }
                for event in try self.core?.pollTcpRemoteWriteSlowEvents() ?? [] {
                    XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
                }
                for event in try self.core?.pollUdpSlowFlowEvents() ?? [] {
                    XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
                }
                for event in try self.core?.pollUdpResponseGapEvents() ?? [] {
                    XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
                }
                for event in try self.core?.pollUdpQuicBlockedEvents() ?? [] {
                    XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
                }
            } catch {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "Failed to read debug stats: \(error.localizedDescription)"
                )
            }
        }
        debugStatsTimer = timer
        timer.resume()
    }

    private func stopDebugStatsLogging() {
        debugStatsTimer?.setEventHandler {}
        debugStatsTimer?.cancel()
        debugStatsTimer = nil
    }
}

enum XrayPacketTunnelIOBackend: Equatable {
    case darwinUtunFileDescriptor(Int32)
    case packetFlowPump
}

@available(iOSApplicationExtension 16.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
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
