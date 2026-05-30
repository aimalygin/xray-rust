#if canImport(NetworkExtension)
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
            "Resolved config source=\(resolvedConfig.source) bytes=\(resolvedConfig.json.utf8.count)"
        )

        setTunnelNetworkSettings(Self.networkSettings()) { [weak self] error in
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
                XrayAppleLog.info("PacketTunnelProvider", "Creating XrayCore")
                let core = try XrayCore(configJSON: resolvedConfig.json)
                let pump = XrayPacketTunnelPump(provider: self, core: core)
                XrayAppleLog.info("PacketTunnelProvider", "Starting XrayCore")
                try core.start()
                XrayAppleLog.info("PacketTunnelProvider", "Starting packet pump")
                pump.start()

                self.core = core
                self.pump = pump
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
            droppedPackets: stats.droppedPackets
        )
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "Returning stats inbound=\(runtimeStats.inboundPackets) outbound=\(runtimeStats.outboundPackets) dropped=\(runtimeStats.droppedPackets)"
        )
        completionHandler?(try? XrayTunnelProviderMessage.encodeStatsResponse(runtimeStats))
    }

    private struct ResolvedConfig {
        var json: String
        var source: String
    }

    private static func configJSON(
        options: [String: NSObject]?,
        protocolConfiguration: NEVPNProtocol
    ) -> ResolvedConfig? {
        if let configJSON = options?[XrayTunnelProviderMessage.configJSONOptionKey] as? String {
            return ResolvedConfig(json: configJSON, source: "startTunnelOptions")
        }

        let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol
        guard let configJSON = tunnelProtocol?.providerConfiguration?[
            XrayTunnelProviderMessage.providerConfigJSONKey
        ] as? String else {
            return nil
        }
        return ResolvedConfig(json: configJSON, source: "providerConfiguration")
    }

    private static func networkSettings() -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")
        settings.mtu = 1500

        let ipv4Settings = NEIPv4Settings(
            addresses: ["198.18.0.2"],
            subnetMasks: ["255.255.255.0"]
        )
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4Settings

        let ipv6Settings = NEIPv6Settings(
            addresses: ["fd00:7872::2"],
            networkPrefixLengths: [64]
        )
        ipv6Settings.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6Settings

        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        return settings
    }
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
