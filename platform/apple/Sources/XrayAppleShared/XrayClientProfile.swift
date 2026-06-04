import Foundation

public struct XrayClientProfile: Codable, Equatable, Identifiable, Sendable {
    public static let defaultRealityVisionFlow = "xtls-rprx-vision"

    public var id: UUID
    public var name: String
    public var providerBundleIdentifier: String
    public var serverAddress: String
    public var configJSON: String
    public var debugLoggingEnabled: Bool
    public var useTunFileDescriptor: Bool
    public var blockQUIC: Bool

    public init(
        id: UUID = UUID(),
        name: String,
        providerBundleIdentifier: String,
        serverAddress: String,
        configJSON: String,
        debugLoggingEnabled: Bool = false,
        useTunFileDescriptor: Bool = true,
        blockQUIC: Bool = false
    ) {
        self.id = id
        self.name = name
        self.providerBundleIdentifier = providerBundleIdentifier
        self.serverAddress = serverAddress
        self.configJSON = configJSON
        self.debugLoggingEnabled = debugLoggingEnabled
        self.useTunFileDescriptor = useTunFileDescriptor
        self.blockQUIC = blockQUIC
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case providerBundleIdentifier
        case serverAddress
        case configJSON
        case debugLoggingEnabled
        case useTunFileDescriptor
        case blockQUIC
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        name = try container.decode(String.self, forKey: .name)
        providerBundleIdentifier = try container.decode(
            String.self,
            forKey: .providerBundleIdentifier
        )
        serverAddress = try container.decode(String.self, forKey: .serverAddress)
        configJSON = try container.decode(String.self, forKey: .configJSON)
        debugLoggingEnabled = try container.decodeIfPresent(
            Bool.self,
            forKey: .debugLoggingEnabled
        ) ?? false
        useTunFileDescriptor = try container.decodeIfPresent(
            Bool.self,
            forKey: .useTunFileDescriptor
        ) ?? true
        blockQUIC = try container.decodeIfPresent(Bool.self, forKey: .blockQUIC) ?? false
    }

    public static func defaultProfile(
        hostBundleIdentifier: String? = Bundle.main.bundleIdentifier
    ) -> XrayClientProfile {
        XrayClientProfile(
            name: "Xray",
            providerBundleIdentifier: defaultProviderBundleIdentifier(
                hostBundleIdentifier: hostBundleIdentifier
            ),
            serverAddress: "xray-rust",
            configJSON: directTunConfigJSON
        )
    }

    public static func defaultProviderBundleIdentifier(
        hostBundleIdentifier: String? = Bundle.main.bundleIdentifier
    ) -> String {
        guard let hostBundleIdentifier, !hostBundleIdentifier.isEmpty else {
            return "org.xrayrust.apple.Tunnel"
        }
        return "\(hostBundleIdentifier).Tunnel"
    }

    public func migratingLegacyDefaultProviderBundleIdentifier(
        hostBundleIdentifier: String? = Bundle.main.bundleIdentifier
    ) -> XrayClientProfile {
        let currentDefault = Self.defaultProviderBundleIdentifier(
            hostBundleIdentifier: hostBundleIdentifier
        )
        let legacyDefault: String
        if let hostBundleIdentifier, !hostBundleIdentifier.isEmpty {
            legacyDefault = "\(hostBundleIdentifier).PacketTunnel"
        } else {
            legacyDefault = "org.xrayrust.apple.PacketTunnel"
        }

        guard providerBundleIdentifier == legacyDefault else {
            return self
        }

        var migrated = self
        migrated.providerBundleIdentifier = currentDefault
        return migrated
    }

    public func addingDefaultRealityVisionFlowIfMissing() -> XrayClientProfile {
        guard let normalizedConfigJSON = Self.configJSONAddingDefaultRealityVisionFlowIfMissing(
            configJSON
        ) else {
            return self
        }

        var profile = self
        profile.configJSON = normalizedConfigJSON
        return profile
    }

    private static func configJSONAddingDefaultRealityVisionFlowIfMissing(
        _ configJSON: String
    ) -> String? {
        guard let data = configJSON.data(using: .utf8),
              var root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              var outbounds = root["outbounds"] as? [[String: Any]]
        else {
            return nil
        }

        var didChange = false
        for outboundIndex in outbounds.indices {
            guard outbounds[outboundIndex]["protocol"] as? String == "vless",
                  let streamSettings = outbounds[outboundIndex]["streamSettings"] as? [String: Any],
                  streamSettings["security"] as? String == "reality",
                  var settings = outbounds[outboundIndex]["settings"] as? [String: Any],
                  var vnext = settings["vnext"] as? [[String: Any]]
            else {
                continue
            }

            for serverIndex in vnext.indices {
                guard var users = vnext[serverIndex]["users"] as? [[String: Any]] else {
                    continue
                }

                for userIndex in users.indices where (users[userIndex]["flow"] as? String)?.isEmpty ?? true {
                    users[userIndex]["flow"] = Self.defaultRealityVisionFlow
                    didChange = true
                }

                vnext[serverIndex]["users"] = users
            }

            settings["vnext"] = vnext
            outbounds[outboundIndex]["settings"] = settings
        }

        guard didChange else {
            return nil
        }

        root["outbounds"] = outbounds
        guard let normalizedData = try? JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        ) else {
            return nil
        }
        return String(data: normalizedData, encoding: .utf8)
    }

    public static let directTunConfigJSON = """
    {
      "inbounds": [
        {
          "tag": "tun-in",
          "protocol": "tun",
          "listen": "127.0.0.1",
          "port": 0,
          "settings": {}
        }
      ],
      "outbounds": [
        {
          "tag": "direct",
          "protocol": "freedom",
          "settings": {}
        }
      ]
    }
    """
}

public enum XrayClientConnectionStatus: String, Codable, Equatable, Sendable {
    case invalid
    case disconnected
    case connecting
    case connected
    case reasserting
    case disconnecting
    case unknown

    public var isActive: Bool {
        switch self {
        case .connected, .connecting, .reasserting:
            return true
        case .invalid, .disconnected, .disconnecting, .unknown:
            return false
        }
    }

    public var displayName: String {
        switch self {
        case .invalid:
            return "Invalid"
        case .disconnected:
            return "Disconnected"
        case .connecting:
            return "Connecting"
        case .connected:
            return "Connected"
        case .reasserting:
            return "Reasserting"
        case .disconnecting:
            return "Disconnecting"
        case .unknown:
            return "Unknown"
        }
    }
}

public struct XrayClientRuntimeStats: Codable, Equatable, Sendable {
    public var inboundPackets: UInt64
    public var outboundPackets: UInt64
    public var droppedPackets: UInt64
    public var activeTCPFlows: UInt64
    public var activeUDPFlows: UInt64
    public var udpFlowLimit: UInt64
    public var udpBudgetDrops: UInt64
    public var udpEvictedFlows: UInt64
    public var udpChannelDroppedPackets: UInt64
    public var udpOpenErrors: UInt64
    public var udpVisionUDP443Rejections: UInt64
    public var udpRemoteWriteErrors: UInt64
    public var udpRemoteReadErrors: UInt64
    public var udpRemoteClosedEvents: UInt64
    public var udpQuicBlockedPackets: UInt64

    public init(
        inboundPackets: UInt64,
        outboundPackets: UInt64,
        droppedPackets: UInt64,
        activeTCPFlows: UInt64 = 0,
        activeUDPFlows: UInt64 = 0,
        udpFlowLimit: UInt64 = 0,
        udpBudgetDrops: UInt64 = 0,
        udpEvictedFlows: UInt64 = 0,
        udpChannelDroppedPackets: UInt64 = 0,
        udpOpenErrors: UInt64 = 0,
        udpVisionUDP443Rejections: UInt64 = 0,
        udpRemoteWriteErrors: UInt64 = 0,
        udpRemoteReadErrors: UInt64 = 0,
        udpRemoteClosedEvents: UInt64 = 0,
        udpQuicBlockedPackets: UInt64 = 0
    ) {
        self.inboundPackets = inboundPackets
        self.outboundPackets = outboundPackets
        self.droppedPackets = droppedPackets
        self.activeTCPFlows = activeTCPFlows
        self.activeUDPFlows = activeUDPFlows
        self.udpFlowLimit = udpFlowLimit
        self.udpBudgetDrops = udpBudgetDrops
        self.udpEvictedFlows = udpEvictedFlows
        self.udpChannelDroppedPackets = udpChannelDroppedPackets
        self.udpOpenErrors = udpOpenErrors
        self.udpVisionUDP443Rejections = udpVisionUDP443Rejections
        self.udpRemoteWriteErrors = udpRemoteWriteErrors
        self.udpRemoteReadErrors = udpRemoteReadErrors
        self.udpRemoteClosedEvents = udpRemoteClosedEvents
        self.udpQuicBlockedPackets = udpQuicBlockedPackets
    }
}
