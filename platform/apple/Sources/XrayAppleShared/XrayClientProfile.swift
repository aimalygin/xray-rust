import Foundation

public enum XrayTunRuntimeProfileSetting: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case `default` = "default"
    case mobile
    case desktop
    case lowMemory = "low-memory"
    case throughput

    public var id: String {
        rawValue
    }

    public var displayName: String {
        switch self {
        case .default:
            return "Default"
        case .mobile:
            return "Mobile"
        case .desktop:
            return "Desktop"
        case .lowMemory:
            return "Low Memory"
        case .throughput:
            return "Throughput"
        }
    }

    public init?(configurationValue: String) {
        let normalizedValue = configurationValue
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        switch normalizedValue {
        case "default":
            self = .default
        case "mobile":
            self = .mobile
        case "desktop":
            self = .desktop
        case "low-memory", "low_memory", "lowmemory":
            self = .lowMemory
        case "throughput":
            self = .throughput
        default:
            return nil
        }
    }
}

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
    public var tunRuntimeProfile: XrayTunRuntimeProfileSetting

    public init(
        id: UUID = UUID(),
        name: String,
        providerBundleIdentifier: String,
        serverAddress: String,
        configJSON: String,
        debugLoggingEnabled: Bool = false,
        useTunFileDescriptor: Bool = true,
        blockQUIC: Bool = false,
        tunRuntimeProfile: XrayTunRuntimeProfileSetting = .default
    ) {
        self.id = id
        self.name = name
        self.providerBundleIdentifier = providerBundleIdentifier
        self.serverAddress = serverAddress
        self.configJSON = configJSON
        self.debugLoggingEnabled = debugLoggingEnabled
        self.useTunFileDescriptor = useTunFileDescriptor
        self.blockQUIC = blockQUIC
        self.tunRuntimeProfile = tunRuntimeProfile
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
        case tunRuntimeProfile
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
        tunRuntimeProfile = try container.decodeIfPresent(
            XrayTunRuntimeProfileSetting.self,
            forKey: .tunRuntimeProfile
        ) ?? .default
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
    public var tcpOpenEvents: UInt64
    public var tcpOpenDurationMsTotal: UInt64
    public var tcpOpenDurationMsMax: UInt64
    public var tcpFirstByteEvents: UInt64
    public var tcpFirstByteDurationMsTotal: UInt64
    public var tcpFirstByteDurationMsMax: UInt64
    public var tcp443OpenEvents: UInt64
    public var tcp443OpenDurationMsTotal: UInt64
    public var tcp443OpenDurationMsMax: UInt64
    public var tcp443FirstByteEvents: UInt64
    public var tcp443FirstByteDurationMsTotal: UInt64
    public var tcp443FirstByteDurationMsMax: UInt64
    public var activeTCPFlows: UInt64
    public var activeUDPFlows: UInt64
    public var udpFlowLimit: UInt64
    public var udpBudgetDrops: UInt64
    public var udpEvictedFlows: UInt64
    public var udpChannelDroppedPackets: UInt64
    public var udpRemoteOpenEvents: UInt64
    public var udpRemoteUDP443OpenEvents: UInt64
    public var udpRemoteWrittenBytes: UInt64
    public var udpRemoteReadBytes: UInt64
    public var udpOpenErrors: UInt64
    public var udpVisionUDP443Rejections: UInt64
    public var udpRemoteWriteErrors: UInt64
    public var udpRemoteReadErrors: UInt64
    public var udpRemoteClosedEvents: UInt64
    public var udpQuicBlockedPackets: UInt64
    public var inboundQueueDepth: UInt64
    public var outboundQueueDepth: UInt64
    public var inboundQueueMaxPackets: UInt64
    public var outboundQueueMaxPackets: UInt64
    public var tunFdWriteBatches: UInt64
    public var tunFdWriteBatchPackets: UInt64
    public var tunFdWriteBatchMaxPackets: UInt64

    private enum CodingKeys: String, CodingKey {
        case inboundPackets
        case outboundPackets
        case droppedPackets
        case tcpOpenEvents
        case tcpOpenDurationMsTotal
        case tcpOpenDurationMsMax
        case tcpFirstByteEvents
        case tcpFirstByteDurationMsTotal
        case tcpFirstByteDurationMsMax
        case tcp443OpenEvents
        case tcp443OpenDurationMsTotal
        case tcp443OpenDurationMsMax
        case tcp443FirstByteEvents
        case tcp443FirstByteDurationMsTotal
        case tcp443FirstByteDurationMsMax
        case activeTCPFlows
        case activeUDPFlows
        case udpFlowLimit
        case udpBudgetDrops
        case udpEvictedFlows
        case udpChannelDroppedPackets
        case udpRemoteOpenEvents
        case udpRemoteUDP443OpenEvents
        case udpRemoteWrittenBytes
        case udpRemoteReadBytes
        case udpOpenErrors
        case udpVisionUDP443Rejections
        case udpRemoteWriteErrors
        case udpRemoteReadErrors
        case udpRemoteClosedEvents
        case udpQuicBlockedPackets
        case inboundQueueDepth
        case outboundQueueDepth
        case inboundQueueMaxPackets
        case outboundQueueMaxPackets
        case tunFdWriteBatches
        case tunFdWriteBatchPackets
        case tunFdWriteBatchMaxPackets
    }

    public init(
        inboundPackets: UInt64,
        outboundPackets: UInt64,
        droppedPackets: UInt64,
        tcpOpenEvents: UInt64 = 0,
        tcpOpenDurationMsTotal: UInt64 = 0,
        tcpOpenDurationMsMax: UInt64 = 0,
        tcpFirstByteEvents: UInt64 = 0,
        tcpFirstByteDurationMsTotal: UInt64 = 0,
        tcpFirstByteDurationMsMax: UInt64 = 0,
        tcp443OpenEvents: UInt64 = 0,
        tcp443OpenDurationMsTotal: UInt64 = 0,
        tcp443OpenDurationMsMax: UInt64 = 0,
        tcp443FirstByteEvents: UInt64 = 0,
        tcp443FirstByteDurationMsTotal: UInt64 = 0,
        tcp443FirstByteDurationMsMax: UInt64 = 0,
        activeTCPFlows: UInt64 = 0,
        activeUDPFlows: UInt64 = 0,
        udpFlowLimit: UInt64 = 0,
        udpBudgetDrops: UInt64 = 0,
        udpEvictedFlows: UInt64 = 0,
        udpChannelDroppedPackets: UInt64 = 0,
        udpRemoteOpenEvents: UInt64 = 0,
        udpRemoteUDP443OpenEvents: UInt64 = 0,
        udpRemoteWrittenBytes: UInt64 = 0,
        udpRemoteReadBytes: UInt64 = 0,
        udpOpenErrors: UInt64 = 0,
        udpVisionUDP443Rejections: UInt64 = 0,
        udpRemoteWriteErrors: UInt64 = 0,
        udpRemoteReadErrors: UInt64 = 0,
        udpRemoteClosedEvents: UInt64 = 0,
        udpQuicBlockedPackets: UInt64 = 0,
        inboundQueueDepth: UInt64 = 0,
        outboundQueueDepth: UInt64 = 0,
        inboundQueueMaxPackets: UInt64 = 0,
        outboundQueueMaxPackets: UInt64 = 0,
        tunFdWriteBatches: UInt64 = 0,
        tunFdWriteBatchPackets: UInt64 = 0,
        tunFdWriteBatchMaxPackets: UInt64 = 0
    ) {
        self.inboundPackets = inboundPackets
        self.outboundPackets = outboundPackets
        self.droppedPackets = droppedPackets
        self.tcpOpenEvents = tcpOpenEvents
        self.tcpOpenDurationMsTotal = tcpOpenDurationMsTotal
        self.tcpOpenDurationMsMax = tcpOpenDurationMsMax
        self.tcpFirstByteEvents = tcpFirstByteEvents
        self.tcpFirstByteDurationMsTotal = tcpFirstByteDurationMsTotal
        self.tcpFirstByteDurationMsMax = tcpFirstByteDurationMsMax
        self.tcp443OpenEvents = tcp443OpenEvents
        self.tcp443OpenDurationMsTotal = tcp443OpenDurationMsTotal
        self.tcp443OpenDurationMsMax = tcp443OpenDurationMsMax
        self.tcp443FirstByteEvents = tcp443FirstByteEvents
        self.tcp443FirstByteDurationMsTotal = tcp443FirstByteDurationMsTotal
        self.tcp443FirstByteDurationMsMax = tcp443FirstByteDurationMsMax
        self.activeTCPFlows = activeTCPFlows
        self.activeUDPFlows = activeUDPFlows
        self.udpFlowLimit = udpFlowLimit
        self.udpBudgetDrops = udpBudgetDrops
        self.udpEvictedFlows = udpEvictedFlows
        self.udpChannelDroppedPackets = udpChannelDroppedPackets
        self.udpRemoteOpenEvents = udpRemoteOpenEvents
        self.udpRemoteUDP443OpenEvents = udpRemoteUDP443OpenEvents
        self.udpRemoteWrittenBytes = udpRemoteWrittenBytes
        self.udpRemoteReadBytes = udpRemoteReadBytes
        self.udpOpenErrors = udpOpenErrors
        self.udpVisionUDP443Rejections = udpVisionUDP443Rejections
        self.udpRemoteWriteErrors = udpRemoteWriteErrors
        self.udpRemoteReadErrors = udpRemoteReadErrors
        self.udpRemoteClosedEvents = udpRemoteClosedEvents
        self.udpQuicBlockedPackets = udpQuicBlockedPackets
        self.inboundQueueDepth = inboundQueueDepth
        self.outboundQueueDepth = outboundQueueDepth
        self.inboundQueueMaxPackets = inboundQueueMaxPackets
        self.outboundQueueMaxPackets = outboundQueueMaxPackets
        self.tunFdWriteBatches = tunFdWriteBatches
        self.tunFdWriteBatchPackets = tunFdWriteBatchPackets
        self.tunFdWriteBatchMaxPackets = tunFdWriteBatchMaxPackets
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        inboundPackets = try container.decode(UInt64.self, forKey: .inboundPackets)
        outboundPackets = try container.decode(UInt64.self, forKey: .outboundPackets)
        droppedPackets = try container.decode(UInt64.self, forKey: .droppedPackets)
        tcpOpenEvents = try container.decodeIfPresent(UInt64.self, forKey: .tcpOpenEvents) ?? 0
        tcpOpenDurationMsTotal = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcpOpenDurationMsTotal
        ) ?? 0
        tcpOpenDurationMsMax = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcpOpenDurationMsMax
        ) ?? 0
        tcpFirstByteEvents = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcpFirstByteEvents
        ) ?? 0
        tcpFirstByteDurationMsTotal = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcpFirstByteDurationMsTotal
        ) ?? 0
        tcpFirstByteDurationMsMax = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcpFirstByteDurationMsMax
        ) ?? 0
        tcp443OpenEvents = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcp443OpenEvents
        ) ?? 0
        tcp443OpenDurationMsTotal = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcp443OpenDurationMsTotal
        ) ?? 0
        tcp443OpenDurationMsMax = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcp443OpenDurationMsMax
        ) ?? 0
        tcp443FirstByteEvents = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcp443FirstByteEvents
        ) ?? 0
        tcp443FirstByteDurationMsTotal = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcp443FirstByteDurationMsTotal
        ) ?? 0
        tcp443FirstByteDurationMsMax = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tcp443FirstByteDurationMsMax
        ) ?? 0
        activeTCPFlows = try container.decodeIfPresent(UInt64.self, forKey: .activeTCPFlows) ?? 0
        activeUDPFlows = try container.decodeIfPresent(UInt64.self, forKey: .activeUDPFlows) ?? 0
        udpFlowLimit = try container.decodeIfPresent(UInt64.self, forKey: .udpFlowLimit) ?? 0
        udpBudgetDrops = try container.decodeIfPresent(UInt64.self, forKey: .udpBudgetDrops) ?? 0
        udpEvictedFlows = try container.decodeIfPresent(UInt64.self, forKey: .udpEvictedFlows) ?? 0
        udpChannelDroppedPackets = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpChannelDroppedPackets
        ) ?? 0
        udpRemoteOpenEvents = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpRemoteOpenEvents
        ) ?? 0
        udpRemoteUDP443OpenEvents = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpRemoteUDP443OpenEvents
        ) ?? 0
        udpRemoteWrittenBytes = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpRemoteWrittenBytes
        ) ?? 0
        udpRemoteReadBytes = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpRemoteReadBytes
        ) ?? 0
        udpOpenErrors = try container.decodeIfPresent(UInt64.self, forKey: .udpOpenErrors) ?? 0
        udpVisionUDP443Rejections = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpVisionUDP443Rejections
        ) ?? 0
        udpRemoteWriteErrors = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpRemoteWriteErrors
        ) ?? 0
        udpRemoteReadErrors = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpRemoteReadErrors
        ) ?? 0
        udpRemoteClosedEvents = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpRemoteClosedEvents
        ) ?? 0
        udpQuicBlockedPackets = try container.decodeIfPresent(
            UInt64.self,
            forKey: .udpQuicBlockedPackets
        ) ?? 0
        inboundQueueDepth = try container.decodeIfPresent(
            UInt64.self,
            forKey: .inboundQueueDepth
        ) ?? 0
        outboundQueueDepth = try container.decodeIfPresent(
            UInt64.self,
            forKey: .outboundQueueDepth
        ) ?? 0
        inboundQueueMaxPackets = try container.decodeIfPresent(
            UInt64.self,
            forKey: .inboundQueueMaxPackets
        ) ?? 0
        outboundQueueMaxPackets = try container.decodeIfPresent(
            UInt64.self,
            forKey: .outboundQueueMaxPackets
        ) ?? 0
        tunFdWriteBatches = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tunFdWriteBatches
        ) ?? 0
        tunFdWriteBatchPackets = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tunFdWriteBatchPackets
        ) ?? 0
        tunFdWriteBatchMaxPackets = try container.decodeIfPresent(
            UInt64.self,
            forKey: .tunFdWriteBatchMaxPackets
        ) ?? 0
    }
}
