import Foundation

public struct XrayClientProfile: Codable, Equatable, Identifiable, Sendable {
    public var id: UUID
    public var name: String
    public var providerBundleIdentifier: String
    public var serverAddress: String
    public var configJSON: String

    public init(
        id: UUID = UUID(),
        name: String,
        providerBundleIdentifier: String,
        serverAddress: String,
        configJSON: String
    ) {
        self.id = id
        self.name = name
        self.providerBundleIdentifier = providerBundleIdentifier
        self.serverAddress = serverAddress
        self.configJSON = configJSON
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

    public init(
        inboundPackets: UInt64,
        outboundPackets: UInt64,
        droppedPackets: UInt64
    ) {
        self.inboundPackets = inboundPackets
        self.outboundPackets = outboundPackets
        self.droppedPackets = droppedPackets
    }
}
