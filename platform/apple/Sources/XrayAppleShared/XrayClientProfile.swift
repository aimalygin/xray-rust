import Foundation

public enum XrayTunRuntimeProfileSetting: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case `default` = "default"
    case mobile
    case mobilePlus = "mobile-plus"
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
        case .mobilePlus:
            return "Mobile+"
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
        case "mobile-plus", "mobile_plus", "mobileplus":
            self = .mobilePlus
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

public enum XrayRegionalRoutingMode: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case off
    case bypassSelected = "bypass-selected"
    case proxyOnlySelected = "proxy-only-selected"

    public var id: String {
        rawValue
    }

    public var displayName: String {
        switch self {
        case .off:
            return "Off"
        case .bypassSelected:
            return "Bypass Selected"
        case .proxyOnlySelected:
            return "Proxy Only Selected"
        }
    }
}

public enum XrayRegionalRoutingRegion: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case china
    case russia
    case iran

    public var id: String {
        rawValue
    }

    public var displayName: String {
        switch self {
        case .china:
            return "China"
        case .russia:
            return "Russia"
        case .iran:
            return "Iran"
        }
    }

    var geoipMatcher: String {
        switch self {
        case .china:
            return "geoip:cn"
        case .russia:
            return "geoip:ru"
        case .iran:
            return "geoip:ir"
        }
    }

    var geositeMatcher: String {
        switch self {
        case .china:
            return "geosite:cn"
        case .russia:
            return "geosite:category-ru"
        case .iran:
            return "geosite:category-ir"
        }
    }
}

public enum XrayRealityVisionFlowMode: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case blockUDP443 = "xtls-rprx-vision"
    case allowUDP443 = "xtls-rprx-vision-udp443"

    public var id: String {
        rawValue
    }

    public var displayName: String {
        switch self {
        case .blockUDP443:
            return "Blocked"
        case .allowUDP443:
            return "Allowed"
        }
    }

    public init?(flowValue: String?) {
        let normalizedValue = flowValue?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        switch normalizedValue {
        case "", Self.blockUDP443.rawValue:
            self = .blockUDP443
        case Self.allowUDP443.rawValue:
            self = .allowUDP443
        default:
            return nil
        }
    }
}

public struct XrayRealityFingerprintMode: RawRepresentable,
                                          Codable,
                                          CaseIterable,
                                          Hashable,
                                          Identifiable,
                                          Sendable {
    public static let chrome = Self("chrome")
    public static let firefox = Self("firefox")
    public static let safari = Self("safari")
    public static let ios = Self("ios")
    public static let edge = Self("edge")
    public static let qq = Self("qq")
    public static let random = Self("random")
    public static let randomized = Self("randomized")
    public static let hellofirefox120 = Self("hellofirefox_120")
    public static let hellofirefox148 = Self("hellofirefox_148")
    public static let hellochrome120 = Self("hellochrome_120")
    public static let hellochrome131 = Self("hellochrome_131")
    public static let hellochrome133 = Self("hellochrome_133")
    public static let helloios13 = Self("helloios_13")
    public static let helloios14 = Self("helloios_14")
    public static let helloedge106 = Self("helloedge_106")
    public static let hellosafari263 = Self("hellosafari_26_3")
    public static let hello360110 = Self("hello360_11_0")
    public static let helloqq111 = Self("helloqq_11_1")
    public static let hellorandomized = Self("hellorandomized")
    public static let hellofirefoxAuto = Self("hellofirefox_auto")
    public static let hellofirefox63 = Self("hellofirefox_63")
    public static let hellofirefox65 = Self("hellofirefox_65")
    public static let hellofirefox99 = Self("hellofirefox_99")
    public static let hellofirefox102 = Self("hellofirefox_102")
    public static let hellofirefox105 = Self("hellofirefox_105")
    public static let hellochromeAuto = Self("hellochrome_auto")
    public static let hellochrome70 = Self("hellochrome_70")
    public static let hellochrome72 = Self("hellochrome_72")
    public static let hellochrome83 = Self("hellochrome_83")
    public static let hellochrome87 = Self("hellochrome_87")
    public static let hellochrome96 = Self("hellochrome_96")
    public static let hellochrome100 = Self("hellochrome_100")
    public static let hellochrome102 = Self("hellochrome_102")
    public static let hellochrome106Shuffle = Self("hellochrome_106_shuffle")
    public static let helloiosAuto = Self("helloios_auto")
    public static let helloedge85 = Self("helloedge_85")
    public static let helloedgeAuto = Self("helloedge_auto")
    public static let hellosafari160 = Self("hellosafari_16_0")
    public static let hellosafariAuto = Self("hellosafari_auto")
    public static let helloqqAuto = Self("helloqq_auto")
    public static let hellochrome100Psk = Self("hellochrome_100_psk")
    public static let hellochrome112PskShuf = Self("hellochrome_112_psk_shuf")
    public static let hellochrome114PaddingPskShuf = Self("hellochrome_114_padding_psk_shuf")
    public static let hellochrome115Pq = Self("hellochrome_115_pq")
    public static let hellochrome115PqPsk = Self("hellochrome_115_pq_psk")
    public static let hellochrome120Pq = Self("hellochrome_120_pq")

    public static let allCases: [Self] = [
        .chrome,
        .firefox,
        .safari,
        .ios,
        .edge,
        .qq,
        .random,
        .randomized,
        .hellofirefox120,
        .hellofirefox148,
        .hellochrome120,
        .hellochrome131,
        .hellochrome133,
        .helloios13,
        .helloios14,
        .helloedge106,
        .hellosafari263,
        .hello360110,
        .helloqq111,
        .hellorandomized,
        .hellofirefoxAuto,
        .hellofirefox63,
        .hellofirefox65,
        .hellofirefox99,
        .hellofirefox102,
        .hellofirefox105,
        .hellochromeAuto,
        .hellochrome70,
        .hellochrome72,
        .hellochrome83,
        .hellochrome87,
        .hellochrome96,
        .hellochrome100,
        .hellochrome102,
        .hellochrome106Shuffle,
        .helloiosAuto,
        .helloedge85,
        .helloedgeAuto,
        .hellosafari160,
        .hellosafariAuto,
        .helloqqAuto,
        .hellochrome100Psk,
        .hellochrome112PskShuf,
        .hellochrome114PaddingPskShuf,
        .hellochrome115Pq,
        .hellochrome115PqPsk,
        .hellochrome120Pq,
    ]

    public let rawValue: String

    public var id: String {
        rawValue
    }

    public var displayName: String {
        rawValue
    }

    public init?(rawValue: String) {
        let normalizedValue = rawValue
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
        guard let mode = Self.allCases.first(where: { $0.rawValue == normalizedValue }) else {
            return nil
        }
        self = mode
    }

    public init?(fingerprintValue: String?) {
        let normalizedValue = fingerprintValue?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        self.init(rawValue: normalizedValue.isEmpty ? Self.chrome.rawValue : normalizedValue)
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let rawValue = try container.decode(String.self)
        guard let mode = Self(rawValue: rawValue) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unsupported REALITY fingerprint `\(rawValue)`."
            )
        }
        self = mode
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    private init(_ rawValue: String) {
        self.rawValue = rawValue
    }
}

public enum XrayRealityVisionFlowError: Error, Equatable, LocalizedError {
    case rootIsNotObject
    case outboundsIsNotArray
    case missingRealityVlessUser
    case unsupportedFlow(String)
    case encodingFailed

    public var errorDescription: String? {
        switch self {
        case .rootIsNotObject:
            return "Config must be a JSON object."
        case .outboundsIsNotArray:
            return "Config outbounds must be an array."
        case .missingRealityVlessUser:
            return "Profile does not contain a Reality VLESS outbound."
        case let .unsupportedFlow(flow):
            return "Unsupported Reality Vision flow `\(flow)`."
        case .encodingFailed:
            return "Failed to encode Reality Vision flow config."
        }
    }
}

public enum XrayRealityFingerprintError: Error, Equatable, LocalizedError {
    case rootIsNotObject
    case outboundsIsNotArray
    case missingRealityVlessOutbound
    case unsupportedFingerprint(String)
    case encodingFailed

    public var errorDescription: String? {
        switch self {
        case .rootIsNotObject:
            return "Config must be a JSON object."
        case .outboundsIsNotArray:
            return "Config outbounds must be an array."
        case .missingRealityVlessOutbound:
            return "Profile does not contain a Reality VLESS outbound."
        case let .unsupportedFingerprint(fingerprint):
            return "Unsupported Reality fingerprint `\(fingerprint)`."
        case .encodingFailed:
            return "Failed to encode Reality fingerprint config."
        }
    }
}

public enum XrayRegionalRoutingError: Error, Equatable, LocalizedError {
    case rootIsNotObject
    case outboundsIsNotArray
    case routingIsNotObject
    case rulesIsNotArray
    case encodingFailed
    case missingOutboundTag(String)

    public var errorDescription: String? {
        switch self {
        case .rootIsNotObject:
            return "Config must be a JSON object."
        case .outboundsIsNotArray:
            return "Config outbounds must be an array."
        case .routingIsNotObject:
            return "Config routing must be an object."
        case .rulesIsNotArray:
            return "Config routing rules must be an array."
        case .encodingFailed:
            return "Failed to encode regional routing config."
        case let .missingOutboundTag(tag):
            return "Regional routing requires an outbound tagged `\(tag)`."
        }
    }
}

public struct XrayClientProfile: Codable, Equatable, Identifiable, Sendable {
    public static let defaultRealityVisionFlow = XrayRealityVisionFlowMode.blockUDP443.rawValue
    public static let realityVisionUDP443Flow = XrayRealityVisionFlowMode.allowUDP443.rawValue

    public var id: UUID
    public var name: String
    public var providerBundleIdentifier: String
    public var serverAddress: String
    public var configJSON: String
    public var debugLoggingEnabled: Bool
    public var useTunFileDescriptor: Bool
    public var tunRuntimeProfile: XrayTunRuntimeProfileSetting
    public var regionalRoutingMode: XrayRegionalRoutingMode
    public var regionalRoutingRegions: [XrayRegionalRoutingRegion]

    public init(
        id: UUID = UUID(),
        name: String,
        providerBundleIdentifier: String,
        serverAddress: String,
        configJSON: String,
        debugLoggingEnabled: Bool = false,
        useTunFileDescriptor: Bool = true,
        tunRuntimeProfile: XrayTunRuntimeProfileSetting = .default,
        regionalRoutingMode: XrayRegionalRoutingMode = .off,
        regionalRoutingRegions: [XrayRegionalRoutingRegion] = []
    ) {
        self.id = id
        self.name = name
        self.providerBundleIdentifier = providerBundleIdentifier
        self.serverAddress = serverAddress
        self.configJSON = configJSON
        self.debugLoggingEnabled = debugLoggingEnabled
        self.useTunFileDescriptor = useTunFileDescriptor
        self.tunRuntimeProfile = tunRuntimeProfile
        self.regionalRoutingMode = regionalRoutingMode
        self.regionalRoutingRegions = Self.normalizedRegions(regionalRoutingRegions)
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case name
        case providerBundleIdentifier
        case serverAddress
        case configJSON
        case debugLoggingEnabled
        case useTunFileDescriptor
        case tunRuntimeProfile
        case regionalRoutingMode
        case regionalRoutingRegions
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
        tunRuntimeProfile = try container.decodeIfPresent(
            XrayTunRuntimeProfileSetting.self,
            forKey: .tunRuntimeProfile
        ) ?? .default
        regionalRoutingMode = try container.decodeIfPresent(
            XrayRegionalRoutingMode.self,
            forKey: .regionalRoutingMode
        ) ?? .off
        regionalRoutingRegions = Self.normalizedRegions(
            try container.decodeIfPresent(
                [XrayRegionalRoutingRegion].self,
                forKey: .regionalRoutingRegions
            ) ?? []
        )
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

    public var realityVisionFlowMode: XrayRealityVisionFlowMode? {
        Self.realityVisionFlowMode(in: configJSON)
    }

    public var realityFingerprintMode: XrayRealityFingerprintMode? {
        Self.realityFingerprintMode(in: configJSON)
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

    public func updatingRealityVisionFlowMode(
        _ mode: XrayRealityVisionFlowMode
    ) throws -> XrayClientProfile {
        var profile = self
        profile.configJSON = try Self.configJSON(
            configJSON,
            applyingRealityVisionFlowMode: mode
        )
        return profile
    }

    public func updatingRealityFingerprintMode(
        _ mode: XrayRealityFingerprintMode
    ) throws -> XrayClientProfile {
        var profile = self
        profile.configJSON = try Self.configJSON(
            configJSON,
            applyingRealityFingerprintMode: mode
        )
        return profile
    }

    public func updatingRegionalRouting(
        mode: XrayRegionalRoutingMode,
        regions: [XrayRegionalRoutingRegion]
    ) -> XrayClientProfile {
        var profile = self
        profile.regionalRoutingMode = mode
        profile.regionalRoutingRegions = Self.normalizedRegions(regions)
        return profile
    }

    public func effectiveConfigJSON() throws -> String {
        let regions = Self.normalizedRegions(regionalRoutingRegions)
        guard regionalRoutingMode != .off, !regions.isEmpty else {
            return configJSON
        }

        return try Self.configJSON(
            configJSON,
            applyingRegionalRoutingMode: regionalRoutingMode,
            regions: regions
        )
    }

    private static func realityVisionFlowMode(in configJSON: String) -> XrayRealityVisionFlowMode? {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let outbounds = root["outbounds"] as? [[String: Any]]
        else {
            return nil
        }

        var selectedMode: XrayRealityVisionFlowMode?
        for outbound in outbounds where isRealityVlessOutbound(outbound) {
            guard let settings = outbound["settings"] as? [String: Any],
                  let vnext = settings["vnext"] as? [[String: Any]]
            else {
                continue
            }

            for server in vnext {
                guard let users = server["users"] as? [[String: Any]] else {
                    continue
                }

                for user in users {
                    guard let mode = XrayRealityVisionFlowMode(
                        flowValue: user["flow"] as? String
                    ) else {
                        return nil
                    }
                    if let selectedMode, selectedMode != mode {
                        return nil
                    }
                    selectedMode = mode
                }
            }
        }

        return selectedMode
    }

    private static func realityFingerprintMode(
        in configJSON: String
    ) -> XrayRealityFingerprintMode? {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let outbounds = root["outbounds"] as? [[String: Any]]
        else {
            return nil
        }

        var selectedMode: XrayRealityFingerprintMode?
        for outbound in outbounds where isRealityVlessOutbound(outbound) {
            guard let streamSettings = outbound["streamSettings"] as? [String: Any],
                  let realitySettings = streamSettings["realitySettings"] as? [String: Any]
            else {
                return nil
            }

            let rawFingerprint = realitySettings["fingerprint"]
            let fingerprintValue: String?
            if let rawFingerprint {
                guard let stringValue = rawFingerprint as? String else {
                    return nil
                }
                fingerprintValue = stringValue
            } else {
                fingerprintValue = nil
            }

            guard let mode = XrayRealityFingerprintMode(fingerprintValue: fingerprintValue) else {
                return nil
            }
            if let selectedMode, selectedMode != mode {
                return nil
            }
            selectedMode = mode
        }

        return selectedMode
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
            guard isRealityVlessOutbound(outbounds[outboundIndex]),
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

    private static func configJSON(
        _ configJSON: String,
        applyingRealityVisionFlowMode mode: XrayRealityVisionFlowMode
    ) throws -> String {
        let data = Data(configJSON.utf8)
        guard var root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw XrayRealityVisionFlowError.rootIsNotObject
        }
        guard var outbounds = root["outbounds"] as? [[String: Any]] else {
            throw XrayRealityVisionFlowError.outboundsIsNotArray
        }

        var didFindRealityVlessUser = false
        var didChange = false
        for outboundIndex in outbounds.indices {
            guard isRealityVlessOutbound(outbounds[outboundIndex]),
                  var settings = outbounds[outboundIndex]["settings"] as? [String: Any],
                  var vnext = settings["vnext"] as? [[String: Any]]
            else {
                continue
            }

            var didChangeOutbound = false
            for serverIndex in vnext.indices {
                guard var users = vnext[serverIndex]["users"] as? [[String: Any]] else {
                    continue
                }

                for userIndex in users.indices {
                    didFindRealityVlessUser = true
                    let rawFlow = users[userIndex]["flow"]
                    let flowValue = rawFlow as? String
                    if let rawFlow, flowValue == nil {
                        throw XrayRealityVisionFlowError.unsupportedFlow(String(describing: rawFlow))
                    }
                    guard XrayRealityVisionFlowMode(flowValue: flowValue) != nil else {
                        throw XrayRealityVisionFlowError.unsupportedFlow(flowValue ?? "")
                    }
                    guard flowValue != mode.rawValue else {
                        continue
                    }

                    users[userIndex]["flow"] = mode.rawValue
                    didChange = true
                    didChangeOutbound = true
                }

                vnext[serverIndex]["users"] = users
            }

            guard didChangeOutbound else {
                continue
            }
            settings["vnext"] = vnext
            outbounds[outboundIndex]["settings"] = settings
        }

        guard didFindRealityVlessUser else {
            throw XrayRealityVisionFlowError.missingRealityVlessUser
        }
        guard didChange else {
            return configJSON
        }

        root["outbounds"] = outbounds
        let encoded = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        guard let json = String(data: encoded, encoding: .utf8) else {
            throw XrayRealityVisionFlowError.encodingFailed
        }
        return json
    }

    private static func configJSON(
        _ configJSON: String,
        applyingRealityFingerprintMode mode: XrayRealityFingerprintMode
    ) throws -> String {
        let data = Data(configJSON.utf8)
        guard var root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw XrayRealityFingerprintError.rootIsNotObject
        }
        guard var outbounds = root["outbounds"] as? [[String: Any]] else {
            throw XrayRealityFingerprintError.outboundsIsNotArray
        }

        var didFindRealityVlessOutbound = false
        var didChange = false
        for outboundIndex in outbounds.indices {
            guard isRealityVlessOutbound(outbounds[outboundIndex]),
                  var streamSettings = outbounds[outboundIndex]["streamSettings"] as? [String: Any],
                  var realitySettings = streamSettings["realitySettings"] as? [String: Any]
            else {
                continue
            }

            didFindRealityVlessOutbound = true
            let rawFingerprint = realitySettings["fingerprint"]
            let fingerprintValue = rawFingerprint as? String
            if let rawFingerprint, fingerprintValue == nil {
                throw XrayRealityFingerprintError.unsupportedFingerprint(
                    String(describing: rawFingerprint)
                )
            }
            guard XrayRealityFingerprintMode(fingerprintValue: fingerprintValue) != nil else {
                throw XrayRealityFingerprintError.unsupportedFingerprint(fingerprintValue ?? "")
            }
            guard fingerprintValue != mode.rawValue else {
                continue
            }

            realitySettings["fingerprint"] = mode.rawValue
            streamSettings["realitySettings"] = realitySettings
            outbounds[outboundIndex]["streamSettings"] = streamSettings
            didChange = true
        }

        guard didFindRealityVlessOutbound else {
            throw XrayRealityFingerprintError.missingRealityVlessOutbound
        }
        guard didChange else {
            return configJSON
        }

        root["outbounds"] = outbounds
        let encoded = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        guard let json = String(data: encoded, encoding: .utf8) else {
            throw XrayRealityFingerprintError.encodingFailed
        }
        return json
    }

    private static func configJSON(
        _ configJSON: String,
        applyingRegionalRoutingMode mode: XrayRegionalRoutingMode,
        regions: [XrayRegionalRoutingRegion]
    ) throws -> String {
        let data = Data(configJSON.utf8)
        guard var root = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw XrayRegionalRoutingError.rootIsNotObject
        }

        let outboundTags = try outboundTags(in: root)
        let selectedOutboundTag: String
        switch mode {
        case .off:
            return configJSON
        case .bypassSelected:
            selectedOutboundTag = "direct"
        case .proxyOnlySelected:
            selectedOutboundTag = "proxy"
        }

        guard outboundTags.contains(selectedOutboundTag) else {
            throw XrayRegionalRoutingError.missingOutboundTag(selectedOutboundTag)
        }
        if mode == .proxyOnlySelected, !outboundTags.contains("direct") {
            throw XrayRegionalRoutingError.missingOutboundTag("direct")
        }

        var routing = try routingObject(in: root)
        var rules = try routingRules(in: routing)
        rules.insert(
            contentsOf: regionalRules(
                regions: regions,
                outboundTag: selectedOutboundTag
            ),
            at: 0
        )
        if mode == .proxyOnlySelected {
            rules.append([
                "type": "field",
                "outboundTag": "direct",
            ])
        }

        if routing["domainStrategy"] == nil {
            routing["domainStrategy"] = "AsIs"
        }
        routing["rules"] = rules
        root["routing"] = routing

        let encoded = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        guard let json = String(data: encoded, encoding: .utf8) else {
            throw XrayRegionalRoutingError.encodingFailed
        }
        return json
    }

    private static func outboundTags(in root: [String: Any]) throws -> Set<String> {
        guard let outbounds = root["outbounds"] as? [[String: Any]] else {
            throw XrayRegionalRoutingError.outboundsIsNotArray
        }

        return Set(outbounds.compactMap { $0["tag"] as? String })
    }

    private static func routingObject(in root: [String: Any]) throws -> [String: Any] {
        guard let routing = root["routing"] else {
            return [:]
        }
        guard let routing = routing as? [String: Any] else {
            throw XrayRegionalRoutingError.routingIsNotObject
        }
        return routing
    }

    private static func routingRules(in routing: [String: Any]) throws -> [[String: Any]] {
        guard let rawRules = routing["rules"] else {
            return []
        }
        guard let rules = rawRules as? [[String: Any]] else {
            throw XrayRegionalRoutingError.rulesIsNotArray
        }
        return rules
    }

    private static func isRealityVlessOutbound(_ outbound: [String: Any]) -> Bool {
        guard outbound["protocol"] as? String == "vless",
              let streamSettings = outbound["streamSettings"] as? [String: Any],
              streamSettings["security"] as? String == "reality"
        else {
            return false
        }
        return true
    }

    private static func regionalRules(
        regions: [XrayRegionalRoutingRegion],
        outboundTag: String
    ) -> [[String: Any]] {
        [
            [
                "type": "field",
                "domain": regions.map(\.geositeMatcher),
                "outboundTag": outboundTag,
            ],
            [
                "type": "field",
                "ip": regions.map(\.geoipMatcher),
                "outboundTag": outboundTag,
            ],
        ]
    }

    private static func normalizedRegions(
        _ regions: [XrayRegionalRoutingRegion]
    ) -> [XrayRegionalRoutingRegion] {
        let selected = Set(regions)
        return XrayRegionalRoutingRegion.allCases.filter { selected.contains($0) }
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
