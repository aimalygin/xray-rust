import Foundation

public enum XrayVlessURLImportError: Error, Equatable, LocalizedError {
    case invalidURL
    case unsupportedScheme(String?)
    case missingUserID
    case invalidUserID(String)
    case missingHost
    case missingPort
    case missingQueryValue(String)
    case duplicateQueryValue(String)
    case unsupportedQueryParameter(String)
    case unsupportedQueryValue(name: String, value: String, expected: String)
    case invalidXHTTPExtra
    case xhttpExtraTooLarge
    case configEncodingFailed

    public var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid VLESS URL."
        case let .unsupportedScheme(scheme):
            return "Unsupported URL scheme `\(scheme ?? "none")`. Expected `vless`."
        case .missingUserID:
            return "VLESS URL is missing a user id."
        case let .invalidUserID(userID):
            return "Invalid VLESS user id `\(userID)`."
        case .missingHost:
            return "VLESS URL is missing a host."
        case .missingPort:
            return "VLESS URL is missing a port."
        case let .missingQueryValue(name):
            return "VLESS URL is missing `\(name)`."
        case let .duplicateQueryValue(name):
            return "VLESS URL contains duplicate `\(name)` values."
        case let .unsupportedQueryParameter(name):
            return "VLESS URL contains unsupported `\(name)`."
        case let .unsupportedQueryValue(name, value, expected):
            return "Unsupported VLESS \(name) `\(value)`. Expected `\(expected)`."
        case .invalidXHTTPExtra:
            return "Invalid VLESS XHTTP `extra`. Expected a JSON object."
        case .xhttpExtraTooLarge:
            return "VLESS XHTTP `extra` is too large."
        case .configEncodingFailed:
            return "Failed to encode imported VLESS config."
        }
    }
}

public enum XrayVlessURLImporter {
    public static func profile(
        from rawURL: String,
        providerBundleIdentifier: String? = nil,
        hostBundleIdentifier: String? = Bundle.main.bundleIdentifier
    ) throws -> XrayClientProfile {
        let endpoint = try VlessEndpoint(rawURL: rawURL)
        return XrayClientProfile(
            name: endpoint.profileName,
            providerBundleIdentifier: providerBundleIdentifier
                ?? XrayClientProfile.defaultProviderBundleIdentifier(
                    hostBundleIdentifier: hostBundleIdentifier
                ),
            serverAddress: endpoint.host,
            configJSON: try endpoint.mobileConfigJSON()
        )
    }
}

private struct VlessEndpoint {
    private static let visionFlow = XrayClientProfile.defaultRealityVisionFlow
    private static let visionUdp443Flow = XrayClientProfile.realityVisionUDP443Flow
    private static let maximumXHTTPExtraBytes = 64 * 1024
    /// Xray renamed the `tcp` transport to `raw`; share links carry either name.
    private static let canonicalNetwork = "tcp"
    private static let networkAliases = [canonicalNetwork, "raw"]
    private static let xhttpNetworkAliases = ["xhttp", "splithttp"]

    private struct RealityParameters {
        var publicKey: String
        var fingerprint: String
        var serverName: String
        var shortID: String
        var spiderX: String
        var mldsa65Verify: String?
        var flow: String?
    }

    private struct TLSParameters {
        var serverName: String
        var fingerprint: String
        var alpn: [String]?
        var allowInsecure: Bool?
    }

    private enum XHTTPSecurity {
        case none
        case tls(TLSParameters)
        case reality(RealityParameters)
    }

    private struct XHTTPParameters {
        var host: String
        var path: String
        var mode: String
        var extra: [String: Any]?
        var security: XHTTPSecurity
    }

    private enum Transport {
        case rawReality(RealityParameters)
        case xhttp(XHTTPParameters)
    }

    var userID: String
    var host: String
    var port: Int
    var encryption: String
    private var transport: Transport
    var profileName: String

    init(rawURL: String) throws {
        let normalizedURL = Self.normalizedVlessURL(from: rawURL)
        guard let components = URLComponents(string: normalizedURL) else {
            throw XrayVlessURLImportError.invalidURL
        }

        let scheme = components.scheme?.lowercased()
        guard scheme == "vless" else {
            throw XrayVlessURLImportError.unsupportedScheme(components.scheme)
        }

        guard let userID = components.user, !userID.isEmpty else {
            throw XrayVlessURLImportError.missingUserID
        }
        guard UUID(uuidString: userID) != nil else {
            throw XrayVlessURLImportError.invalidUserID(userID)
        }

        guard let host = components.host, !host.isEmpty else {
            throw XrayVlessURLImportError.missingHost
        }
        guard let port = components.port else {
            throw XrayVlessURLImportError.missingPort
        }

        let query = QueryValues(items: components.queryItems ?? [])
        try query.rejectDuplicates([
            "type", "encryption", "security", "flow", "host", "path", "mode",
            "sni", "fp", "alpn", "allowInsecure", "pbk", "sid", "spx", "pqv",
            "extra", "pcs", "vcn", "ech", "echQuery",
        ])
        let network = query.optional("type", default: Self.canonicalNetwork)

        let encryption = query.optional("encryption", default: "none")
        try Self.require(encryption, named: "encryption", toEqual: "none")

        let security = query.optional("security", default: "none")
        let flow = query.optional("flow", default: "")

        let transport: Transport
        if Self.networkAliases.contains(network) {
            try Self.require(security, named: "security", toEqual: "reality")
            if !flow.isEmpty {
                try Self.require(
                    flow,
                    named: "flow",
                    toEqualOneOf: [Self.visionFlow, Self.visionUdp443Flow]
                )
            }
            transport = .rawReality(
                try Self.rawRealityParameters(
                    from: query,
                    flow: flow.isEmpty ? nil : flow
                )
            )
        } else if Self.xhttpNetworkAliases.contains(network) {
            guard flow.isEmpty else {
                throw XrayVlessURLImportError.unsupportedQueryValue(
                    name: "flow",
                    value: flow,
                    expected: "empty"
                )
            }
            let rawMode = query.optional("mode", default: "auto")
            let mode = rawMode.isEmpty ? "auto" : rawMode
            try Self.require(
                mode,
                named: "mode",
                toEqualOneOf: ["auto", "packet-up", "stream-up", "stream-one"]
            )
            let extra = try query.value("extra").map(Self.decodeXHTTPExtra)
            try Self.rejectUnsupportedSecurityQueryValues(in: query)
            let xhttpSecurity: XHTTPSecurity
            switch security {
            case "none":
                xhttpSecurity = .none
            case "tls":
                try Self.rejectRealityOnlyQueryValues(in: query)
                xhttpSecurity = .tls(
                    try Self.tlsParameters(from: query, defaultServerName: host)
                )
            case "reality":
                try Self.validateRealityCompatibilityQueryValues(in: query)
                xhttpSecurity = .reality(
                    try Self.xhttpRealityParameters(
                        from: query,
                        defaultServerName: host
                    )
                )
            default:
                throw XrayVlessURLImportError.unsupportedQueryValue(
                    name: "security",
                    value: security,
                    expected: "none or tls or reality"
                )
            }
            transport = .xhttp(
                XHTTPParameters(
                    host: query.optional("host", default: ""),
                    path: query.optional("path", default: ""),
                    mode: mode,
                    extra: extra,
                    security: xhttpSecurity
                )
            )
        } else {
            throw XrayVlessURLImportError.unsupportedQueryValue(
                name: "type",
                value: network,
                expected: (Self.networkAliases + Self.xhttpNetworkAliases)
                    .joined(separator: " or ")
            )
        }

        self.userID = userID
        self.host = host
        self.port = port
        self.encryption = encryption
        self.transport = transport
        self.profileName = components.fragment?.isEmpty == false
            ? components.fragment!
            : "\(host):\(port)"
    }

    func mobileConfigJSON() throws -> String {
        var user: [String: Any] = [
            "id": userID,
            "encryption": encryption,
        ]
        let streamSettings: [String: Any]
        switch transport {
        case let .rawReality(reality):
            if let flow = reality.flow {
                user["flow"] = flow
            }
            streamSettings = [
                "network": Self.canonicalNetwork,
                "security": "reality",
                "realitySettings": Self.realitySettings(from: reality),
            ]
        case let .xhttp(xhttp):
            var xhttpSettings: [String: Any] = [
                "host": xhttp.host,
                "path": xhttp.path,
                "mode": xhttp.mode,
            ]
            if let extra = xhttp.extra {
                xhttpSettings["extra"] = extra
            }
            var xhttpStreamSettings: [String: Any] = [
                "network": "xhttp",
                "xhttpSettings": xhttpSettings,
            ]
            switch xhttp.security {
            case .none:
                xhttpStreamSettings["security"] = "none"
            case let .tls(tls):
                var tlsSettings: [String: Any] = [
                    "serverName": tls.serverName,
                    "fingerprint": tls.fingerprint,
                ]
                if let alpn = tls.alpn {
                    tlsSettings["alpn"] = alpn
                }
                if let allowInsecure = tls.allowInsecure {
                    tlsSettings["allowInsecure"] = allowInsecure
                }
                xhttpStreamSettings["security"] = "tls"
                xhttpStreamSettings["tlsSettings"] = tlsSettings
            case let .reality(reality):
                xhttpStreamSettings["security"] = "reality"
                xhttpStreamSettings["realitySettings"] = Self.realitySettings(from: reality)
            }
            streamSettings = xhttpStreamSettings
        }

        let root: [String: Any] = [
            "inbounds": [
                [
                    "tag": "tun-in",
                    "protocol": "tun",
                    "listen": "127.0.0.1",
                    "port": 0,
                    "settings": [:],
                    // Sniffing is the only way a flow recovers its domain when
                    // the fake-IP mapping is missing — after a tunnel restart the
                    // table is empty while clients still hold cached fake IPs.
                    "sniffing": [
                        "enabled": true,
                        "destOverride": ["http", "tls", "quic"],
                        "metadataOnly": false,
                    ],
                ],
            ],
            "outbounds": [
                [
                    "tag": "proxy",
                    "protocol": "vless",
                    "settings": [
                        "vnext": [
                            [
                                "address": host,
                                "port": port,
                                "users": [user],
                            ],
                        ],
                    ],
                    "streamSettings": streamSettings,
                ],
                [
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": [:],
                ],
            ],
            "routing": [
                "domainStrategy": "AsIs",
                "rules": [
                    [
                        "type": "field",
                        "ip": ["geoip:private", "127.0.0.0/8", "fd00::/8"],
                        "outboundTag": "direct",
                    ],
                ],
            ],
            "dns": [
                "queryStrategy": "UseIPv4",
                "fakeIp": [
                    "enabled": true,
                    "ipv4Pool": "198.19.0.0/16",
                    "poolSize": 32768,
                    "ttl": 60,
                ],
            ],
        ]

        let data = try JSONSerialization.data(
            withJSONObject: root,
            options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        )
        guard let json = String(data: data, encoding: .utf8) else {
            throw XrayVlessURLImportError.configEncodingFailed
        }
        return json
    }

    private static func require(
        _ value: String,
        named name: String,
        toEqual expected: String
    ) throws {
        guard value == expected else {
            throw XrayVlessURLImportError.unsupportedQueryValue(
                name: name,
                value: value,
                expected: expected
            )
        }
    }

    private static func tlsParameters(
        from query: QueryValues,
        defaultServerName: String
    ) throws -> TLSParameters {
        let serverName: String
        if let rawServerName = query.value("sni") {
            try requireNonEmpty(rawServerName, named: "sni")
            serverName = rawServerName
        } else {
            serverName = defaultServerName
        }

        let fingerprint: String
        if let rawFingerprint = query.value("fp") {
            try requireNonEmpty(rawFingerprint, named: "fp")
            fingerprint = rawFingerprint
        } else {
            fingerprint = "chrome"
        }
        let alpn: [String]?
        if let rawALPN = query.value("alpn") {
            let values = rawALPN.split(separator: ",", omittingEmptySubsequences: false)
                .map(String.init)
            guard !rawALPN.isEmpty,
                  !rawALPN.contains(where: \.isWhitespace),
                  values.allSatisfy({ !$0.isEmpty })
            else {
                throw XrayVlessURLImportError.unsupportedQueryValue(
                    name: "alpn",
                    value: rawALPN,
                    expected: "comma-separated values without spaces or empty entries"
                )
            }
            alpn = values
        } else {
            alpn = nil
        }

        let allowInsecure: Bool?
        if let rawAllowInsecure = query.value("allowInsecure") {
            switch rawAllowInsecure.lowercased() {
            case "1", "true":
                allowInsecure = true
            case "0", "false":
                allowInsecure = false
            default:
                throw XrayVlessURLImportError.unsupportedQueryValue(
                    name: "allowInsecure",
                    value: rawAllowInsecure,
                    expected: "0 or 1 or false or true"
                )
            }
        } else {
            allowInsecure = nil
        }

        return TLSParameters(
            serverName: serverName,
            fingerprint: fingerprint,
            alpn: alpn,
            allowInsecure: allowInsecure
        )
    }

    private static func rawRealityParameters(
        from query: QueryValues,
        flow: String?
    ) throws -> RealityParameters {
        let mldsa65Verify = query.optional("pqv", default: "")
        return RealityParameters(
            publicKey: try query.required("pbk"),
            fingerprint: try query.required("fp"),
            serverName: try query.required("sni"),
            shortID: try query.required("sid"),
            spiderX: query.optional("spx", default: ""),
            mldsa65Verify: mldsa65Verify.isEmpty ? nil : mldsa65Verify,
            flow: flow
        )
    }

    private static func xhttpRealityParameters(
        from query: QueryValues,
        defaultServerName: String
    ) throws -> RealityParameters {
        let serverName: String
        if let rawServerName = query.value("sni") {
            try requireNonEmpty(rawServerName, named: "sni")
            serverName = rawServerName
        } else {
            serverName = defaultServerName
        }
        guard let fingerprint = query.value("fp") else {
            throw XrayVlessURLImportError.missingQueryValue("fp")
        }
        try requireNonEmpty(fingerprint, named: "fp")
        let mldsa65Verify = query.optional("pqv", default: "")
        return RealityParameters(
            publicKey: try query.required("pbk"),
            fingerprint: fingerprint,
            serverName: serverName,
            shortID: try query.requiredPresent("sid"),
            spiderX: query.optional("spx", default: ""),
            mldsa65Verify: mldsa65Verify.isEmpty ? nil : mldsa65Verify,
            flow: nil
        )
    }

    private static func requireNonEmpty(_ value: String, named name: String) throws {
        guard !value.isEmpty else {
            throw XrayVlessURLImportError.unsupportedQueryValue(
                name: name,
                value: value,
                expected: "non-empty"
            )
        }
    }

    private static func realitySettings(from reality: RealityParameters) -> [String: Any] {
        var settings: [String: Any] = [
            "serverName": reality.serverName,
            "fingerprint": reality.fingerprint,
            "publicKey": reality.publicKey,
            "shortId": reality.shortID,
            "spiderX": reality.spiderX,
        ]
        if let mldsa65Verify = reality.mldsa65Verify {
            settings["mldsa65Verify"] = mldsa65Verify
        }
        return settings
    }

    private static func rejectUnsupportedSecurityQueryValues(
        in query: QueryValues
    ) throws {
        for name in ["pcs", "vcn", "ech", "echQuery"] {
            guard query.value(name)?.isEmpty == false else {
                continue
            }
            throw XrayVlessURLImportError.unsupportedQueryParameter(name)
        }
    }

    private static func rejectRealityOnlyQueryValues(in query: QueryValues) throws {
        for name in ["pbk", "sid", "spx", "pqv"] {
            guard query.value(name) != nil else {
                continue
            }
            throw XrayVlessURLImportError.unsupportedQueryParameter(name)
        }
    }

    private static func validateRealityCompatibilityQueryValues(
        in query: QueryValues
    ) throws {
        if let alpn = query.value("alpn"), alpn != "h2" {
            throw XrayVlessURLImportError.unsupportedQueryValue(
                name: "alpn",
                value: alpn,
                expected: "h2 or absent for Reality"
            )
        }
        if query.value("allowInsecure") != nil {
            throw XrayVlessURLImportError.unsupportedQueryParameter("allowInsecure")
        }
    }

    private static func decodeXHTTPExtra(_ rawValue: String) throws -> [String: Any] {
        guard !rawValue.isEmpty else {
            throw XrayVlessURLImportError.invalidXHTTPExtra
        }
        guard rawValue.utf8.count <= maximumXHTTPExtraBytes else {
            throw XrayVlessURLImportError.xhttpExtraTooLarge
        }

        if let object = xhttpJSONObject(rawValue) {
            return object
        }
        guard let decoded = rawValue.removingPercentEncoding else {
            throw XrayVlessURLImportError.invalidXHTTPExtra
        }
        guard decoded.utf8.count <= maximumXHTTPExtraBytes else {
            throw XrayVlessURLImportError.xhttpExtraTooLarge
        }
        guard decoded != rawValue, let object = xhttpJSONObject(decoded) else {
            throw XrayVlessURLImportError.invalidXHTTPExtra
        }
        return object
    }

    private static func xhttpJSONObject(_ rawValue: String) -> [String: Any]? {
        guard let data = rawValue.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data),
              let dictionary = object as? [String: Any]
        else {
            return nil
        }
        return dictionary
    }

    private static func require(
        _ value: String,
        named name: String,
        toEqualOneOf expectedValues: [String]
    ) throws {
        guard expectedValues.contains(value) else {
            throw XrayVlessURLImportError.unsupportedQueryValue(
                name: name,
                value: value,
                expected: expectedValues.joined(separator: " or ")
            )
        }
    }

    private static func normalizedVlessURL(from rawURL: String) -> String {
        let trimmedURL = rawURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedURL.isEmpty else {
            return trimmedURL
        }

        if let schemeRange = trimmedURL.range(of: "vless://", options: .caseInsensitive) {
            return Self.firstToken(in: String(trimmedURL[schemeRange.lowerBound...]))
        }

        if let authorityRange = trimmedURL.range(
            of: #"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@"#,
            options: .regularExpression
        ) {
            return "vless://\(Self.firstToken(in: String(trimmedURL[authorityRange.lowerBound...])))"
        }

        return trimmedURL
    }

    private static func firstToken(in text: String) -> String {
        let token = text.split(whereSeparator: { $0.isWhitespace }).first.map(String.init) ?? text
        return token.trimmingCharacters(in: CharacterSet(charactersIn: "\"',;"))
    }
}

private struct QueryValues {
    private var values: [String: String]
    private var duplicateNames: Set<String>

    init(items: [URLQueryItem]) {
        var collectedValues: [String: String] = [:]
        var collectedDuplicates = Set<String>()
        for item in items {
            let name = item.name.lowercased()
            if collectedValues[name] != nil {
                collectedDuplicates.insert(name)
            }
            collectedValues[name] = item.value ?? ""
        }
        values = collectedValues
        duplicateNames = collectedDuplicates
    }

    func required(_ name: String) throws -> String {
        let key = name.lowercased()
        guard let value = values[key], !value.isEmpty else {
            throw XrayVlessURLImportError.missingQueryValue(name)
        }
        return value
    }

    func requiredPresent(_ name: String) throws -> String {
        let key = name.lowercased()
        guard let value = values[key] else {
            throw XrayVlessURLImportError.missingQueryValue(name)
        }
        return value
    }

    func optional(_ name: String, default defaultValue: String) -> String {
        values[name.lowercased()] ?? defaultValue
    }

    func value(_ name: String) -> String? {
        values[name.lowercased()]
    }

    func rejectDuplicates(_ names: [String]) throws {
        if let name = names.first(where: { duplicateNames.contains($0.lowercased()) }) {
            throw XrayVlessURLImportError.duplicateQueryValue(name)
        }
    }
}
