import Foundation

public enum XrayVlessURLImportError: Error, Equatable, LocalizedError {
    case invalidURL
    case unsupportedScheme(String?)
    case missingUserID
    case invalidUserID(String)
    case missingHost
    case missingPort
    case missingQueryValue(String)
    case unsupportedQueryValue(name: String, value: String, expected: String)
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
        case let .unsupportedQueryValue(name, value, expected):
            return "Unsupported VLESS \(name) `\(value)`. Expected `\(expected)`."
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
    var userID: String
    var host: String
    var port: Int
    var network: String
    var encryption: String
    var security: String
    var publicKey: String
    var fingerprint: String
    var serverName: String
    var shortID: String
    var spiderX: String
    var flow: String?
    var profileName: String

    init(rawURL: String) throws {
        let trimmedURL = rawURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmedURL) else {
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
        let network = query.optional("type", default: "tcp")
        try Self.require(network, named: "type", toEqual: "tcp")

        let encryption = query.optional("encryption", default: "none")
        try Self.require(encryption, named: "encryption", toEqual: "none")

        let security = query.optional("security", default: "none")
        try Self.require(security, named: "security", toEqual: "reality")

        let flow = query.optional("flow", default: "")
        if !flow.isEmpty {
            try Self.require(flow, named: "flow", toEqual: "xtls-rprx-vision")
        }

        self.userID = userID
        self.host = host
        self.port = port
        self.network = network
        self.encryption = encryption
        self.security = security
        self.publicKey = try query.required("pbk")
        self.fingerprint = try query.required("fp")
        self.serverName = try query.required("sni")
        self.shortID = try query.required("sid")
        self.spiderX = query.optional("spx", default: "")
        self.flow = flow.isEmpty ? nil : flow
        self.profileName = components.fragment?.isEmpty == false
            ? components.fragment!
            : "\(host):\(port)"
    }

    func mobileConfigJSON() throws -> String {
        var user: [String: Any] = [
            "id": userID,
            "encryption": encryption,
        ]
        if let flow {
            user["flow"] = flow
        }

        let root: [String: Any] = [
            "inbounds": [
                [
                    "tag": "tun-in",
                    "protocol": "tun",
                    "listen": "127.0.0.1",
                    "port": 0,
                    "settings": [:],
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
                    "streamSettings": [
                        "network": network,
                        "security": security,
                        "realitySettings": [
                            "serverName": serverName,
                            "fingerprint": fingerprint,
                            "publicKey": publicKey,
                            "shortId": shortID,
                            "spiderX": spiderX,
                        ],
                    ],
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
                    [
                        "type": "field",
                        "domain": ["full:captive.apple.com"],
                        "outboundTag": "direct",
                    ],
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
}

private struct QueryValues {
    private var values: [String: String]

    init(items: [URLQueryItem]) {
        values = items.reduce(into: [:]) { result, item in
            result[item.name.lowercased()] = item.value ?? ""
        }
    }

    func required(_ name: String) throws -> String {
        let key = name.lowercased()
        guard let value = values[key], !value.isEmpty else {
            throw XrayVlessURLImportError.missingQueryValue(name)
        }
        return value
    }

    func optional(_ name: String, default defaultValue: String) -> String {
        values[name.lowercased()] ?? defaultValue
    }
}
