import CoreFoundation
import Darwin
import Foundation

/// The source used by the packet tunnel for the system-wide DNS destination.
///
/// A custom destination is already syntax-checked by the packet-tunnel option
/// parser. The preflight only needs to know whether such a destination exists.
public enum XrayMobileExplicitDNSConfiguration: Equatable, Sendable {
    case system
    case custom
    case invalid
}

public enum XrayMobileDNSPreflightError: Error, Equatable, LocalizedError, Sendable {
    case unavailable
    case unsafeFakeIPFreedomRouting

    public var errorDescription: String? {
        switch self {
        case .unavailable:
            return "DNS requires enabled dns.fakeIp, at least one dns.servers upstream, or explicit IP servers; fake-IP cannot be combined with explicit servers."
        case .unsafeFakeIPFreedomRouting:
            return "Fake-IP without dns.servers cannot use Freedom as the default or from a TUN domain-capable routing rule."
        }
    }
}

/// Validates the mobile full-tunnel DNS invariants shared by the host app and
/// packet-tunnel provider.
///
/// Callers must run the core config validator first. This preflight is about
/// the full-tunnel topology rather than the complete Xray JSON schema.
public enum XrayMobileDNSPreflight {
    public static func validate(
        _ configJSON: String,
        explicitDNS: XrayMobileExplicitDNSConfiguration = .system
    ) throws {
        let root = jsonRoot(configJSON)
        let dns = root?["dns"] as? [String: Any]
        let fakeIPIsEnabled = fakeIPIsEnabled(dns)
        let fakeIPIsAvailable = fakeIPIsAvailable(dns)
        let hasConfiguredServers = !(dns?["servers"] as? [Any] ?? []).isEmpty

        // Match the provider's fail-closed behavior: an explicitly enabled
        // but unusable FakeIP block is an error even if dns.servers exists.
        guard !fakeIPIsEnabled || fakeIPIsAvailable else {
            throw XrayMobileDNSPreflightError.unavailable
        }

        switch explicitDNS {
        case .invalid:
            throw XrayMobileDNSPreflightError.unavailable
        case .custom:
            guard !fakeIPIsEnabled else {
                throw XrayMobileDNSPreflightError.unavailable
            }
        case .system:
            guard fakeIPIsAvailable || hasConfiguredServers else {
                throw XrayMobileDNSPreflightError.unavailable
            }
        }

        guard fakeIPIsEnabled, !hasConfiguredServers else {
            return
        }
        try validateFakeIPRoutingTopology(root)
    }

    private static func validateFakeIPRoutingTopology(_ root: [String: Any]?) throws {
        guard let root else {
            return
        }
        let outbounds = root["outbounds"] as? [[String: Any]] ?? []
        if let defaultOutbound = outbounds.first,
           (defaultOutbound["protocol"] as? String)?.lowercased() == "freedom"
        {
            throw XrayMobileDNSPreflightError.unsafeFakeIPFreedomRouting
        }

        let freedomTags = Set(outbounds.compactMap { outbound -> String? in
            guard (outbound["protocol"] as? String)?.lowercased() == "freedom" else {
                return nil
            }
            return outbound["tag"] as? String
        })
        guard !freedomTags.isEmpty else {
            return
        }

        let inbounds = root["inbounds"] as? [[String: Any]] ?? []
        let tunInbounds = inbounds.filter {
            ($0["protocol"] as? String)?.lowercased() == "tun"
        }
        guard !tunInbounds.isEmpty else {
            return
        }
        let tunInboundTags = Set(tunInbounds.compactMap { $0["tag"] as? String })
        let routing = root["routing"] as? [String: Any]
        let rules = routing?["rules"] as? [[String: Any]] ?? []
        for rule in rules {
            guard let outboundTag = rule["outboundTag"] as? String,
                  freedomTags.contains(outboundTag),
                  routingRuleAppliesToTun(rule, tunInboundTags: tunInboundTags)
            else {
                continue
            }

            let domains = (rule["domain"] as? [Any] ?? [])
                + (rule["domains"] as? [Any] ?? [])
            let ips = rule["ip"] as? [Any] ?? []
            let isIPOnly = domains.isEmpty && !ips.isEmpty
            if !isIPOnly {
                throw XrayMobileDNSPreflightError.unsafeFakeIPFreedomRouting
            }
        }
    }

    private static func routingRuleAppliesToTun(
        _ rule: [String: Any],
        tunInboundTags: Set<String>
    ) -> Bool {
        let inboundTags = rule["inboundTag"] as? [String] ?? []
        return inboundTags.isEmpty || !tunInboundTags.isDisjoint(with: inboundTags)
    }

    private static func jsonRoot(_ configJSON: String) -> [String: Any]? {
        guard let data = configJSON.data(using: .utf8) else {
            return nil
        }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private static func fakeIPIsEnabled(_ dns: [String: Any]?) -> Bool {
        guard let fakeIP = dns?["fakeIp"] as? [String: Any],
              let number = fakeIP["enabled"] as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else {
            return false
        }
        return number.boolValue
    }

    private static func fakeIPIsAvailable(_ dns: [String: Any]?) -> Bool {
        guard let dns,
              let fakeIP = dns["fakeIp"] as? [String: Any],
              Set(fakeIP.keys).isSubset(of: ["enabled", "ipv4Pool", "poolSize", "ttl"]),
              fakeIPIsEnabled(dns),
              let ipv4Pool = fakeIP["ipv4Pool"] as? String
        else {
            return false
        }
        if let ttl = fakeIP["ttl"], !isJSONUInt32(ttl) {
            return false
        }
        if let poolSize = fakeIP["poolSize"],
           !isJSONUInt32(poolSize) || (poolSize as? NSNumber)?.uint64Value == 0
        {
            return false
        }
        return !usesIPv6OnlyQueryStrategy(dns["queryStrategy"])
            && isValidIPv4Pool(ipv4Pool)
    }

    private static func usesIPv6OnlyQueryStrategy(_ rawStrategy: Any?) -> Bool {
        guard let strategy = (rawStrategy as? String)?.lowercased() else {
            return false
        }
        return [
            "useip6", "useipv6", "use_ip6", "use_ipv6", "use_ip_v6",
            "use-ip6", "use-ipv6", "use-ip-v6",
        ].contains(strategy)
    }

    private static func isJSONUInt32(_ value: Any) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else {
            return false
        }
        let integerEncodings = "cislqCISLQ"
        guard let encoding = String(cString: number.objCType).first,
              integerEncodings.contains(encoding),
              let numericValue = UInt64(number.stringValue)
        else {
            return false
        }
        return numericValue <= UInt64(UInt32.max)
    }

    private static func isValidIPv4Pool(_ value: String) -> Bool {
        let components = value.split(
            separator: "/",
            maxSplits: 1,
            omittingEmptySubsequences: false
        )
        guard let address = components.first,
              isIPv4Address(String(address))
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

    private static func isIPv4Address(_ address: String) -> Bool {
        var storage = in_addr()
        return address.withCString { rawAddress in
            inet_pton(AF_INET, rawAddress, &storage) == 1
        }
    }
}
