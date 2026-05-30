import Foundation

public enum XrayTunnelProviderMessage {
    public static let configJSONOptionKey = "xrayConfigJSON"
    public static let providerConfigJSONKey = "configJSON"
    public static let statsRequest = "stats"

    public static func encodeStatsResponse(_ stats: XrayClientRuntimeStats) throws -> Data {
        try JSONEncoder().encode(stats)
    }

    public static func decodeStatsResponse(_ data: Data) throws -> XrayClientRuntimeStats {
        try JSONDecoder().decode(XrayClientRuntimeStats.self, from: data)
    }
}
