import Foundation

public enum XrayTunnelProviderMessage {
    public static let configReferenceOptionKey = "xrayConfigReference"
    public static let debugLoggingOptionKey = "xrayDebugLogging"
    public static let useTunFileDescriptorOptionKey = "xrayUseTunFileDescriptor"
    public static let tunRuntimeProfileOptionKey = "xrayTunRuntimeProfile"
    public static let startupProbeEnabledOptionKey = "xrayStartupProbeEnabled"
    public static let startupProbeURLOptionKey = "xrayStartupProbeURL"
    public static let startupProbeTimeoutMsOptionKey = "xrayStartupProbeTimeoutMs"
    public static let startupProbeOutboundTagOptionKey = "xrayStartupProbeOutboundTag"
    public static let dnsServersOptionKey = "xrayDNSServers"
    public static let providerConfigReferenceKey = "configReference"
    public static let providerDebugLoggingKey = "debugLogging"
    public static let providerUseTunFileDescriptorKey = "useTunFileDescriptor"
    public static let providerTunRuntimeProfileKey = "tunRuntimeProfile"
    public static let providerStartupProbeEnabledKey = "startupProbeEnabled"
    public static let providerStartupProbeURLKey = "startupProbeURL"
    public static let providerStartupProbeTimeoutMsKey = "startupProbeTimeoutMs"
    public static let providerStartupProbeOutboundTagKey = "startupProbeOutboundTag"
    public static let providerDNSServersKey = "dnsServers"
    public static let providerGeodataAppGroupIdentifierKey = "geodataAppGroupIdentifier"
    public static let providerGeodataRelativeDirectoryKey = "geodataRelativeDirectory"
    public static let statsRequest = "stats"

    public static func encodeStatsResponse(_ stats: XrayClientRuntimeStats) throws -> Data {
        try JSONEncoder().encode(stats)
    }

    public static func decodeStatsResponse(_ data: Data) throws -> XrayClientRuntimeStats {
        try JSONDecoder().decode(XrayClientRuntimeStats.self, from: data)
    }
}
