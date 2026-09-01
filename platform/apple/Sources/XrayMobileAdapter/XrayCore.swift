import Foundation
import XrayRust

public enum XrayCoreError: Error, CustomStringConvertible, CustomNSError, LocalizedError {
    case status(code: XrayStatus, message: String)
    case incompatibleFFIMajorVersion(expected: UInt32, actual: UInt32)
    case incompatibleFFIMinorVersion(required: UInt32, actual: UInt32)
    case invalidPacketPollSize(Int)
    case invalidPacketBatchLimits(maxPackets: Int, maxPacketBytes: Int)
    case packetBatchSizeOverflow(maxPackets: Int, maxPacketBytes: Int)
    case packetBatchTooLarge(requestedBytes: Int, maximumBytes: Int)
    case missingHandle
    case notRunning
    case invalidUtf8

    public var description: String {
        switch self {
        case let .status(code, message):
            return "xray status \(code): \(message)"
        case let .incompatibleFFIMajorVersion(expected, actual):
            return "incompatible xray FFI ABI major: expected \(expected), got \(actual)"
        case let .incompatibleFFIMinorVersion(required, actual):
            return "incompatible xray FFI ABI minor: require at least \(required), got \(actual)"
        case let .invalidPacketPollSize(maxBytes):
            return "packet poll buffer size must be between 1 and 65535 bytes, got \(maxBytes)"
        case let .invalidPacketBatchLimits(maxPackets, maxPacketBytes):
            return "packet batch limits must be positive, got maxPackets=\(maxPackets) maxPacketBytes=\(maxPacketBytes)"
        case let .packetBatchSizeOverflow(maxPackets, maxPacketBytes):
            return "packet batch size overflows Int for maxPackets=\(maxPackets) maxPacketBytes=\(maxPacketBytes)"
        case let .packetBatchTooLarge(requestedBytes, maximumBytes):
            return "packet batch buffer of \(requestedBytes) bytes exceeds the \(maximumBytes)-byte limit"
        case .missingHandle:
            return "xray core handle is missing"
        case .notRunning:
            return "xray core is not running"
        case .invalidUtf8:
            return "xray returned an invalid UTF-8 error message"
        }
    }

    // Without CustomNSError, Swift bridges this enum to NSError using only the
    // type name and case index, so the engine status and message — the only
    // parts that say what failed — never reach the NEVPNManager error a user
    // sees. Both conformances reuse `description` rather than duplicating it.
    public static let errorDomain = "XrayMobileAdapter.XrayCoreError"

    public var errorCode: Int {
        switch self {
        case .status:
            return 0
        case .incompatibleFFIMajorVersion:
            return 1
        case .invalidPacketPollSize:
            return 2
        case .invalidPacketBatchLimits:
            return 3
        case .packetBatchSizeOverflow:
            return 4
        case .packetBatchTooLarge:
            return 5
        case .missingHandle:
            return 6
        case .notRunning:
            return 7
        case .invalidUtf8:
            return 8
        case .incompatibleFFIMinorVersion:
            return 9
        }
    }

    public var errorUserInfo: [String: Any] {
        [NSLocalizedDescriptionKey: description]
    }

    public var errorDescription: String? {
        description
    }
}

public struct XrayFFIVersion: Equatable, Sendable {
    public let major: UInt32
    public let minor: UInt32

    public init(major: UInt32, minor: UInt32) {
        self.major = major
        self.minor = minor
    }
}

public struct XrayFFICapabilities: OptionSet, Equatable, Sendable {
    public let rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    public static let configWarnings = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_CONFIG_WARNINGS.rawValue)
    )
    public static let geodataSearch = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_GEODATA_SEARCH.rawValue)
    )
    public static let socketProtection = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_SOCKET_PROTECTION.rawValue)
    )
    public static let startupProbe = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_STARTUP_PROBE.rawValue)
    )
    public static let fileLogging = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_FILE_LOGGING.rawValue)
    )
    public static let tunPacketIO = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_TUN_PACKET_IO.rawValue)
    )
    public static let tunFileDescriptor = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_TUN_FD.rawValue)
    )
    public static let tunBatchPoll = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_TUN_BATCH_POLL.rawValue)
    )
    public static let tunRuntimeProfiles = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_TUN_RUNTIME_PROFILES.rawValue)
    )
    public static let dnsBootstrapPolicy = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_DNS_BOOTSTRAP_POLICY.rawValue)
    )
    public static let tunStats = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_TUN_STATS.rawValue)
    )
    public static let tunDiagnosticEvents = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_TUN_DIAGNOSTIC_EVENTS.rawValue)
    )
    public static let outboundSelection = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_OUTBOUND_SELECTION.rawValue)
    )
    public static let outboundHealth = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_OUTBOUND_HEALTH.rawValue)
    )
    public static let connectionManagement = Self(
        rawValue: UInt64(XRAY_FFI_CAPABILITY_CONNECTION_MANAGEMENT.rawValue)
    )
}

public struct XrayFFIInfo: Equatable, Sendable {
    public let version: XrayFFIVersion
    public let capabilities: XrayFFICapabilities

    public init(version: XrayFFIVersion, capabilities: XrayFFICapabilities) {
        self.version = version
        self.capabilities = capabilities
    }

    public func supports(_ capability: XrayFFICapabilities) -> Bool {
        capabilities.contains(capability)
    }
}

public struct XrayOutboundSelectionSnapshot: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let revision: UInt64
    public let groups: [XrayOutboundSelectorGroupSnapshot]

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case revision
        case groups
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == 1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "unsupported outbound selection snapshot schema: \(schemaVersion)"
            )
        }
        revision = try container.decode(UInt64.self, forKey: .revision)
        groups = try container.decode(
            [XrayOutboundSelectorGroupSnapshot].self,
            forKey: .groups
        )
    }
}

public struct XrayOutboundSelectorGroupSnapshot: Codable, Equatable, Sendable {
    public let tag: String
    public let candidates: [String]
    public let overrideTag: String?
}

public enum XrayOutboundHealthState: String, Codable, Equatable, Sendable {
    case unknown
    case healthy
    case unhealthy
}

public enum XrayOutboundHealthFailureKind: String, Codable, Equatable, Sendable {
    case timeout
    case transport
    case tls
    case io
    case malformedHttpResponse
    case httpStatus
}

public struct XrayOutboundHealthSnapshot: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let revision: UInt64
    public let outbounds: [XrayOutboundHealthStatus]

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case revision
        case outbounds
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == 1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "unsupported outbound health snapshot schema: \(schemaVersion)"
            )
        }
        revision = try container.decode(UInt64.self, forKey: .revision)
        outbounds = try container.decode([XrayOutboundHealthStatus].self, forKey: .outbounds)
    }
}

public struct XrayOutboundHealthStatus: Codable, Equatable, Sendable {
    public let tag: String
    public let state: XrayOutboundHealthState
    public let delayMs: UInt64?
    public let lastTryUnixMs: UInt64?
    public let lastSeenUnixMs: UInt64?
    public let consecutiveFailures: UInt64
    public let lastFailureKind: XrayOutboundHealthFailureKind?
    public let httpStatus: UInt16?
}

public enum XrayConnectionState: String, Codable, Equatable, Sendable {
    case opening
    case active
}

public enum XrayConnectionNetwork: String, Codable, Equatable, Sendable {
    case tcp
    case udp
}

public enum XrayConnectionAddressType: String, Codable, Equatable, Sendable {
    case ip
    case domain
}

public struct XrayConnectionSnapshot: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let revision: UInt64
    public let connections: [XrayConnectionInfo]

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case revision
        case connections
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == 1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "unsupported connection snapshot schema: \(schemaVersion)"
            )
        }
        revision = try container.decode(UInt64.self, forKey: .revision)
        connections = try container.decode([XrayConnectionInfo].self, forKey: .connections)
    }
}

public struct XrayConnectionInfo: Codable, Equatable, Sendable {
    public let id: UInt64
    public let state: XrayConnectionState
    public let inboundTag: String?
    public let outboundTag: String?
    public let network: XrayConnectionNetwork
    public let addressType: XrayConnectionAddressType
    public let address: String
    public let port: UInt16
    public let startedUnixMs: UInt64
}

public struct XrayOutboundAccountingSnapshot: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let revision: UInt64
    public let outbounds: [XrayOutboundAccounting]

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case revision
        case outbounds
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        guard schemaVersion == 1 else {
            throw DecodingError.dataCorruptedError(
                forKey: .schemaVersion,
                in: container,
                debugDescription: "unsupported outbound accounting snapshot schema: \(schemaVersion)"
            )
        }
        revision = try container.decode(UInt64.self, forKey: .revision)
        outbounds = try container.decode([XrayOutboundAccounting].self, forKey: .outbounds)
    }
}

public struct XrayOutboundAccounting: Codable, Equatable, Sendable {
    public let outboundTag: String?
    public let openedConnections: UInt64
    public let completedConnections: UInt64
    public let hostClosedConnections: UInt64
    public let uplinkBytes: UInt64
    public let downlinkBytes: UInt64
}

/// Controls whether the core may use the platform resolver for bootstrap lookups.
public enum XrayDNSBootstrapMode: Equatable, Sendable {
    /// Allows the platform resolver when config-backed resolution has no IP result.
    case system

    /// Disables platform fallback; bootstrap names must resolve from static config.
    case staticOnly

    fileprivate var ffiValue: XrayDnsBootstrapMode {
        switch self {
        case .system:
            return XRAY_DNS_BOOTSTRAP_MODE_SYSTEM
        case .staticOnly:
            return XRAY_DNS_BOOTSTRAP_MODE_STATIC_ONLY
        }
    }
}

/// Controls whether an explicit geodata directory may fall back to process defaults.
public enum XrayGeodataSearchPolicy: Equatable, Sendable {
    /// Searches the explicit directory first, then the process default directories.
    case fallbackToDefaults

    /// Searches only the explicit directory and fails if a referenced asset is absent.
    case exclusive
}

final class XrayPacketBatchPollStorage: @unchecked Sendable {
    let maxPackets: Int
    let maxPacketBytes: Int

    private var bytes: [UInt8]
    private var lengths: [Int]
    private(set) var materializedPacketCount = 0

    init(
        validatedMaxPackets maxPackets: Int,
        validatedMaxPacketBytes maxPacketBytes: Int,
        validatedByteCount byteCount: Int
    ) {
        precondition(maxPackets > 0)
        precondition(maxPacketBytes > 0)
        precondition(byteCount == maxPackets * maxPacketBytes)
        self.maxPackets = maxPackets
        self.maxPacketBytes = maxPacketBytes
        bytes = [UInt8](repeating: 0, count: byteCount)
        lengths = [Int](repeating: 0, count: maxPackets)
    }

    func withUnsafeMutableBuffers<T>(
        _ body: (
            UnsafeMutableBufferPointer<UInt8>,
            UnsafeMutableBufferPointer<Int>
        ) throws -> T
    ) rethrows -> T {
        try bytes.withUnsafeMutableBufferPointer { byteBuffer in
            try lengths.withUnsafeMutableBufferPointer { lengthBuffer in
                try body(byteBuffer, lengthBuffer)
            }
        }
    }

    func materializePackets(packetCount: Int) -> [Data] {
        guard packetCount > 0 else {
            return []
        }
        precondition(packetCount <= maxPackets)

        var packets = [Data]()
        packets.reserveCapacity(packetCount)
        var offset = 0
        for index in 0..<packetCount {
            let length = lengths[index]
            precondition(length >= 0)
            precondition(offset <= bytes.count - length)
            packets.append(Data(bytes[offset..<(offset + length)]))
            materializedPacketCount += 1
            offset += length
        }
        return packets
    }

    var bufferIdentities: (bytes: UInt, lengths: UInt) {
        withUnsafeMutableBuffers { byteBuffer, lengthBuffer in
            (
                bytes: byteBuffer.baseAddress.map(UInt.init(bitPattern:)) ?? 0,
                lengths: lengthBuffer.baseAddress.map(UInt.init(bitPattern:)) ?? 0
            )
        }
    }
}

public protocol XraySocketProtecting: AnyObject, Sendable {
    func protect(socket: Int32) -> Bool
}

private final class XraySocketProtectContext: @unchecked Sendable {
    let protector: XraySocketProtecting

    init(protector: XraySocketProtecting) {
        self.protector = protector
    }
}

private func xraySwiftSocketProtect(
    socket: Int32,
    userData: UnsafeMutableRawPointer?
) -> Int32 {
    guard let userData else {
        return 0
    }
    let context = Unmanaged<XraySocketProtectContext>
        .fromOpaque(userData)
        .takeUnretainedValue()
    return context.protector.protect(socket: socket) ? 1 : 0
}

final class XrayCoreCallGate: @unchecked Sendable {
    private let condition = NSCondition()
    private var activeDataPathCalls = 0
    private var waitingLifecycleCalls = 0
    private var lifecycleCallActive = false

    var hasWaitingLifecycleCall: Bool {
        condition.lock()
        defer { condition.unlock() }
        return waitingLifecycleCalls > 0
    }

    func withDataPath<T>(_ body: () throws -> T) rethrows -> T {
        condition.lock()
        while lifecycleCallActive || waitingLifecycleCalls > 0 {
            condition.wait()
        }
        activeDataPathCalls += 1
        condition.unlock()

        defer {
            condition.lock()
            activeDataPathCalls -= 1
            if activeDataPathCalls == 0 {
                condition.broadcast()
            }
            condition.unlock()
        }
        return try body()
    }

    func withLifecycle<T>(_ body: () throws -> T) rethrows -> T {
        condition.lock()
        waitingLifecycleCalls += 1
        while lifecycleCallActive || activeDataPathCalls > 0 {
            condition.wait()
        }
        waitingLifecycleCalls -= 1
        lifecycleCallActive = true
        condition.unlock()

        defer {
            condition.lock()
            lifecycleCallActive = false
            condition.broadcast()
            condition.unlock()
        }
        return try body()
    }
}

public struct XrayStartupProbeOptions: Equatable, Sendable {
    public let url: String
    public let timeoutMs: UInt64
    public let outboundTag: String?

    public init(
        url: String,
        timeoutMs: UInt64 = 5_000,
        outboundTag: String? = nil
    ) {
        self.url = url
        self.timeoutMs = timeoutMs
        self.outboundTag = outboundTag
    }
}

public struct XrayTunStatsSnapshot: Equatable, Sendable {
    public let inboundPackets: UInt64
    public let outboundPackets: UInt64
    public let droppedPackets: UInt64
    public let inboundDroppedPackets: UInt64
    public let outboundDroppedPackets: UInt64
    public let tcpStackToRemoteBytes: UInt64
    public let tcpRemoteWrittenBytes: UInt64
    public let tcpRemoteReadBytes: UInt64
    public let tcpBackpressureEvents: UInt64
    public let tcpStackToRemoteBackpressureEvents: UInt64
    public let tcpRemoteToStackBackpressureEvents: UInt64
    public let tcpRemoteWriteBatches: UInt64
    public let tcpRemoteWriteBatchMessages: UInt64
    public let tcpRemoteWriteBatchMaxMessages: UInt64
    public let tcpRemoteWriteBatchMaxBytes: UInt64
    public let tcpRemoteWriteWaitEvents: UInt64
    public let tcpRemoteWriteWaitDurationMsTotal: UInt64
    public let tcpRemoteWriteWaitDurationMsMax: UInt64
    public let tcpRemoteFlushWaitEvents: UInt64
    public let tcpRemoteFlushWaitDurationMsTotal: UInt64
    public let tcpRemoteFlushWaitDurationMsMax: UInt64
    public let tcpPendingRemoteBytes: UInt64
    public let tcpPendingRemoteFlows: UInt64
    public let tcpPendingRemoteMaxBytes: UInt64
    public let tcpPendingUploadBytes: UInt64
    public let tcpPendingUploadMaxBytes: UInt64
    public let tcpPendingTotalBytes: UInt64
    public let tcpRemoteBufferLimitBytes: UInt64
    public let tcpBufferHardLimitBytes: UInt64
    public let tcpRemoteBufferPressureActive: Bool
    public let tcpRemoteWriteErrors: UInt64
    public let tcpRemoteClosedEvents: UInt64
    public let tcpRemoteReadErrors: UInt64
    public let tcpOpenErrors: UInt64
    public let tcpOpenEvents: UInt64
    public let tcpOpenDurationMsTotal: UInt64
    public let tcpOpenDurationMsMax: UInt64
    public let tcpFirstByteEvents: UInt64
    public let tcpFirstByteDurationMsTotal: UInt64
    public let tcpFirstByteDurationMsMax: UInt64
    public let tcp443OpenEvents: UInt64
    public let tcp443OpenDurationMsTotal: UInt64
    public let tcp443OpenDurationMsMax: UInt64
    public let tcp443FirstByteEvents: UInt64
    public let tcp443FirstByteDurationMsTotal: UInt64
    public let tcp443FirstByteDurationMsMax: UInt64
    public let activeTCPFlows: UInt64
    public let activeUDPFlows: UInt64
    public let udpFlowLimit: UInt64
    public let udpBudgetDrops: UInt64
    public let udpEvictedFlows: UInt64
    public let udpChannelDroppedPackets: UInt64
    public let udpRemoteOpenEvents: UInt64
    public let udpRemoteUDP443OpenEvents: UInt64
    public let udpRemoteWrittenBytes: UInt64
    public let udpRemoteReadBytes: UInt64
    public let udpOpenErrors: UInt64
    public let udpVisionUDP443Rejections: UInt64
    public let udpRemoteWriteErrors: UInt64
    public let udpRemoteReadErrors: UInt64
    public let udpRemoteClosedEvents: UInt64
    public let udpQuicBlockedPackets: UInt64
    public let inboundQueueDepth: UInt64
    public let outboundQueueDepth: UInt64
    public let inboundQueueMaxPackets: UInt64
    public let outboundQueueMaxPackets: UInt64
    public let tunFdWriteBatches: UInt64
    public let tunFdWriteBatchPackets: UInt64
    public let tunFdWriteBatchMaxPackets: UInt64
    public let tunFdReadLoopExits: UInt64
    public let tunFdWriteLoopExits: UInt64
    public let tunFdTransientIoErrors: UInt64
}

public extension XrayTunStatsSnapshot {
    func debugLogMessages(prefix: String = "Debug stats") -> [String] {
        [
            "\(prefix) core inbound=\(inboundPackets) outbound=\(outboundPackets) dropped=\(droppedPackets) inboundDropped=\(inboundDroppedPackets) outboundDropped=\(outboundDroppedPackets) activeTCPFlows=\(activeTCPFlows) activeUDPFlows=\(activeUDPFlows)",
            "\(prefix) queues inboundQueueDepth=\(inboundQueueDepth) outboundQueueDepth=\(outboundQueueDepth) inboundQueueMaxPackets=\(inboundQueueMaxPackets) outboundQueueMaxPackets=\(outboundQueueMaxPackets) tunFdWriteBatches=\(tunFdWriteBatches) tunFdWriteBatchPackets=\(tunFdWriteBatchPackets) tunFdWriteBatchMaxPackets=\(tunFdWriteBatchMaxPackets) tunFdReadLoopExits=\(tunFdReadLoopExits) tunFdWriteLoopExits=\(tunFdWriteLoopExits) tunFdTransientIoErrors=\(tunFdTransientIoErrors)",
            "\(prefix) tcpBytes tcpStackToRemoteBytes=\(tcpStackToRemoteBytes) tcpRemoteWrittenBytes=\(tcpRemoteWrittenBytes) tcpRemoteReadBytes=\(tcpRemoteReadBytes) tcpBackpressure=\(tcpBackpressureEvents) tcpStackToRemoteBackpressure=\(tcpStackToRemoteBackpressureEvents) tcpRemoteToStackBackpressure=\(tcpRemoteToStackBackpressureEvents)",
            "\(prefix) tcpBuffers tcpRemoteWriteBatches=\(tcpRemoteWriteBatches) tcpRemoteWriteBatchMessages=\(tcpRemoteWriteBatchMessages) tcpRemoteWriteBatchMaxMessages=\(tcpRemoteWriteBatchMaxMessages) tcpRemoteWriteBatchMaxBytes=\(tcpRemoteWriteBatchMaxBytes) tcpPendingRemoteBytes=\(tcpPendingRemoteBytes) tcpPendingRemoteFlows=\(tcpPendingRemoteFlows) tcpPendingRemoteMaxBytes=\(tcpPendingRemoteMaxBytes) tcpWriteErrors=\(tcpRemoteWriteErrors) tcpRemoteClosed=\(tcpRemoteClosedEvents) tcpReadErrors=\(tcpRemoteReadErrors) tcpOpenErrors=\(tcpOpenErrors)",
            "\(prefix) tcpBudget tcpPendingUploadBytes=\(tcpPendingUploadBytes) tcpPendingUploadMaxBytes=\(tcpPendingUploadMaxBytes) tcpPendingTotalBytes=\(tcpPendingTotalBytes) tcpRemoteBufferLimitBytes=\(tcpRemoteBufferLimitBytes) tcpBufferHardLimitBytes=\(tcpBufferHardLimitBytes) tcpRemoteBufferPressureActive=\(tcpRemoteBufferPressureActive)",
            "\(prefix) tcpWriteWait tcpRemoteWriteWaitEvents=\(tcpRemoteWriteWaitEvents) tcpRemoteWriteWaitAvgMs=\(averageDurationMs(total: tcpRemoteWriteWaitDurationMsTotal, events: tcpRemoteWriteWaitEvents)) tcpRemoteWriteWaitMaxMs=\(tcpRemoteWriteWaitDurationMsMax) tcpRemoteFlushWaitEvents=\(tcpRemoteFlushWaitEvents) tcpRemoteFlushWaitAvgMs=\(averageDurationMs(total: tcpRemoteFlushWaitDurationMsTotal, events: tcpRemoteFlushWaitEvents)) tcpRemoteFlushWaitMaxMs=\(tcpRemoteFlushWaitDurationMsMax)",
            "\(prefix) tcpTiming tcpOpenEvents=\(tcpOpenEvents) tcpOpenAvgMs=\(averageDurationMs(total: tcpOpenDurationMsTotal, events: tcpOpenEvents)) tcpOpenMaxMs=\(tcpOpenDurationMsMax) tcpFirstByteEvents=\(tcpFirstByteEvents) tcpFirstByteAvgMs=\(averageDurationMs(total: tcpFirstByteDurationMsTotal, events: tcpFirstByteEvents)) tcpFirstByteMaxMs=\(tcpFirstByteDurationMsMax) tcp443OpenEvents=\(tcp443OpenEvents) tcp443OpenAvgMs=\(averageDurationMs(total: tcp443OpenDurationMsTotal, events: tcp443OpenEvents)) tcp443OpenMaxMs=\(tcp443OpenDurationMsMax) tcp443FirstByteEvents=\(tcp443FirstByteEvents) tcp443FirstByteAvgMs=\(averageDurationMs(total: tcp443FirstByteDurationMsTotal, events: tcp443FirstByteEvents)) tcp443FirstByteMaxMs=\(tcp443FirstByteDurationMsMax)",
            "\(prefix) udpFlows udpFlowLimit=\(udpFlowLimit) udpBudgetDrops=\(udpBudgetDrops) udpEvictedFlows=\(udpEvictedFlows) udpChannelDroppedPackets=\(udpChannelDroppedPackets)",
            "\(prefix) udpRemote udpOpenEvents=\(udpRemoteOpenEvents) udpUDP443OpenEvents=\(udpRemoteUDP443OpenEvents) udpWrittenBytes=\(udpRemoteWrittenBytes) udpReadBytes=\(udpRemoteReadBytes) udpOpenErrors=\(udpOpenErrors) udpVisionUDP443Rejections=\(udpVisionUDP443Rejections) udpWriteErrors=\(udpRemoteWriteErrors) udpReadErrors=\(udpRemoteReadErrors) udpRemoteClosed=\(udpRemoteClosedEvents) udpQuicBlockedPackets=\(udpQuicBlockedPackets)",
        ]
    }
}

private func averageDurationMs(total: UInt64, events: UInt64) -> UInt64 {
    events == 0 ? 0 : total / events
}

public enum XrayTcpSlowFlowEventKind: String, Sendable {
    case open
    case firstByte
    case unknown
}

public struct XrayTcpSlowFlowEventSnapshot: Equatable, Sendable {
    public let kind: XrayTcpSlowFlowEventKind
    public let target: String
    public let openDurationMs: UInt64
    public let firstByteDurationMs: UInt64
}

public extension XrayTcpSlowFlowEventSnapshot {
    func debugLogMessage(prefix: String = "Debug tcpSlowFlow") -> String {
        "\(prefix) kind=\(kind.rawValue) target=\(target) openMs=\(openDurationMs) firstByteMs=\(firstByteDurationMs)"
    }
}

public struct XrayTcpFlowSummaryEventSnapshot: Equatable, Sendable {
    public let target: String
    public let outboundTag: String?
    public let closed: Bool
    public let durationMs: UInt64
    public let openDurationMs: UInt64
    public let firstByteDurationMs: UInt64
    public let remoteReadBytes: UInt64
    public let msTo64KiB: UInt64
    public let msTo128KiB: UInt64
    public let msTo256KiB: UInt64
    public let msTo512KiB: UInt64
    public let msTo1MiB: UInt64
}

public extension XrayTcpFlowSummaryEventSnapshot {
    func debugLogMessage(prefix: String = "Debug tcpFlowSummary") -> String {
        "\(prefix) target=\(target) outbound=\(outboundTag ?? "untagged") closed=\(closed) durationMs=\(durationMs) openMs=\(openDurationMs) firstByteMs=\(firstByteDurationMs) remoteReadBytes=\(remoteReadBytes) msTo64KiB=\(msTo64KiB) msTo128KiB=\(msTo128KiB) msTo256KiB=\(msTo256KiB) msTo512KiB=\(msTo512KiB) msTo1MiB=\(msTo1MiB)"
    }
}

public struct XrayTcpRemoteWriteSlowEventSnapshot: Equatable, Sendable {
    public let target: String
    public let outboundTag: String?
    public let durationMs: UInt64
    public let bytes: UInt64
    public let messages: UInt64
}

public extension XrayTcpRemoteWriteSlowEventSnapshot {
    func debugLogMessage(prefix: String = "Debug tcpRemoteWriteSlow") -> String {
        "\(prefix) target=\(target) outbound=\(outboundTag ?? "untagged") writeWaitMs=\(durationMs) bytes=\(bytes) messages=\(messages)"
    }
}

public struct XrayTcpOpenErrorEventSnapshot: Equatable, Sendable {
    public let target: String
    public let outboundTag: String?
    public let error: String
}

public extension XrayTcpOpenErrorEventSnapshot {
    func debugLogMessage(prefix: String = "Debug tcpOpenError") -> String {
        "\(prefix) target=\(target) outbound=\(outboundTag ?? "untagged") error=\(error)"
    }
}

public struct XrayUdpSlowFlowEventSnapshot: Equatable, Sendable {
    public let target: String
    public let firstResponseDurationMs: UInt64
    public let writtenBytes: UInt64
    public let readBytes: UInt64
}

public extension XrayUdpSlowFlowEventSnapshot {
    func debugLogMessage(prefix: String = "Debug udpSlowFlow") -> String {
        "\(prefix) target=\(target) firstResponseMs=\(firstResponseDurationMs) writtenBytes=\(writtenBytes) readBytes=\(readBytes)"
    }
}

public struct XrayUdpResponseGapEventSnapshot: Equatable, Sendable {
    public let target: String
    public let responseGapDurationMs: UInt64
    public let writtenBytes: UInt64
    public let readBytes: UInt64
}

public extension XrayUdpResponseGapEventSnapshot {
    func debugLogMessage(prefix: String = "Debug udpResponseGap") -> String {
        "\(prefix) target=\(target) responseGapMs=\(responseGapDurationMs) writtenBytes=\(writtenBytes) readBytes=\(readBytes)"
    }
}

public struct XrayUdpQuicBlockedEventSnapshot: Equatable, Sendable {
    public let target: String
    public let bytes: UInt64
}

public extension XrayUdpQuicBlockedEventSnapshot {
    func debugLogMessage(prefix: String = "Debug quicBlocked") -> String {
        "\(prefix) target=\(target) bytes=\(bytes)"
    }
}

private extension XrayTcpSlowFlowKind {
    var snapshotKind: XrayTcpSlowFlowEventKind {
        switch rawValue {
        case XRAY_TCP_SLOW_FLOW_KIND_OPEN.rawValue:
            return .open
        case XRAY_TCP_SLOW_FLOW_KIND_FIRST_BYTE.rawValue:
            return .firstByte
        default:
            return .unknown
        }
    }
}

public final class XrayCore: @unchecked Sendable {
    static let expectedFFIMajorVersion: UInt32 = 1
    static let minimumFFIMinorVersion: UInt32 = 1
    static let maximumPolledPacketBytes = 65_535
    static let maximumPacketBatchBytes = 4 * 1_024 * 1_024

    private let callGate = XrayCoreCallGate()
    private var handle: OpaquePointer?
    private var dataPathEnabled = false
    private var retainedSocketProtectContext: Unmanaged<XraySocketProtectContext>?

    public static var ffiInfo: XrayFFIInfo {
        XrayFFIInfo(
            version: XrayFFIVersion(
                major: xray_ffi_version_major(),
                minor: xray_ffi_version_minor()
            ),
            capabilities: XrayFFICapabilities(rawValue: xray_ffi_capabilities())
        )
    }

    public static func tunRuntimeProfile(named rawValue: String) -> XrayTunRuntimeProfile {
        switch rawValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "mobile":
            return XRAY_TUN_RUNTIME_PROFILE_MOBILE
        case "mobile-plus", "mobile_plus", "mobileplus":
            return XRAY_TUN_RUNTIME_PROFILE_MOBILE_PLUS
        case "desktop":
            return XRAY_TUN_RUNTIME_PROFILE_DESKTOP
        case "low-memory", "low_memory", "lowmemory":
            return XRAY_TUN_RUNTIME_PROFILE_LOW_MEMORY
        case "throughput":
            return XRAY_TUN_RUNTIME_PROFILE_THROUGHPUT
        default:
            return XRAY_TUN_RUNTIME_PROFILE_DEFAULT
        }
    }

    public convenience init(
        configJSON: String,
        borrowedDarwinTunFileDescriptor fd: Int32,
        collectTcpTimings: Bool = false,
        tunRuntimeProfile: XrayTunRuntimeProfile = XRAY_TUN_RUNTIME_PROFILE_DEFAULT,
        dnsBootstrapMode: XrayDNSBootstrapMode = .system,
        geodataSearchDirectory: URL? = nil,
        geodataSearchPolicy: XrayGeodataSearchPolicy = .fallbackToDefaults,
        startupProbe: XrayStartupProbeOptions? = nil,
        fileLogDirectory: URL? = nil
    ) throws {
        try self.init(
            configJSON: configJSON,
            collectTcpTimings: collectTcpTimings,
            tunRuntimeProfile: tunRuntimeProfile,
            dnsBootstrapMode: dnsBootstrapMode,
            geodataSearchDirectory: geodataSearchDirectory,
            geodataSearchPolicy: geodataSearchPolicy,
            startupProbe: startupProbe,
            fileLogDirectory: fileLogDirectory,
            tunFileDescriptor: fd,
            tunPacketFormat: XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN,
            tunClosePolicy: XRAY_TUN_FD_CLOSE_POLICY_BORROWED
        )
    }

    public init(
        configJSON: String,
        collectTcpTimings: Bool = false,
        tunRuntimeProfile: XrayTunRuntimeProfile = XRAY_TUN_RUNTIME_PROFILE_DEFAULT,
        dnsBootstrapMode: XrayDNSBootstrapMode = .system,
        geodataSearchDirectory: URL? = nil,
        geodataSearchPolicy: XrayGeodataSearchPolicy = .fallbackToDefaults,
        startupProbe: XrayStartupProbeOptions? = nil,
        fileLogDirectory: URL? = nil,
        socketProtector: XraySocketProtecting? = nil,
        tunFileDescriptor: Int32? = nil,
        tunPacketFormat: XrayTunFdPacketFormat = XRAY_TUN_FD_PACKET_FORMAT_RAW_IP,
        tunClosePolicy: XrayTunFdClosePolicy = XRAY_TUN_FD_CLOSE_POLICY_BORROWED
    ) throws {
        let ffiInfo = Self.ffiInfo
        try Self.validateFFIVersion(
            major: ffiInfo.version.major,
            minor: ffiInfo.version.minor
        )

        var error: OpaquePointer?
        XrayMobileLog.info(
            "Core",
            "Creating core configBytes=\(configJSON.utf8.count) socketProtect=\(socketProtector != nil) tunFd=\(tunFileDescriptor != nil ? "present" : "none") collectTcpTimings=\(collectTcpTimings) tunRuntimeProfile=\(tunRuntimeProfile.rawValue) dnsBootstrapMode=\(dnsBootstrapMode)"
        )
        guard let handle = xray_core_new(&error) else {
            let coreError = XrayCore.takeError(error)
            XrayMobileLog.error("Core", "xray_core_new failed: \(coreError.description)")
            throw coreError
        }

        self.handle = handle
        do {
            try check(
                xray_core_set_dns_bootstrap_mode(
                    handle,
                    Int32(dnsBootstrapMode.ffiValue.rawValue),
                    &error
                ),
                error: error
            )
            if let startupProbe {
                try startupProbe.url.withCString { urlPointer in
                    if let outboundTag = startupProbe.outboundTag, !outboundTag.isEmpty {
                        try outboundTag.withCString { outboundTagPointer in
                            try check(
                                xray_core_set_startup_probe(
                                    handle,
                                    urlPointer,
                                    startupProbe.timeoutMs,
                                    outboundTagPointer,
                                    &error
                                ),
                                error: error
                            )
                        }
                    } else {
                        try check(
                            xray_core_set_startup_probe(
                                handle,
                                urlPointer,
                                startupProbe.timeoutMs,
                                nil,
                                &error
                            ),
                            error: error
                        )
                    }
                }
            }
            if let fileLogDirectory {
                try FileManager.default.createDirectory(
                    at: fileLogDirectory,
                    withIntermediateDirectories: true
                )
                try fileLogDirectory.path.withCString { pointer in
                    try check(
                        xray_core_set_file_logging(handle, pointer, 1, &error),
                        error: error
                    )
                }
            }
            if let socketProtector {
                let context = Unmanaged.passRetained(
                    XraySocketProtectContext(protector: socketProtector)
                )
                do {
                    try check(
                        xray_core_set_socket_protect_callback(
                            handle,
                            xraySwiftSocketProtect,
                            context.toOpaque(),
                            &error
                        ),
                        error: error
                    )
                    retainedSocketProtectContext = context
                } catch {
                    context.release()
                    throw error
                }
            }
            if let tunFileDescriptor {
                try check(
                    xray_core_set_tun_fd(
                        handle,
                        tunFileDescriptor,
                        Int32(tunPacketFormat.rawValue),
                        Int32(tunClosePolicy.rawValue),
                        &error
                    ),
                    error: error
                )
            }
            try check(
                xray_core_set_tun_collect_tcp_timings(
                    handle,
                    collectTcpTimings ? 1 : 0,
                    &error
                ),
                error: error
            )
            try check(
                xray_core_set_tun_runtime_profile(
                    handle,
                    Int32(tunRuntimeProfile.rawValue),
                    &error
                ),
                error: error
            )
            if let geodataSearchDirectory {
                try geodataSearchDirectory.path.withCString { pointer in
                    let status: XrayStatus
                    switch geodataSearchPolicy {
                    case .fallbackToDefaults:
                        status = xray_core_set_geodata_search_dir(handle, pointer, &error)
                    case .exclusive:
                        status = xray_core_set_geodata_search_dir_exclusive(
                            handle,
                            pointer,
                            &error
                        )
                    }
                    try check(status, error: error)
                }
            }
            try configJSON.withCString { pointer in
                try check(xray_core_load_config_json(handle, pointer, &error), error: error)
            }
            for warning in try configWarnings(handle: handle) {
                XrayMobileLog.info("Core", "Config warning: \(warning)")
            }
            XrayMobileLog.info("Core", "Core config loaded")
        } catch {
            XrayMobileLog.error("Core", "Core init failed: \(error)")
            xray_core_free(handle)
            retainedSocketProtectContext?.release()
            retainedSocketProtectContext = nil
            self.handle = nil
            throw error
        }
    }

    static func validateFFIVersion(major: UInt32, minor: UInt32) throws {
        guard major == expectedFFIMajorVersion else {
            throw XrayCoreError.incompatibleFFIMajorVersion(
                expected: expectedFFIMajorVersion,
                actual: major
            )
        }
        guard minor >= minimumFFIMinorVersion else {
            throw XrayCoreError.incompatibleFFIMinorVersion(
                required: minimumFFIMinorVersion,
                actual: minor
            )
        }
    }

    deinit {
        callGate.withLifecycle {
            dataPathEnabled = false
            if let handle {
                self.handle = nil
                XrayMobileLog.info("Core", "Deinit stopping and freeing core")
                _ = xray_core_stop(handle, nil)
                xray_core_free(handle)
            }
            retainedSocketProtectContext?.release()
            retainedSocketProtectContext = nil
        }
    }

    public func start() throws {
        do {
            try withLifecycleHandle { handle in
                var error: OpaquePointer?
                XrayMobileLog.info("Core", "Starting core")
                try check(xray_core_start(handle, &error), error: error)
                dataPathEnabled = true
                XrayMobileLog.info("Core", "Core started")
            }
        } catch {
            XrayMobileLog.error("Core", "Core start failed: \(error)")
            throw error
        }
    }

    public func stop() throws {
        do {
            try withLifecycleHandle { handle in
                var error: OpaquePointer?
                XrayMobileLog.info("Core", "Stopping core")
                dataPathEnabled = false
                try check(xray_core_stop(handle, &error), error: error)
                XrayMobileLog.info("Core", "Core stopped")
            }
        } catch {
            XrayMobileLog.error("Core", "Core stop failed: \(error)")
            throw error
        }
    }

    public func setOutboundSelectorOverride(groupTag: String, outboundTag: String) throws {
        try requireCapability(.outboundSelection)
        try withSharedHandle { handle in
            var error: OpaquePointer?
            try groupTag.withCString { groupPointer in
                try outboundTag.withCString { outboundPointer in
                    try check(
                        xray_core_set_outbound_selector_override(
                            handle,
                            groupPointer,
                            outboundPointer,
                            &error
                        ),
                        error: error
                    )
                }
            }
        }
    }

    public func clearOutboundSelectorOverride(groupTag: String) throws {
        try requireCapability(.outboundSelection)
        try withSharedHandle { handle in
            var error: OpaquePointer?
            try groupTag.withCString { groupPointer in
                try check(
                    xray_core_clear_outbound_selector_override(
                        handle,
                        groupPointer,
                        &error
                    ),
                    error: error
                )
            }
        }
    }

    public func outboundSelectionSnapshot() throws -> XrayOutboundSelectionSnapshot {
        try requireCapability(.outboundSelection)
        return try withSharedHandle { handle in
            let data = try snapshotJSON(handle: handle, kind: .selection)
            return try JSONDecoder().decode(XrayOutboundSelectionSnapshot.self, from: data)
        }
    }

    public func outboundHealthSnapshot() throws -> XrayOutboundHealthSnapshot {
        try requireCapability(.outboundHealth)
        return try withSharedHandle { handle in
            let data = try snapshotJSON(handle: handle, kind: .health)
            return try JSONDecoder().decode(XrayOutboundHealthSnapshot.self, from: data)
        }
    }

    public func connectionSnapshot() throws -> XrayConnectionSnapshot {
        try requireCapability(.connectionManagement)
        return try withSharedHandle { handle in
            let data = try snapshotJSON(handle: handle, kind: .connections)
            return try JSONDecoder().decode(XrayConnectionSnapshot.self, from: data)
        }
    }

    public func outboundAccountingSnapshot() throws -> XrayOutboundAccountingSnapshot {
        try requireCapability(.connectionManagement)
        return try withSharedHandle { handle in
            let data = try snapshotJSON(handle: handle, kind: .accounting)
            return try JSONDecoder().decode(XrayOutboundAccountingSnapshot.self, from: data)
        }
    }

    public func closeConnection(id: UInt64) throws {
        try requireCapability(.connectionManagement)
        try withSharedHandle { handle in
            var error: OpaquePointer?
            try check(xray_core_close_connection(handle, id, &error), error: error)
        }
    }

    public func pushPacket(_ packet: Data) throws {
        try withDataPathHandle { handle in
            var error: OpaquePointer?
            try packet.withUnsafeBytes { rawBuffer in
                let pointer = rawBuffer.bindMemory(to: UInt8.self).baseAddress
                try check(
                    xray_tun_push_packet(handle, pointer, packet.count, &error),
                    error: error
                )
            }
        }
    }

    public func pollPacket(maxBytes: Int = 1_500) throws -> Data? {
        try Self.validatePacketPollSize(maxBytes)
        return try withDataPathHandle { handle in
            var error: OpaquePointer?
            var written = 0
            var buffer = [UInt8](repeating: 0, count: maxBytes)
            let status = buffer.withUnsafeMutableBufferPointer { mutableBuffer in
                xray_tun_poll_packet(
                    handle,
                    mutableBuffer.baseAddress,
                    mutableBuffer.count,
                    &written,
                    &error
                )
            }

            if status == XRAY_STATUS_NO_PACKET {
                return nil
            }

            try check(status, error: error)
            return Data(buffer.prefix(written))
        }
    }

    /// Polls a batch of outbound packets, waiting up to `waitMilliseconds`
    /// for the first one. Returns an empty array on timeout.
    public func pollPackets(
        maxPackets: Int = 64,
        maxPacketBytes: Int = 1_500,
        waitMilliseconds: UInt32 = 0
    ) throws -> [Data] {
        let byteCount = try Self.validatedPacketBatchByteCount(
            maxPackets: maxPackets,
            maxPacketBytes: maxPacketBytes
        )
        let storage = XrayPacketBatchPollStorage(
            validatedMaxPackets: maxPackets,
            validatedMaxPacketBytes: maxPacketBytes,
            validatedByteCount: byteCount
        )
        return try pollPackets(
            storage: storage,
            waitMilliseconds: waitMilliseconds
        )
    }

    func pollPackets(
        storage: XrayPacketBatchPollStorage,
        waitMilliseconds: UInt32 = 0
    ) throws -> [Data] {
        try withDataPathHandle { handle in
            var error: OpaquePointer?
            var packetCount = 0
            let status = storage.withUnsafeMutableBuffers {
                bufferPointer,
                lengthsPointer in
                xray_tun_poll_packets(
                    handle,
                    bufferPointer.baseAddress,
                    bufferPointer.count,
                    lengthsPointer.baseAddress,
                    storage.maxPackets,
                    &packetCount,
                    waitMilliseconds,
                    &error
                )
            }

            if status == XRAY_STATUS_NO_PACKET {
                return []
            }

            try check(status, error: error)
            return storage.materializePackets(packetCount: packetCount)
        }
    }

    static func validatePacketPollSize(_ maxBytes: Int) throws {
        guard (1...maximumPolledPacketBytes).contains(maxBytes) else {
            throw XrayCoreError.invalidPacketPollSize(maxBytes)
        }
    }

    static func validatedPacketBatchByteCount(
        maxPackets: Int,
        maxPacketBytes: Int
    ) throws -> Int {
        guard maxPackets > 0, maxPacketBytes > 0 else {
            throw XrayCoreError.invalidPacketBatchLimits(
                maxPackets: maxPackets,
                maxPacketBytes: maxPacketBytes
            )
        }
        try validatePacketPollSize(maxPacketBytes)
        let (byteCount, overflowed) = maxPackets.multipliedReportingOverflow(
            by: maxPacketBytes
        )
        guard !overflowed else {
            throw XrayCoreError.packetBatchSizeOverflow(
                maxPackets: maxPackets,
                maxPacketBytes: maxPacketBytes
            )
        }
        guard byteCount <= maximumPacketBatchBytes else {
            throw XrayCoreError.packetBatchTooLarge(
                requestedBytes: byteCount,
                maximumBytes: maximumPacketBatchBytes
            )
        }
        return byteCount
    }

    public func stats() throws -> XrayTunStatsSnapshot {
        try withDataPathHandle { handle in
            var error: OpaquePointer?
            var stats = XrayTunStats()
            stats.struct_size = MemoryLayout<XrayTunStats>.size
            try check(xray_tun_stats(handle, &stats, &error), error: error)
            return XrayTunStatsSnapshot(
                inboundPackets: stats.inbound_packets,
                outboundPackets: stats.outbound_packets,
                droppedPackets: stats.dropped_packets,
                inboundDroppedPackets: stats.inbound_dropped_packets,
                outboundDroppedPackets: stats.outbound_dropped_packets,
                tcpStackToRemoteBytes: stats.tcp_stack_to_remote_bytes,
                tcpRemoteWrittenBytes: stats.tcp_remote_written_bytes,
                tcpRemoteReadBytes: stats.tcp_remote_read_bytes,
                tcpBackpressureEvents: stats.tcp_backpressure_events,
                tcpStackToRemoteBackpressureEvents: stats.tcp_stack_to_remote_backpressure_events,
                tcpRemoteToStackBackpressureEvents: stats.tcp_remote_to_stack_backpressure_events,
                tcpRemoteWriteBatches: stats.tcp_remote_write_batches,
                tcpRemoteWriteBatchMessages: stats.tcp_remote_write_batch_messages,
                tcpRemoteWriteBatchMaxMessages: stats.tcp_remote_write_batch_max_messages,
                tcpRemoteWriteBatchMaxBytes: stats.tcp_remote_write_batch_max_bytes,
                tcpRemoteWriteWaitEvents: stats.tcp_remote_write_wait_events,
                tcpRemoteWriteWaitDurationMsTotal: stats.tcp_remote_write_wait_ms_total,
                tcpRemoteWriteWaitDurationMsMax: stats.tcp_remote_write_wait_ms_max,
                tcpRemoteFlushWaitEvents: stats.tcp_remote_flush_wait_events,
                tcpRemoteFlushWaitDurationMsTotal: stats.tcp_remote_flush_wait_ms_total,
                tcpRemoteFlushWaitDurationMsMax: stats.tcp_remote_flush_wait_ms_max,
                tcpPendingRemoteBytes: stats.tcp_pending_remote_bytes,
                tcpPendingRemoteFlows: stats.tcp_pending_remote_flows,
                tcpPendingRemoteMaxBytes: stats.tcp_pending_remote_max_bytes,
                tcpPendingUploadBytes: stats.tcp_pending_upload_bytes,
                tcpPendingUploadMaxBytes: stats.tcp_pending_upload_max_bytes,
                tcpPendingTotalBytes: stats.tcp_pending_total_bytes,
                tcpRemoteBufferLimitBytes: stats.tcp_remote_buffer_limit_bytes,
                tcpBufferHardLimitBytes: stats.tcp_buffer_hard_limit_bytes,
                tcpRemoteBufferPressureActive: stats.tcp_remote_buffer_pressure_active != 0,
                tcpRemoteWriteErrors: stats.tcp_remote_write_errors,
                tcpRemoteClosedEvents: stats.tcp_remote_closed_events,
                tcpRemoteReadErrors: stats.tcp_remote_read_errors,
                tcpOpenErrors: stats.tcp_open_errors,
                tcpOpenEvents: stats.tcp_open_events,
                tcpOpenDurationMsTotal: stats.tcp_open_duration_ms_total,
                tcpOpenDurationMsMax: stats.tcp_open_duration_ms_max,
                tcpFirstByteEvents: stats.tcp_first_byte_events,
                tcpFirstByteDurationMsTotal: stats.tcp_first_byte_duration_ms_total,
                tcpFirstByteDurationMsMax: stats.tcp_first_byte_duration_ms_max,
                tcp443OpenEvents: stats.tcp443_open_events,
                tcp443OpenDurationMsTotal: stats.tcp443_open_duration_ms_total,
                tcp443OpenDurationMsMax: stats.tcp443_open_duration_ms_max,
                tcp443FirstByteEvents: stats.tcp443_first_byte_events,
                tcp443FirstByteDurationMsTotal: stats.tcp443_first_byte_duration_ms_total,
                tcp443FirstByteDurationMsMax: stats.tcp443_first_byte_duration_ms_max,
                activeTCPFlows: stats.active_tcp_flows,
                activeUDPFlows: stats.active_udp_flows,
                udpFlowLimit: stats.udp_flow_limit,
                udpBudgetDrops: stats.udp_budget_drops,
                udpEvictedFlows: stats.udp_evicted_flows,
                udpChannelDroppedPackets: stats.udp_channel_dropped_packets,
                udpRemoteOpenEvents: stats.udp_remote_open_events,
                udpRemoteUDP443OpenEvents: stats.udp_remote_udp443_open_events,
                udpRemoteWrittenBytes: stats.udp_remote_written_bytes,
                udpRemoteReadBytes: stats.udp_remote_read_bytes,
                udpOpenErrors: stats.udp_open_errors,
                udpVisionUDP443Rejections: stats.udp_vision_udp443_rejections,
                udpRemoteWriteErrors: stats.udp_remote_write_errors,
                udpRemoteReadErrors: stats.udp_remote_read_errors,
                udpRemoteClosedEvents: stats.udp_remote_closed_events,
                udpQuicBlockedPackets: stats.udp_quic_blocked_packets,
                inboundQueueDepth: stats.inbound_queue_depth,
                outboundQueueDepth: stats.outbound_queue_depth,
                inboundQueueMaxPackets: stats.inbound_queue_max_packets,
                outboundQueueMaxPackets: stats.outbound_queue_max_packets,
                tunFdWriteBatches: stats.tun_fd_write_batches,
                tunFdWriteBatchPackets: stats.tun_fd_write_batch_packets,
                tunFdWriteBatchMaxPackets: stats.tun_fd_write_batch_max_packets,
                tunFdReadLoopExits: stats.tun_fd_read_loop_exits,
                tunFdWriteLoopExits: stats.tun_fd_write_loop_exits,
                tunFdTransientIoErrors: stats.tun_fd_transient_io_errors
            )
        }
    }

    public func pollTcpSlowFlowEvents(maxEvents: Int = 16) throws -> [XrayTcpSlowFlowEventSnapshot] {
        try withDataPathHandle { handle in
            var events: [XrayTcpSlowFlowEventSnapshot] = []
            while events.count < maxEvents {
                var error: OpaquePointer?
                var event = XrayTcpSlowFlowEvent()
                var targetWritten = 0
                var targetBuffer = [CChar](repeating: 0, count: 256)
                let status = targetBuffer.withUnsafeMutableBufferPointer { mutableBuffer in
                    xray_tun_poll_tcp_slow_flow_event(
                        handle,
                        &event,
                        mutableBuffer.baseAddress,
                        mutableBuffer.count,
                        &targetWritten,
                        &error
                    )
                }

                if status == XRAY_STATUS_NO_PACKET {
                    return events
                }

                try check(status, error: error)
                events.append(
                    XrayTcpSlowFlowEventSnapshot(
                        kind: event.kind.snapshotKind,
                        target: String(cString: targetBuffer),
                        openDurationMs: event.open_duration_ms,
                        firstByteDurationMs: event.first_byte_duration_ms
                    )
                )
            }
            return events
        }
    }

    public func pollTcpFlowSummaryEvents(maxEvents: Int = 16) throws -> [XrayTcpFlowSummaryEventSnapshot] {
        try withDataPathHandle { handle in
            var events: [XrayTcpFlowSummaryEventSnapshot] = []
            while events.count < maxEvents {
                var error: OpaquePointer?
                var event = XrayTcpFlowSummaryEvent()
                var targetWritten = 0
                var targetBuffer = [CChar](repeating: 0, count: 256)
                var outboundTagWritten = 0
                var outboundTagBuffer = [CChar](repeating: 0, count: 64)
                let status = targetBuffer.withUnsafeMutableBufferPointer { targetMutableBuffer in
                    outboundTagBuffer.withUnsafeMutableBufferPointer { outboundTagMutableBuffer in
                        xray_tun_poll_tcp_flow_summary_event(
                            handle,
                            &event,
                            targetMutableBuffer.baseAddress,
                            targetMutableBuffer.count,
                            &targetWritten,
                            outboundTagMutableBuffer.baseAddress,
                            outboundTagMutableBuffer.count,
                            &outboundTagWritten,
                            &error
                        )
                    }
                }

                if status == XRAY_STATUS_NO_PACKET {
                    return events
                }

                try check(status, error: error)
                let outboundTag = String(cString: outboundTagBuffer)
                events.append(
                    XrayTcpFlowSummaryEventSnapshot(
                        target: String(cString: targetBuffer),
                        outboundTag: outboundTag.isEmpty ? nil : outboundTag,
                        closed: event.closed != 0,
                        durationMs: event.duration_ms,
                        openDurationMs: event.open_duration_ms,
                        firstByteDurationMs: event.first_byte_duration_ms,
                        remoteReadBytes: event.remote_read_bytes,
                        msTo64KiB: event.ms_to_64kib,
                        msTo128KiB: event.ms_to_128kib,
                        msTo256KiB: event.ms_to_256kib,
                        msTo512KiB: event.ms_to_512kib,
                        msTo1MiB: event.ms_to_1mib
                    )
                )
            }
            return events
        }
    }

    public func pollTcpRemoteWriteSlowEvents(maxEvents: Int = 16) throws -> [XrayTcpRemoteWriteSlowEventSnapshot] {
        try withDataPathHandle { handle in
            var events: [XrayTcpRemoteWriteSlowEventSnapshot] = []
            while events.count < maxEvents {
                var error: OpaquePointer?
                var event = XrayTcpRemoteWriteSlowEvent()
                var targetWritten = 0
                var targetBuffer = [CChar](repeating: 0, count: 256)
                var outboundTagWritten = 0
                var outboundTagBuffer = [CChar](repeating: 0, count: 64)
                let status = targetBuffer.withUnsafeMutableBufferPointer { targetMutableBuffer in
                    outboundTagBuffer.withUnsafeMutableBufferPointer { outboundTagMutableBuffer in
                        xray_tun_poll_tcp_remote_write_slow_event(
                            handle,
                            &event,
                            targetMutableBuffer.baseAddress,
                            targetMutableBuffer.count,
                            &targetWritten,
                            outboundTagMutableBuffer.baseAddress,
                            outboundTagMutableBuffer.count,
                            &outboundTagWritten,
                            &error
                        )
                    }
                }

                if status == XRAY_STATUS_NO_PACKET {
                    return events
                }

                try check(status, error: error)
                let outboundTag = String(cString: outboundTagBuffer)
                events.append(
                    XrayTcpRemoteWriteSlowEventSnapshot(
                        target: String(cString: targetBuffer),
                        outboundTag: outboundTag.isEmpty ? nil : outboundTag,
                        durationMs: event.duration_ms,
                        bytes: event.bytes,
                        messages: event.messages
                    )
                )
            }
            return events
        }
    }

    public func pollTcpOpenErrorEvents(maxEvents: Int = 16) throws -> [XrayTcpOpenErrorEventSnapshot] {
        try withDataPathHandle { handle in
            var events: [XrayTcpOpenErrorEventSnapshot] = []
            while events.count < maxEvents {
                var error: OpaquePointer?
                var event = XrayTcpOpenErrorEvent()
                var targetWritten = 0
                var targetBuffer = [CChar](repeating: 0, count: 256)
                var outboundTagWritten = 0
                var outboundTagBuffer = [CChar](repeating: 0, count: 64)
                var errorMessageWritten = 0
                var errorMessageBuffer = [CChar](repeating: 0, count: 512)
                let status = targetBuffer.withUnsafeMutableBufferPointer { targetMutableBuffer in
                    outboundTagBuffer.withUnsafeMutableBufferPointer { outboundTagMutableBuffer in
                        errorMessageBuffer.withUnsafeMutableBufferPointer { errorMessageMutableBuffer in
                            xray_tun_poll_tcp_open_error_event(
                                handle,
                                &event,
                                targetMutableBuffer.baseAddress,
                                targetMutableBuffer.count,
                                &targetWritten,
                                outboundTagMutableBuffer.baseAddress,
                                outboundTagMutableBuffer.count,
                                &outboundTagWritten,
                                errorMessageMutableBuffer.baseAddress,
                                errorMessageMutableBuffer.count,
                                &errorMessageWritten,
                                &error
                            )
                        }
                    }
                }

                if status == XRAY_STATUS_NO_PACKET {
                    return events
                }

                try check(status, error: error)
                let outboundTag = String(cString: outboundTagBuffer)
                events.append(
                    XrayTcpOpenErrorEventSnapshot(
                        target: String(cString: targetBuffer),
                        outboundTag: outboundTag.isEmpty ? nil : outboundTag,
                        error: String(cString: errorMessageBuffer)
                    )
                )
            }
            return events
        }
    }

    public func pollUdpSlowFlowEvents(maxEvents: Int = 16) throws -> [XrayUdpSlowFlowEventSnapshot] {
        try withDataPathHandle { handle in
            var events: [XrayUdpSlowFlowEventSnapshot] = []
            while events.count < maxEvents {
                var error: OpaquePointer?
                var event = XrayUdpSlowFlowEvent()
                var targetWritten = 0
                var targetBuffer = [CChar](repeating: 0, count: 256)
                let status = targetBuffer.withUnsafeMutableBufferPointer { mutableBuffer in
                    xray_tun_poll_udp_slow_flow_event(
                        handle,
                        &event,
                        mutableBuffer.baseAddress,
                        mutableBuffer.count,
                        &targetWritten,
                        &error
                    )
                }

                if status == XRAY_STATUS_NO_PACKET {
                    return events
                }

                try check(status, error: error)
                events.append(
                    XrayUdpSlowFlowEventSnapshot(
                        target: String(cString: targetBuffer),
                        firstResponseDurationMs: event.first_response_duration_ms,
                        writtenBytes: event.written_bytes,
                        readBytes: event.read_bytes
                    )
                )
            }
            return events
        }
    }

    public func pollUdpResponseGapEvents(maxEvents: Int = 16) throws -> [XrayUdpResponseGapEventSnapshot] {
        try withDataPathHandle { handle in
            var events: [XrayUdpResponseGapEventSnapshot] = []
            while events.count < maxEvents {
                var error: OpaquePointer?
                var event = XrayUdpResponseGapEvent()
                var targetWritten = 0
                var targetBuffer = [CChar](repeating: 0, count: 256)
                let status = targetBuffer.withUnsafeMutableBufferPointer { mutableBuffer in
                    xray_tun_poll_udp_response_gap_event(
                        handle,
                        &event,
                        mutableBuffer.baseAddress,
                        mutableBuffer.count,
                        &targetWritten,
                        &error
                    )
                }

                if status == XRAY_STATUS_NO_PACKET {
                    return events
                }

                try check(status, error: error)
                events.append(
                    XrayUdpResponseGapEventSnapshot(
                        target: String(cString: targetBuffer),
                        responseGapDurationMs: event.response_gap_duration_ms,
                        writtenBytes: event.written_bytes,
                        readBytes: event.read_bytes
                    )
                )
            }
            return events
        }
    }

    public func pollUdpQuicBlockedEvents(maxEvents: Int = 16) throws -> [XrayUdpQuicBlockedEventSnapshot] {
        try withDataPathHandle { handle in
            var events: [XrayUdpQuicBlockedEventSnapshot] = []
            while events.count < maxEvents {
                var error: OpaquePointer?
                var event = XrayUdpQuicBlockedEvent()
                var targetWritten = 0
                var targetBuffer = [CChar](repeating: 0, count: 256)
                let status = targetBuffer.withUnsafeMutableBufferPointer { mutableBuffer in
                    xray_tun_poll_udp_quic_blocked_event(
                        handle,
                        &event,
                        mutableBuffer.baseAddress,
                        mutableBuffer.count,
                        &targetWritten,
                        &error
                    )
                }

                if status == XRAY_STATUS_NO_PACKET {
                    return events
                }

                try check(status, error: error)
                events.append(
                    XrayUdpQuicBlockedEventSnapshot(
                        target: String(cString: targetBuffer),
                        bytes: event.bytes
                    )
                )
            }
            return events
        }
    }

    private func withLifecycleHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        try callGate.withLifecycle {
            guard let handle else {
                throw XrayCoreError.missingHandle
            }
            return try body(handle)
        }
    }

    private func withSharedHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        try callGate.withDataPath {
            guard let handle else {
                throw XrayCoreError.missingHandle
            }
            return try body(handle)
        }
    }

    private func withDataPathHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        try withSharedHandle { handle in
            guard dataPathEnabled else {
                throw XrayCoreError.notRunning
            }
            return try body(handle)
        }
    }

    private enum SnapshotKind {
        case selection
        case health
        case connections
        case accounting
    }

    private func snapshotJSON(handle: OpaquePointer, kind: SnapshotKind) throws -> Data {
        var requiredLength = 0
        var error: OpaquePointer?
        let queryStatus: XrayStatus
        switch kind {
        case .selection:
            queryStatus = xray_core_outbound_selection_snapshot_json(
                handle,
                nil,
                0,
                &requiredLength,
                &error
            )
        case .health:
            queryStatus = xray_core_outbound_health_snapshot_json(
                handle,
                nil,
                0,
                &requiredLength,
                &error
            )
        case .connections:
            queryStatus = xray_core_connection_snapshot_json(
                handle,
                nil,
                0,
                &requiredLength,
                &error
            )
        case .accounting:
            queryStatus = xray_core_outbound_accounting_snapshot_json(
                handle,
                nil,
                0,
                &requiredLength,
                &error
            )
        }
        try check(queryStatus, error: error)

        var buffer = [CChar](repeating: 0, count: requiredLength + 1)
        var written = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            switch kind {
            case .selection:
                return xray_core_outbound_selection_snapshot_json(
                    handle,
                    pointer.baseAddress,
                    pointer.count,
                    &written,
                    &error
                )
            case .health:
                return xray_core_outbound_health_snapshot_json(
                    handle,
                    pointer.baseAddress,
                    pointer.count,
                    &written,
                    &error
                )
            case .connections:
                return xray_core_connection_snapshot_json(
                    handle,
                    pointer.baseAddress,
                    pointer.count,
                    &written,
                    &error
                )
            case .accounting:
                return xray_core_outbound_accounting_snapshot_json(
                    handle,
                    pointer.baseAddress,
                    pointer.count,
                    &written,
                    &error
                )
            }
        }
        try check(status, error: error)
        guard written <= requiredLength else {
            throw XrayCoreError.invalidUtf8
        }
        return Data(buffer.prefix(written).map { UInt8(bitPattern: $0) })
    }

    private func requireCapability(_ capability: XrayFFICapabilities) throws {
        guard Self.ffiInfo.supports(capability) else {
            throw XrayCoreError.status(
                code: XRAY_STATUS_RUNTIME_ERROR,
                message: "required xray FFI capability is unavailable"
            )
        }
    }

    private func check(_ status: XrayStatus, error: OpaquePointer?) throws {
        guard status != XRAY_STATUS_OK else {
            if let error {
                xray_error_free(error)
            }
            return
        }

        throw XrayCore.takeError(error, fallbackStatus: status)
    }

    private func configWarnings(handle: OpaquePointer) throws -> [String] {
        var requiredLength = 0
        var error: OpaquePointer?
        let queryStatus = xray_core_config_warnings(
            handle,
            nil,
            0,
            &requiredLength,
            &error
        )
        if queryStatus == XRAY_STATUS_BUFFER_TOO_SMALL {
            if let error {
                xray_error_free(error)
            }
            error = nil
        } else {
            try check(queryStatus, error: error)
        }
        guard requiredLength > 0 else {
            return []
        }

        var buffer = [CChar](repeating: 0, count: requiredLength + 1)
        var written = 0
        let status = buffer.withUnsafeMutableBufferPointer { pointer in
            xray_core_config_warnings(
                handle,
                pointer.baseAddress,
                pointer.count,
                &written,
                &error
            )
        }
        try check(status, error: error)
        guard written <= requiredLength,
              let warnings = String(
                  bytes: buffer.prefix(written).map { UInt8(bitPattern: $0) },
                  encoding: .utf8
              )
        else {
            throw XrayCoreError.invalidUtf8
        }
        return warnings
            .split(whereSeparator: \.isNewline)
            .map(String.init)
            .filter { !$0.isEmpty }
    }

    private static func takeError(
        _ error: OpaquePointer?,
        fallbackStatus: XrayStatus = XRAY_STATUS_PANIC
    ) -> XrayCoreError {
        defer {
            if let error {
                xray_error_free(error)
            }
        }

        guard let error else {
            return .status(code: fallbackStatus, message: "xray operation failed")
        }
        let code = xray_error_code(error)
        guard let messagePointer = xray_error_message(error) else {
            return .status(code: code, message: "xray operation failed")
        }
        guard let message = String(validatingUTF8: messagePointer) else {
            return .invalidUtf8
        }

        return .status(code: code, message: message)
    }
}
