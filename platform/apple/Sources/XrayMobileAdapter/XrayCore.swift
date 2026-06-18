import Foundation
import XrayRust

private enum XrayMobileLog {
    static func info(_ category: String, _ message: String) {
        NSLog("[XrayRust][\(category)] \(message)")
    }

    static func error(_ category: String, _ message: String) {
        NSLog("[XrayRust][\(category)][error] \(message)")
    }
}

public enum XrayCoreError: Error, CustomStringConvertible {
    case status(code: XrayStatus, message: String)
    case missingHandle
    case invalidUtf8

    public var description: String {
        switch self {
        case let .status(code, message):
            return "xray status \(code): \(message)"
        case .missingHandle:
            return "xray core handle is missing"
        case .invalidUtf8:
            return "xray returned an invalid UTF-8 error message"
        }
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
}

public extension XrayTunStatsSnapshot {
    func debugLogMessages(prefix: String = "Debug stats") -> [String] {
        [
            "\(prefix) core inbound=\(inboundPackets) outbound=\(outboundPackets) dropped=\(droppedPackets) inboundDropped=\(inboundDroppedPackets) outboundDropped=\(outboundDroppedPackets) activeTCPFlows=\(activeTCPFlows) activeUDPFlows=\(activeUDPFlows)",
            "\(prefix) queues inboundQueueDepth=\(inboundQueueDepth) outboundQueueDepth=\(outboundQueueDepth) inboundQueueMaxPackets=\(inboundQueueMaxPackets) outboundQueueMaxPackets=\(outboundQueueMaxPackets) tunFdWriteBatches=\(tunFdWriteBatches) tunFdWriteBatchPackets=\(tunFdWriteBatchPackets) tunFdWriteBatchMaxPackets=\(tunFdWriteBatchMaxPackets)",
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
    private let lock = NSLock()
    private var handle: OpaquePointer?

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
        geodataSearchDirectory: URL? = nil,
        startupProbe: XrayStartupProbeOptions? = nil
    ) throws {
        try self.init(
            configJSON: configJSON,
            collectTcpTimings: collectTcpTimings,
            tunRuntimeProfile: tunRuntimeProfile,
            geodataSearchDirectory: geodataSearchDirectory,
            startupProbe: startupProbe,
            tunFileDescriptor: fd,
            tunPacketFormat: XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN,
            tunClosePolicy: XRAY_TUN_FD_CLOSE_POLICY_BORROWED
        )
    }

    public init(
        configJSON: String,
        collectTcpTimings: Bool = false,
        tunRuntimeProfile: XrayTunRuntimeProfile = XRAY_TUN_RUNTIME_PROFILE_DEFAULT,
        geodataSearchDirectory: URL? = nil,
        startupProbe: XrayStartupProbeOptions? = nil,
        socketProtectCallback: XraySocketProtectCallback? = nil,
        socketProtectUserData: UnsafeMutableRawPointer? = nil,
        tunFileDescriptor: Int32? = nil,
        tunPacketFormat: XrayTunFdPacketFormat = XRAY_TUN_FD_PACKET_FORMAT_RAW_IP,
        tunClosePolicy: XrayTunFdClosePolicy = XRAY_TUN_FD_CLOSE_POLICY_BORROWED
    ) throws {
        var error: OpaquePointer?
        XrayMobileLog.info(
            "Core",
            "Creating core configBytes=\(configJSON.utf8.count) socketProtect=\(socketProtectCallback != nil) tunFd=\(tunFileDescriptor != nil ? "present" : "none") collectTcpTimings=\(collectTcpTimings) tunRuntimeProfile=\(tunRuntimeProfile.rawValue)"
        )
        guard let handle = xray_core_new(&error) else {
            let coreError = XrayCore.takeError(error)
            XrayMobileLog.error("Core", "xray_core_new failed: \(coreError.description)")
            throw coreError
        }

        self.handle = handle
        do {
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
            if socketProtectCallback != nil {
                try check(
                    xray_core_set_socket_protect_callback(
                        handle,
                        socketProtectCallback,
                        socketProtectUserData,
                        &error
                    ),
                    error: error
                )
            }
            if let tunFileDescriptor {
                try check(
                    xray_core_set_tun_fd(
                        handle,
                        tunFileDescriptor,
                        tunPacketFormat,
                        tunClosePolicy,
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
                xray_core_set_tun_runtime_profile(handle, tunRuntimeProfile, &error),
                error: error
            )
            if let geodataSearchDirectory {
                try geodataSearchDirectory.path.withCString { pointer in
                    try check(
                        xray_core_set_geodata_search_dir(handle, pointer, &error),
                        error: error
                    )
                }
            }
            try configJSON.withCString { pointer in
                try check(xray_core_load_config_json(handle, pointer, &error), error: error)
            }
            XrayMobileLog.info("Core", "Core config loaded")
        } catch {
            XrayMobileLog.error("Core", "Core init failed: \(error)")
            xray_core_free(handle)
            self.handle = nil
            throw error
        }
    }

    deinit {
        lock.lock()
        let handle = self.handle
        self.handle = nil
        lock.unlock()

        if let handle {
            XrayMobileLog.info("Core", "Deinit stopping and freeing core")
            _ = xray_core_stop(handle, nil)
            xray_core_free(handle)
        }
    }

    public func start() throws {
        do {
            try withHandle { handle in
                var error: OpaquePointer?
                XrayMobileLog.info("Core", "Starting core")
                try check(xray_core_start(handle, &error), error: error)
                XrayMobileLog.info("Core", "Core started")
            }
        } catch {
            XrayMobileLog.error("Core", "Core start failed: \(error)")
            throw error
        }
    }

    public func stop() throws {
        do {
            try withHandle { handle in
                var error: OpaquePointer?
                XrayMobileLog.info("Core", "Stopping core")
                try check(xray_core_stop(handle, &error), error: error)
                XrayMobileLog.info("Core", "Core stopped")
            }
        } catch {
            XrayMobileLog.error("Core", "Core stop failed: \(error)")
            throw error
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
        try withDataPathHandle { handle in
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
        try withDataPathHandle { handle in
            var error: OpaquePointer?
            var buffer = [UInt8](repeating: 0, count: maxPackets * maxPacketBytes)
            var lengths = [Int](repeating: 0, count: maxPackets)
            var packetCount = 0
            let status = buffer.withUnsafeMutableBufferPointer { bufferPointer in
                lengths.withUnsafeMutableBufferPointer { lengthsPointer in
                    xray_tun_poll_packets(
                        handle,
                        bufferPointer.baseAddress,
                        bufferPointer.count,
                        lengthsPointer.baseAddress,
                        maxPackets,
                        &packetCount,
                        waitMilliseconds,
                        &error
                    )
                }
            }

            if status == XRAY_STATUS_NO_PACKET {
                return []
            }

            try check(status, error: error)
            var packets = [Data]()
            packets.reserveCapacity(packetCount)
            var offset = 0
            for index in 0..<packetCount {
                let length = lengths[index]
                packets.append(Data(buffer[offset..<(offset + length)]))
                offset += length
            }
            return packets
        }
    }

    public func stats() throws -> XrayTunStatsSnapshot {
        try withHandle { handle in
            var error: OpaquePointer?
            var stats = XrayTunStats()
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
                tunFdWriteBatchMaxPackets: stats.tun_fd_write_batch_max_packets
            )
        }
    }

    public func pollTcpSlowFlowEvents(maxEvents: Int = 16) throws -> [XrayTcpSlowFlowEventSnapshot] {
        try withHandle { handle in
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
        try withHandle { handle in
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
        try withHandle { handle in
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
        try withHandle { handle in
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
        try withHandle { handle in
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
        try withHandle { handle in
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
        try withHandle { handle in
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

    private func withHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }

        guard let handle else {
            throw XrayCoreError.missingHandle
        }
        return try body(handle)
    }

    /// Reads the handle under the lock but runs `body` outside it, so blocking
    /// data-path calls (pollPackets) do not stall pushPacket or stats. Safe
    /// because the handle is only freed in deinit, which cannot run while the
    /// caller holds a strong reference, and the FFI data-path entry points
    /// accept concurrent calls on the same handle.
    private func withDataPathHandle<T>(_ body: (OpaquePointer) throws -> T) throws -> T {
        lock.lock()
        let handle = self.handle
        lock.unlock()

        guard let handle else {
            throw XrayCoreError.missingHandle
        }
        return try body(handle)
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
