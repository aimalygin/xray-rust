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
    public let tcpPendingRemoteBytes: UInt64
    public let tcpPendingRemoteFlows: UInt64
    public let tcpPendingRemoteMaxBytes: UInt64
    public let tcpRemoteBufferLimitBytes: UInt64
    public let tcpRemoteBufferPressureActive: Bool
    public let tcpRemoteWriteErrors: UInt64
    public let tcpRemoteClosedEvents: UInt64
    public let tcpRemoteReadErrors: UInt64
    public let tcpOpenErrors: UInt64
}

public final class XrayCore: @unchecked Sendable {
    private let lock = NSLock()
    private var handle: OpaquePointer?

    public convenience init(
        configJSON: String,
        borrowedDarwinTunFileDescriptor fd: Int32
    ) throws {
        try self.init(
            configJSON: configJSON,
            tunFileDescriptor: fd,
            tunPacketFormat: XRAY_TUN_FD_PACKET_FORMAT_DARWIN_UTUN,
            tunClosePolicy: XRAY_TUN_FD_CLOSE_POLICY_BORROWED
        )
    }

    public init(
        configJSON: String,
        socketProtectCallback: XraySocketProtectCallback? = nil,
        socketProtectUserData: UnsafeMutableRawPointer? = nil,
        tunFileDescriptor: Int32? = nil,
        tunPacketFormat: XrayTunFdPacketFormat = XRAY_TUN_FD_PACKET_FORMAT_RAW_IP,
        tunClosePolicy: XrayTunFdClosePolicy = XRAY_TUN_FD_CLOSE_POLICY_BORROWED
    ) throws {
        var error: OpaquePointer?
        XrayMobileLog.info(
            "Core",
            "Creating core configBytes=\(configJSON.utf8.count) socketProtect=\(socketProtectCallback != nil) tunFd=\(tunFileDescriptor.map(String.init) ?? "none")"
        )
        guard let handle = xray_core_new(&error) else {
            let coreError = XrayCore.takeError(error)
            XrayMobileLog.error("Core", "xray_core_new failed: \(coreError.description)")
            throw coreError
        }

        self.handle = handle
        do {
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
        try withHandle { handle in
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
        try withHandle { handle in
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
                tcpPendingRemoteBytes: stats.tcp_pending_remote_bytes,
                tcpPendingRemoteFlows: stats.tcp_pending_remote_flows,
                tcpPendingRemoteMaxBytes: stats.tcp_pending_remote_max_bytes,
                tcpRemoteBufferLimitBytes: stats.tcp_remote_buffer_limit_bytes,
                tcpRemoteBufferPressureActive: stats.tcp_remote_buffer_pressure_active != 0,
                tcpRemoteWriteErrors: stats.tcp_remote_write_errors,
                tcpRemoteClosedEvents: stats.tcp_remote_closed_events,
                tcpRemoteReadErrors: stats.tcp_remote_read_errors,
                tcpOpenErrors: stats.tcp_open_errors
            )
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
