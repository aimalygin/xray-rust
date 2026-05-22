import Foundation
import XrayRust

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
}

public final class XrayCore: @unchecked Sendable {
    private let lock = NSLock()
    private var handle: UnsafeMutablePointer<XrayCoreHandle>?

    public init(
        configJSON: String,
        socketProtectCallback: XraySocketProtectCallback? = nil,
        socketProtectUserData: UnsafeMutableRawPointer? = nil
    ) throws {
        var error: UnsafeMutablePointer<XrayError>?
        guard let handle = xray_core_new(&error) else {
            throw XrayCore.takeError(error)
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
            try configJSON.withCString { pointer in
                try check(xray_core_load_config_json(handle, pointer, &error), error: error)
            }
        } catch {
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
            _ = xray_core_stop(handle, nil)
            xray_core_free(handle)
        }
    }

    public func start() throws {
        try withHandle { handle in
            var error: UnsafeMutablePointer<XrayError>?
            try check(xray_core_start(handle, &error), error: error)
        }
    }

    public func stop() throws {
        try withHandle { handle in
            var error: UnsafeMutablePointer<XrayError>?
            try check(xray_core_stop(handle, &error), error: error)
        }
    }

    public func pushPacket(_ packet: Data) throws {
        try withHandle { handle in
            var error: UnsafeMutablePointer<XrayError>?
            try packet.withUnsafeBytes { rawBuffer in
                let pointer = rawBuffer.bindMemory(to: UInt8.self).baseAddress
                try check(
                    xray_tun_push_packet(handle, pointer, packet.count, &error),
                    error: error
                )
            }
        }
    }

    public func pollPacket(maxBytes: Int = 65_535) throws -> Data? {
        try withHandle { handle in
            var error: UnsafeMutablePointer<XrayError>?
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
            var error: UnsafeMutablePointer<XrayError>?
            var stats = XrayTunStats()
            try check(xray_tun_stats(handle, &stats, &error), error: error)
            return XrayTunStatsSnapshot(
                inboundPackets: stats.inbound_packets,
                outboundPackets: stats.outbound_packets,
                droppedPackets: stats.dropped_packets
            )
        }
    }

    private func withHandle<T>(_ body: (UnsafeMutablePointer<XrayCoreHandle>) throws -> T) throws -> T {
        lock.lock()
        defer { lock.unlock() }

        guard let handle else {
            throw XrayCoreError.missingHandle
        }
        return try body(handle)
    }

    private func check(_ status: XrayStatus, error: UnsafeMutablePointer<XrayError>?) throws {
        guard status != XRAY_STATUS_OK else {
            if let error {
                xray_error_free(error)
            }
            return
        }

        throw XrayCore.takeError(error, fallbackStatus: status)
    }

    private static func takeError(
        _ error: UnsafeMutablePointer<XrayError>?,
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
