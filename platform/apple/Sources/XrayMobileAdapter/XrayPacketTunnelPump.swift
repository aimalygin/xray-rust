#if canImport(NetworkExtension)
import Darwin
import Foundation
import NetworkExtension

private enum XrayMobileLog {
    static func info(_ category: String, _ message: String) {
        NSLog("[XrayRust][\(category)] \(message)")
    }

    static func error(_ category: String, _ message: String) {
        NSLog("[XrayRust][\(category)][error] \(message)")
    }
}

@available(iOS 9.0, tvOS 17.0, macOS 10.11, *)
public struct XrayPacketTunnelPumpOptions: Equatable, Sendable {
    public var blockQUIC: Bool

    public init(blockQUIC: Bool = false) {
        self.blockQUIC = blockQUIC
    }
}

@available(iOS 9.0, tvOS 17.0, macOS 10.11, *)
public final class XrayPacketTunnelPump: @unchecked Sendable {
    private static let maxPacketsPerPoll = 64
    private static let pollWaitMilliseconds: UInt32 = 250
    private static let pollErrorBackoffSeconds: TimeInterval = 0.05

    private let provider: NEPacketTunnelProvider
    private let core: XrayCore
    private let queue: DispatchQueue
    private let options: XrayPacketTunnelPumpOptions
    private let lock = NSLock()
    private let pollLoopExited = DispatchSemaphore(value: 0)
    private var running = false
    private var pushPacketErrorCount = 0
    private var pollPacketErrorCount = 0
    private var writePacketErrorCount = 0
    private var readBatchCount: UInt64 = 0
    private var readPacketCount: UInt64 = 0
    private var readByteCount: UInt64 = 0
    private var writtenPacketCount: UInt64 = 0
    private var writtenByteCount: UInt64 = 0
    private var lastStatsLog = Date.distantPast

    public init(
        provider: NEPacketTunnelProvider,
        core: XrayCore,
        options: XrayPacketTunnelPumpOptions = XrayPacketTunnelPumpOptions(),
        queue: DispatchQueue = DispatchQueue(label: "org.xrayrust.packet-tunnel-pump")
    ) {
        self.provider = provider
        self.core = core
        self.options = options
        self.queue = queue
    }

    public func start() {
        lock.lock()
        guard !running else {
            lock.unlock()
            return
        }
        running = true
        pushPacketErrorCount = 0
        pollPacketErrorCount = 0
        writePacketErrorCount = 0
        readBatchCount = 0
        readPacketCount = 0
        readByteCount = 0
        writtenPacketCount = 0
        writtenByteCount = 0
        lastStatsLog = Date()
        lock.unlock()

        XrayMobileLog.info("PacketPump", "Starting packet pump blockQUIC=\(options.blockQUIC)")
        readPackets()
        pollPackets()
    }

    public func stop() {
        lock.lock()
        let wasRunning = running
        running = false
        lock.unlock()
        XrayMobileLog.info("PacketPump", "Stopping packet pump")
        guard wasRunning else {
            return
        }
        // Join the poll loop so the provider can stop the core without a
        // blocking poll still holding the FFI data path.
        let deadline = DispatchTime.now() + .milliseconds(Int(Self.pollWaitMilliseconds) * 4)
        if pollLoopExited.wait(timeout: deadline) == .timedOut {
            XrayMobileLog.error("PacketPump", "Poll loop did not exit before stop deadline")
        }
    }

    private func readPackets() {
        guard isRunning else {
            return
        }

        provider.packetFlow.readPackets { [weak self] packets, protocols in
            guard let self else {
                return
            }
            let byteCount = packets.reduce(0) { total, packet in
                total + packet.count
            }
            if let snapshot = self.recordReadPacketBatch(
                packetCount: packets.count,
                byteCount: byteCount
            ) {
                XrayMobileLog.info(
                    "PacketPump",
                    "Read packet batch=\(snapshot.readBatchCount) packets=\(packets.count) bytes=\(byteCount) protocols=\(Self.protocolSummary(protocols)) totals readPackets=\(snapshot.readPacketCount) readBytes=\(snapshot.readByteCount)"
                )
            }

            for packet in packets {
                // QUIC blocking happens once, inside the Rust core, which
                // also emits the ICMP port-unreachable reply on the outbound
                // queue; filtering here as well parsed every UDP packet twice.
                do {
                    try self.core.pushPacket(packet)
                } catch {
                    let count = self.incrementPushPacketErrorCount()
                    if Self.shouldLogPacketError(count) {
                        XrayMobileLog.error(
                            "PacketPump",
                            "pushPacket failed count=\(count) bytes=\(packet.count) error=\(error)"
                        )
                    }
                }
            }
            self.readPackets()
        }
    }

    private func pollPackets() {
        queue.async { [weak self] in
            guard let self else {
                return
            }

            // The poll blocks inside the core until a packet is queued (or the
            // wait expires), so the loop wakes immediately on traffic instead
            // of sleeping between polling passes.
            while self.isRunning {
                autoreleasepool {
                    self.pollAndWriteBatch()
                }
                self.logStatsIfNeeded()
            }
            self.pollLoopExited.signal()
            XrayMobileLog.info("PacketPump", "Packet pump poll loop exited")
        }
    }

    private func pollAndWriteBatch() {
        let packets: [Data]
        do {
            packets = try core.pollPackets(
                maxPackets: Self.maxPacketsPerPoll,
                waitMilliseconds: Self.pollWaitMilliseconds
            )
        } catch {
            let count = incrementPollPacketErrorCount()
            if Self.shouldLogPacketError(count) {
                XrayMobileLog.error(
                    "PacketPump",
                    "pollPackets failed count=\(count) error=\(error)"
                )
            }
            Thread.sleep(forTimeInterval: Self.pollErrorBackoffSeconds)
            return
        }

        guard !packets.isEmpty else {
            return
        }

        let protocols = packets.map { NSNumber(value: Self.protocolFamily(for: $0)) }
        let didWrite = provider.packetFlow.writePackets(packets, withProtocols: protocols)
        let byteCount = packets.reduce(0) { $0 + $1.count }
        if let snapshot = recordWrittenBatch(
            packetCount: packets.count,
            byteCount: byteCount,
            didWrite: didWrite
        ) {
            XrayMobileLog.info(
                "PacketPump",
                "Wrote packet batch packets=\(packets.count) bytes=\(byteCount) didWrite=\(didWrite) totals writtenPackets=\(snapshot.writtenPacketCount) writtenBytes=\(snapshot.writtenByteCount) writeErrors=\(snapshot.writePacketErrorCount)"
            )
        }
        if !didWrite {
            let count = currentWritePacketErrorCount()
            if Self.shouldLogPacketError(count) {
                XrayMobileLog.error(
                    "PacketPump",
                    "writePackets returned false count=\(count) packets=\(packets.count)"
                )
            }
        }
    }

    private var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    private func incrementPushPacketErrorCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        pushPacketErrorCount += 1
        return pushPacketErrorCount
    }

    private func incrementPollPacketErrorCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        pollPacketErrorCount += 1
        return pollPacketErrorCount
    }

    private func currentWritePacketErrorCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return writePacketErrorCount
    }

    private func recordReadPacketBatch(packetCount: Int, byteCount: Int) -> PacketPumpSnapshot? {
        lock.lock()
        defer { lock.unlock() }

        readBatchCount += 1
        readPacketCount += UInt64(packetCount)
        readByteCount += UInt64(byteCount)

        guard Self.shouldLogPacketEvent(readBatchCount) else {
            return nil
        }
        return snapshotLocked()
    }

    private func recordWrittenBatch(
        packetCount: Int,
        byteCount: Int,
        didWrite: Bool
    ) -> PacketPumpSnapshot? {
        lock.lock()
        defer { lock.unlock() }

        if didWrite {
            writtenPacketCount += UInt64(packetCount)
            writtenByteCount += UInt64(byteCount)
        } else {
            writePacketErrorCount += 1
        }

        guard !didWrite || Self.shouldLogPacketEvent(writtenPacketCount) else {
            return nil
        }
        return snapshotLocked()
    }

    private func logStatsIfNeeded() {
        let now = Date()
        let snapshot: PacketPumpSnapshot?
        lock.lock()
        if now.timeIntervalSince(lastStatsLog) >= 5 {
            lastStatsLog = now
            snapshot = snapshotLocked()
        } else {
            snapshot = nil
        }
        lock.unlock()

        guard let snapshot else {
            return
        }

        XrayMobileLog.info(
            "PacketPump",
            "Stats packetFlow readPackets=\(snapshot.readPacketCount) readBytes=\(snapshot.readByteCount) writtenPackets=\(snapshot.writtenPacketCount) writtenBytes=\(snapshot.writtenByteCount) pushErrors=\(snapshot.pushPacketErrorCount) pollErrors=\(snapshot.pollPacketErrorCount) writeErrors=\(snapshot.writePacketErrorCount)"
        )
        guard let coreStats = try? core.stats() else {
            XrayMobileLog.info("PacketPump", "Stats core unavailable")
            return
        }
        for message in coreStats.debugLogMessages(prefix: "Stats core") {
            XrayMobileLog.info("PacketPump", message)
        }
    }

    private func snapshotLocked() -> PacketPumpSnapshot {
        PacketPumpSnapshot(
            readBatchCount: readBatchCount,
            readPacketCount: readPacketCount,
            readByteCount: readByteCount,
            writtenPacketCount: writtenPacketCount,
            writtenByteCount: writtenByteCount,
            pushPacketErrorCount: pushPacketErrorCount,
            pollPacketErrorCount: pollPacketErrorCount,
            writePacketErrorCount: writePacketErrorCount
        )
    }

    private static func shouldLogPacketEvent(_ count: UInt64) -> Bool {
        count <= 5 || count.isMultiple(of: 50)
    }

    private static func shouldLogPacketError(_ count: Int) -> Bool {
        count <= 5 || count.isMultiple(of: 100)
    }

    private static func protocolSummary(_ protocols: [NSNumber]) -> String {
        let values = Set(protocols.map(\.int32Value)).sorted()
        return values.map(String.init).joined(separator: ",")
    }

    private static func protocolFamily(for packet: Data) -> Int32 {
        guard let first = packet.first else {
            return AF_INET
        }

        switch first >> 4 {
        case 6:
            return AF_INET6
        default:
            return AF_INET
        }
    }
}

private struct PacketPumpSnapshot {
    var readBatchCount: UInt64
    var readPacketCount: UInt64
    var readByteCount: UInt64
    var writtenPacketCount: UInt64
    var writtenByteCount: UInt64
    var pushPacketErrorCount: Int
    var pollPacketErrorCount: Int
    var writePacketErrorCount: Int
}
#endif
