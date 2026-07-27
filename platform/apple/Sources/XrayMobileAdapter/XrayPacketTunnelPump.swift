#if canImport(NetworkExtension)
import Darwin
import Foundation
import NetworkExtension

public enum XrayPacketTunnelPumpError: Error, Equatable, LocalizedError, Sendable {
    case persistentPollPacketFailures(consecutiveFailures: Int)
    case persistentWritePacketFailures(consecutiveFailures: Int)

    public var errorDescription: String? {
        switch self {
        case let .persistentPollPacketFailures(consecutiveFailures):
            return "Packet tunnel output polling failed \(consecutiveFailures) consecutive times."
        case let .persistentWritePacketFailures(consecutiveFailures):
            return "Packet tunnel output delivery failed \(consecutiveFailures) consecutive times."
        }
    }
}

enum XrayPacketTunnelPumpOperation: CaseIterable, Hashable, Sendable {
    case pollPackets
    case writePackets
}

final class XrayPacketTunnelFailureCircuitBreaker: @unchecked Sendable {
    private let lock = NSLock()
    private let maxConsecutiveFailures: Int
    private var isRunning = false
    private var didTrip = false
    private var consecutiveFailures: [XrayPacketTunnelPumpOperation: Int] = [:]

    init(maxConsecutiveFailures: Int) {
        precondition(maxConsecutiveFailures > 0)
        self.maxConsecutiveFailures = maxConsecutiveFailures
    }

    func start() {
        lock.lock()
        isRunning = true
        didTrip = false
        consecutiveFailures.removeAll(keepingCapacity: true)
        lock.unlock()
    }

    func stop() {
        lock.lock()
        isRunning = false
        lock.unlock()
    }

    func recordSuccess(_ operation: XrayPacketTunnelPumpOperation) {
        lock.lock()
        if isRunning, !didTrip {
            consecutiveFailures[operation] = 0
        }
        lock.unlock()
    }

    // The Rust FFI currently maps inbound QueueFull/backpressure to a generic
    // TUN error. Treat every push failure as a dropped packet; a tight burst
    // must never disconnect an otherwise healthy tunnel.
    func recordRecoverablePushFailure() -> XrayPacketTunnelPumpError? {
        nil
    }

    func recordFailure(
        _ operation: XrayPacketTunnelPumpOperation
    ) -> XrayPacketTunnelPumpError? {
        lock.lock()
        defer { lock.unlock() }
        guard isRunning, !didTrip else {
            return nil
        }

        let count = consecutiveFailures[operation, default: 0] + 1
        consecutiveFailures[operation] = count
        guard count >= maxConsecutiveFailures else {
            return nil
        }
        didTrip = true

        switch operation {
        case .pollPackets:
            return .persistentPollPacketFailures(consecutiveFailures: count)
        case .writePackets:
            return .persistentWritePacketFailures(consecutiveFailures: count)
        }
    }
}

final class XrayPacketTunnelTerminalFailureDelivery: @unchecked Sendable {
    private let lock = NSLock()
    private let queue: DispatchQueue
    private let handler: @Sendable (XrayPacketTunnelPumpError) -> Void
    private var isStopped = true
    private var isScheduled = false

    init(
        queue: DispatchQueue = DispatchQueue(
            label: "org.xrayrust.packet-tunnel-pump.terminal-failure"
        ),
        handler: @escaping @Sendable (XrayPacketTunnelPumpError) -> Void
    ) {
        self.queue = queue
        self.handler = handler
    }

    func start() {
        lock.lock()
        isStopped = false
        isScheduled = false
        lock.unlock()
    }

    func stop() {
        lock.lock()
        isStopped = true
        lock.unlock()
    }

    func submit(_ error: XrayPacketTunnelPumpError) {
        lock.lock()
        guard !isStopped, !isScheduled else {
            lock.unlock()
            return
        }
        isScheduled = true
        lock.unlock()

        queue.async { [self] in
            lock.lock()
            let shouldDeliver = !isStopped
            lock.unlock()
            if shouldDeliver {
                // Never call the handler while holding the delivery lock. The
                // handler may synchronously tear down the pump.
                handler(error)
            }
        }
    }
}

@available(iOS 9.0, tvOS 17.0, macOS 10.11, *)
public final class XrayPacketTunnelPump: @unchecked Sendable {
    private static let maxPacketsPerPoll = 64
    private static let maxPacketBytes = 1_500
    private static let pollWaitMilliseconds: UInt32 = 250
    private static let pollErrorBackoffSeconds: TimeInterval = 0.05
    private static let maxConsecutivePacketFailures = 8

    private let provider: NEPacketTunnelProvider
    private let core: XrayCore
    private let queue: DispatchQueue
    private let pollStorage: XrayPacketBatchPollStorage
    private let terminalFailureDelivery: XrayPacketTunnelTerminalFailureDelivery
    private let failureCircuitBreaker = XrayPacketTunnelFailureCircuitBreaker(
        maxConsecutiveFailures: XrayPacketTunnelPump.maxConsecutivePacketFailures
    )
    private let condition = NSCondition()
    private let pollLoopGroup = DispatchGroup()
    private var running = false
    private var stopped = false
    private var hasStarted = false
    private var pollLoopActive = false
    private var generation: UInt64 = 0
    private var activeReadCallbacks = 0
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
        queue: DispatchQueue = DispatchQueue(label: "org.xrayrust.packet-tunnel-pump"),
        terminalFailureHandler: @escaping @Sendable (
            XrayPacketTunnelPumpError
        ) -> Void = { _ in }
    ) {
        self.provider = provider
        self.core = core
        self.queue = queue
        terminalFailureDelivery = XrayPacketTunnelTerminalFailureDelivery(
            handler: terminalFailureHandler
        )
        let pollByteCount = Self.maxPacketsPerPoll * Self.maxPacketBytes
        pollStorage = XrayPacketBatchPollStorage(
            validatedMaxPackets: Self.maxPacketsPerPoll,
            validatedMaxPacketBytes: Self.maxPacketBytes,
            validatedByteCount: pollByteCount
        )
    }

    public func start() {
        condition.lock()
        guard !running, !stopped else {
            condition.unlock()
            return
        }
        generation &+= 1
        let startedGeneration = generation
        running = true
        hasStarted = true
        pollLoopActive = true
        pollLoopGroup.enter()
        failureCircuitBreaker.start()
        terminalFailureDelivery.start()
        pushPacketErrorCount = 0
        pollPacketErrorCount = 0
        writePacketErrorCount = 0
        readBatchCount = 0
        readPacketCount = 0
        readByteCount = 0
        writtenPacketCount = 0
        writtenByteCount = 0
        lastStatsLog = Date()
        condition.unlock()

        XrayMobileLog.info("PacketPump", "Starting packet pump")
        readPackets(generation: startedGeneration)
        pollPackets(generation: startedGeneration)
    }

    public func stop() {
        condition.lock()
        guard hasStarted else {
            condition.unlock()
            return
        }
        let shouldLog = !stopped || pollLoopActive || activeReadCallbacks > 0
        running = false
        stopped = true
        generation &+= 1
        failureCircuitBreaker.stop()
        terminalFailureDelivery.stop()
        while activeReadCallbacks > 0 {
            condition.wait()
        }
        condition.unlock()
        if shouldLog {
            XrayMobileLog.info("PacketPump", "Stopping packet pump")
        }
        // The Rust poll has a bounded wait. Joining without a timeout guarantees
        // that the provider cannot call core.stop while poll/stats still use it.
        pollLoopGroup.wait()
    }

    private func readPackets(generation: UInt64) {
        guard isRunning(generation: generation) else {
            return
        }

        provider.packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.beginReadCallback(generation: generation) else {
                return
            }
            defer {
                self.endReadCallback()
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

            var droppedPacket = false
            for packet in packets {
                // QUIC blocking happens once, inside the Rust core, which
                // also emits the ICMP port-unreachable reply on the outbound
                // queue; filtering here as well parsed every UDP packet twice.
                do {
                    try self.core.pushPacket(packet)
                } catch {
                    droppedPacket = true
                    let count = self.incrementPushPacketErrorCount()
                    if Self.shouldLogPacketError(count) {
                        XrayMobileLog.error(
                            "PacketPump",
                            "pushPacket failed count=\(count) bytes=\(packet.count) error=\(error)"
                        )
                    }
                    _ = self.failureCircuitBreaker.recordRecoverablePushFailure()
                }
            }
            if droppedPacket {
                Thread.sleep(forTimeInterval: 0.001)
            }
            self.readPackets(generation: generation)
        }
    }

    private func pollPackets(generation: UInt64) {
        let group = pollLoopGroup
        queue.async { [weak self, group] in
            defer {
                if let self {
                    self.condition.lock()
                    self.pollLoopActive = false
                    self.condition.broadcast()
                    self.condition.unlock()
                }
                group.leave()
            }
            guard let self else {
                return
            }

            // The poll blocks inside the core until a packet is queued (or the
            // wait expires), so the loop wakes immediately on traffic instead
            // of sleeping between polling passes.
            while self.isRunning(generation: generation) {
                autoreleasepool {
                    self.pollAndWriteBatch()
                }
                self.logStatsIfNeeded()
            }
            XrayMobileLog.info("PacketPump", "Packet pump poll loop exited")
        }
    }

    private func pollAndWriteBatch() {
        let packets: [Data]
        do {
            packets = try core.pollPackets(
                storage: pollStorage,
                waitMilliseconds: Self.pollWaitMilliseconds
            )
            failureCircuitBreaker.recordSuccess(.pollPackets)
        } catch {
            let count = incrementPollPacketErrorCount()
            if Self.shouldLogPacketError(count) {
                XrayMobileLog.error(
                    "PacketPump",
                    "pollPackets failed count=\(count) error=\(error)"
                )
            }
            if let terminalError = failureCircuitBreaker.recordFailure(.pollPackets) {
                tripTerminalFailure(terminalError)
                return
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
            if let terminalError = failureCircuitBreaker.recordFailure(.writePackets) {
                tripTerminalFailure(terminalError)
            }
        } else {
            failureCircuitBreaker.recordSuccess(.writePackets)
        }
    }

    private func tripTerminalFailure(_ error: XrayPacketTunnelPumpError) {
        condition.lock()
        guard running else {
            condition.unlock()
            return
        }
        running = false
        stopped = true
        generation &+= 1
        failureCircuitBreaker.stop()
        condition.broadcast()
        condition.unlock()

        XrayMobileLog.error(
            "PacketPump",
            "Packet pump reached a terminal failure: \(error.localizedDescription)"
        )
        terminalFailureDelivery.submit(error)
    }

    private func isRunning(generation: UInt64) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        return running && self.generation == generation
    }

    private func beginReadCallback(generation: UInt64) -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard running, self.generation == generation else {
            return false
        }
        activeReadCallbacks += 1
        return true
    }

    private func endReadCallback() {
        condition.lock()
        activeReadCallbacks -= 1
        if activeReadCallbacks == 0 {
            condition.broadcast()
        }
        condition.unlock()
    }

    private func incrementPushPacketErrorCount() -> Int {
        condition.lock()
        defer { condition.unlock() }
        pushPacketErrorCount += 1
        return pushPacketErrorCount
    }

    private func incrementPollPacketErrorCount() -> Int {
        condition.lock()
        defer { condition.unlock() }
        pollPacketErrorCount += 1
        return pollPacketErrorCount
    }

    private func currentWritePacketErrorCount() -> Int {
        condition.lock()
        defer { condition.unlock() }
        return writePacketErrorCount
    }

    private func recordReadPacketBatch(packetCount: Int, byteCount: Int) -> PacketPumpSnapshot? {
        condition.lock()
        defer { condition.unlock() }

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
        condition.lock()
        defer { condition.unlock() }

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
        condition.lock()
        if now.timeIntervalSince(lastStatsLog) >= 5 {
            lastStatsLog = now
            snapshot = snapshotLocked()
        } else {
            snapshot = nil
        }
        condition.unlock()

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
