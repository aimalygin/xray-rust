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
    private static let maxPacketsPerPollPass = 256

    private let provider: NEPacketTunnelProvider
    private let core: XrayCore
    private let queue: DispatchQueue
    private let options: XrayPacketTunnelPumpOptions
    private let lock = NSLock()
    private var running = false
    private var pushPacketErrorCount = 0
    private var pollPacketErrorCount = 0
    private var writePacketErrorCount = 0
    private var blockedQUICPacketCount: UInt64 = 0
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
        blockedQUICPacketCount = 0
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
        running = false
        lock.unlock()
        XrayMobileLog.info("PacketPump", "Stopping packet pump")
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
                if Self.shouldDropPacket(packet, options: self.options) {
                    let count = self.incrementBlockedQUICPacketCount()
                    if Self.shouldLogPacketEvent(count) {
                        XrayMobileLog.info(
                            "PacketPump",
                            "Blocked UDP/443 packet bytes=\(packet.count) totalBlockedQUIC=\(count)"
                        )
                    }
                    continue
                }

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

            while self.isRunning {
                var packetsThisPass = 0
                while self.isRunning && packetsThisPass < Self.maxPacketsPerPollPass {
                    let didPollPacket = autoreleasepool {
                        self.pollAndWritePacket()
                    }
                    if !didPollPacket {
                        break
                    }
                    packetsThisPass += 1
                }
                self.logStatsIfNeeded()
                Thread.sleep(
                    forTimeInterval: packetsThisPass == Self.maxPacketsPerPollPass ? 0.001 : 0.005
                )
            }
            XrayMobileLog.info("PacketPump", "Packet pump poll loop exited")
        }
    }

    private func pollAndWritePacket() -> Bool {
        let packet: Data?
        do {
            packet = try core.pollPacket()
        } catch {
            let count = incrementPollPacketErrorCount()
            if Self.shouldLogPacketError(count) {
                XrayMobileLog.error(
                    "PacketPump",
                    "pollPacket failed count=\(count) error=\(error)"
                )
            }
            return false
        }
        guard let packet else {
            return false
        }

        let protocolFamily = NSNumber(value: Self.protocolFamily(for: packet))
        let didWrite = provider.packetFlow.writePackets(
            [packet],
            withProtocols: [protocolFamily]
        )
        if let snapshot = recordWrittenPacket(
            byteCount: packet.count,
            didWrite: didWrite
        ) {
            XrayMobileLog.info(
                "PacketPump",
                "Wrote packet bytes=\(packet.count) protocol=\(protocolFamily) didWrite=\(didWrite) totals writtenPackets=\(snapshot.writtenPacketCount) writtenBytes=\(snapshot.writtenByteCount) writeErrors=\(snapshot.writePacketErrorCount)"
            )
        }
        if !didWrite {
            let count = currentWritePacketErrorCount()
            if Self.shouldLogPacketError(count) {
                XrayMobileLog.error(
                    "PacketPump",
                    "writePackets returned false count=\(count) bytes=\(packet.count)"
                )
            }
        }
        return true
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

    private func incrementBlockedQUICPacketCount() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        blockedQUICPacketCount += 1
        return blockedQUICPacketCount
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

    private func recordWrittenPacket(byteCount: Int, didWrite: Bool) -> PacketPumpSnapshot? {
        lock.lock()
        defer { lock.unlock() }

        if didWrite {
            writtenPacketCount += 1
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

        let coreStats = try? core.stats()
        XrayMobileLog.info(
            "PacketPump",
            "Stats readPackets=\(snapshot.readPacketCount) readBytes=\(snapshot.readByteCount) writtenPackets=\(snapshot.writtenPacketCount) writtenBytes=\(snapshot.writtenByteCount) blockedQUIC=\(snapshot.blockedQUICPacketCount) pushErrors=\(snapshot.pushPacketErrorCount) pollErrors=\(snapshot.pollPacketErrorCount) writeErrors=\(snapshot.writePacketErrorCount) coreInbound=\(coreStats?.inboundPackets ?? 0) coreOutbound=\(coreStats?.outboundPackets ?? 0) coreDropped=\(coreStats?.droppedPackets ?? 0) coreInboundDropped=\(coreStats?.inboundDroppedPackets ?? 0) coreOutboundDropped=\(coreStats?.outboundDroppedPackets ?? 0) tcpStackToRemoteBytes=\(coreStats?.tcpStackToRemoteBytes ?? 0) tcpRemoteWrittenBytes=\(coreStats?.tcpRemoteWrittenBytes ?? 0) tcpRemoteReadBytes=\(coreStats?.tcpRemoteReadBytes ?? 0) tcpBackpressure=\(coreStats?.tcpBackpressureEvents ?? 0) tcpPendingRemoteBytes=\(coreStats?.tcpPendingRemoteBytes ?? 0) tcpPendingRemoteFlows=\(coreStats?.tcpPendingRemoteFlows ?? 0) tcpPendingRemoteMaxBytes=\(coreStats?.tcpPendingRemoteMaxBytes ?? 0) tcpWriteErrors=\(coreStats?.tcpRemoteWriteErrors ?? 0) tcpRemoteClosed=\(coreStats?.tcpRemoteClosedEvents ?? 0) tcpReadErrors=\(coreStats?.tcpRemoteReadErrors ?? 0) tcpOpenErrors=\(coreStats?.tcpOpenErrors ?? 0)"
        )
    }

    private func snapshotLocked() -> PacketPumpSnapshot {
        PacketPumpSnapshot(
            readBatchCount: readBatchCount,
            readPacketCount: readPacketCount,
            readByteCount: readByteCount,
            writtenPacketCount: writtenPacketCount,
            writtenByteCount: writtenByteCount,
            blockedQUICPacketCount: blockedQUICPacketCount,
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

    static func shouldDropPacket(
        _ packet: Data,
        options: XrayPacketTunnelPumpOptions
    ) -> Bool {
        guard options.blockQUIC,
              let payload = udpPayload(in: packet)
        else {
            return false
        }

        return payload.destinationPort == 443 && isLikelyQUICLongHeader(payload.payload)
    }

    private static func udpPayload(in packet: Data) -> UDPPacketPayload? {
        guard let first = packet.first else {
            return nil
        }

        switch first >> 4 {
        case 4:
            return ipv4UDPPayload(in: packet)
        case 6:
            return ipv6UDPPayload(in: packet)
        default:
            return nil
        }
    }

    private static func ipv4UDPPayload(in packet: Data) -> UDPPacketPayload? {
        guard packet.count >= 28 else {
            return nil
        }
        let headerLength = Int(packet[0] & 0x0f) * 4
        guard headerLength >= 20,
              packet.count >= headerLength + 8,
              packet[9] == 17
        else {
            return nil
        }
        let destinationPort = UInt16(packet[headerLength + 2]) << 8
            | UInt16(packet[headerLength + 3])
        return UDPPacketPayload(
            destinationPort: destinationPort,
            payload: packet[(headerLength + 8)...]
        )
    }

    private static func ipv6UDPPayload(in packet: Data) -> UDPPacketPayload? {
        guard packet.count >= 48,
              packet[6] == 17
        else {
            return nil
        }
        let destinationPort = UInt16(packet[42]) << 8 | UInt16(packet[43])
        return UDPPacketPayload(
            destinationPort: destinationPort,
            payload: packet[48...]
        )
    }

    private static func isLikelyQUICLongHeader(_ payload: Data.SubSequence) -> Bool {
        guard payload.count >= 7,
              let first = payload.first,
              first & 0xc0 == 0xc0
        else {
            return false
        }

        let start = payload.startIndex
        let versionStart = payload.index(after: start)
        let versionEnd = payload.index(versionStart, offsetBy: 4)
        let version = payload[versionStart ..< versionEnd]
        guard version.contains(where: { $0 != 0 }) else {
            return false
        }

        let dcidLengthIndex = versionEnd
        let dcidLength = Int(payload[dcidLengthIndex])
        guard dcidLength <= 20 else {
            return false
        }

        let scidLengthIndex = payload.index(after: dcidLengthIndex)
        guard payload.distance(from: scidLengthIndex, to: payload.endIndex) > dcidLength else {
            return false
        }
        let scidLengthIndexAfterDCID = payload.index(scidLengthIndex, offsetBy: dcidLength)
        let scidLength = Int(payload[scidLengthIndexAfterDCID])
        return scidLength <= 20
    }
}

private struct UDPPacketPayload {
    var destinationPort: UInt16
    var payload: Data.SubSequence
}

private struct PacketPumpSnapshot {
    var readBatchCount: UInt64
    var readPacketCount: UInt64
    var readByteCount: UInt64
    var writtenPacketCount: UInt64
    var writtenByteCount: UInt64
    var blockedQUICPacketCount: UInt64
    var pushPacketErrorCount: Int
    var pollPacketErrorCount: Int
    var writePacketErrorCount: Int
}
#endif
