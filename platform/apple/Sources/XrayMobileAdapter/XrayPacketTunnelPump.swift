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
                if let rejectPacket = Self.quicRejectPacket(for: packet, options: self.options) {
                    let count = self.incrementBlockedQUICPacketCount()
                    if Self.shouldLogPacketEvent(count) {
                        XrayMobileLog.info(
                            "PacketPump",
                            "Rejected UDP/443 QUIC packet bytes=\(packet.count) rejectBytes=\(rejectPacket.count) totalBlockedQUIC=\(count)"
                        )
                    }
                    let protocolFamily = NSNumber(value: Self.protocolFamily(for: rejectPacket))
                    let didWrite = self.provider.packetFlow.writePackets(
                        [rejectPacket],
                        withProtocols: [protocolFamily]
                    )
                    if let snapshot = self.recordWrittenPacket(
                        byteCount: rejectPacket.count,
                        didWrite: didWrite
                    ) {
                        XrayMobileLog.info(
                            "PacketPump",
                            "Wrote QUIC reject packet bytes=\(rejectPacket.count) protocol=\(protocolFamily) didWrite=\(didWrite) totals writtenPackets=\(snapshot.writtenPacketCount) writtenBytes=\(snapshot.writtenByteCount) writeErrors=\(snapshot.writePacketErrorCount)"
                        )
                    }
                    if !didWrite {
                        let errorCount = self.currentWritePacketErrorCount()
                        if Self.shouldLogPacketError(errorCount) {
                            XrayMobileLog.error(
                                "PacketPump",
                                "writePackets for QUIC reject returned false count=\(errorCount) bytes=\(rejectPacket.count)"
                            )
                        }
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

        XrayMobileLog.info(
            "PacketPump",
            "Stats packetFlow readPackets=\(snapshot.readPacketCount) readBytes=\(snapshot.readByteCount) writtenPackets=\(snapshot.writtenPacketCount) writtenBytes=\(snapshot.writtenByteCount) blockedQUIC=\(snapshot.blockedQUICPacketCount) pushErrors=\(snapshot.pushPacketErrorCount) pollErrors=\(snapshot.pollPacketErrorCount) writeErrors=\(snapshot.writePacketErrorCount)"
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

    static func quicRejectPacket(
        for packet: Data,
        options: XrayPacketTunnelPumpOptions
    ) -> Data? {
        guard options.blockQUIC,
              let payload = udpPayload(in: packet)
        else {
            return nil
        }

        guard payload.destinationPort == 443,
              isLikelyQUICLongHeader(payload.payload)
        else {
            return nil
        }

        return icmpPortUnreachableReply(for: packet)
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
        let bytes = [UInt8](packet)
        guard bytes.count >= 28 else {
            return nil
        }
        let headerLength = Int(bytes[0] & 0x0f) * 4
        guard headerLength >= 20,
              bytes.count >= headerLength + 8,
              bytes[9] == 17
        else {
            return nil
        }

        let fragment = UInt16(bytes[6]) << 8 | UInt16(bytes[7])
        guard fragment & 0x3fff == 0 else {
            return nil
        }

        let packetLength = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        guard packetLength >= headerLength + 8,
              bytes.count >= packetLength
        else {
            return nil
        }

        let udpLength = Int(UInt16(bytes[headerLength + 4]) << 8 | UInt16(bytes[headerLength + 5]))
        guard udpLength >= 8,
              headerLength + udpLength <= packetLength
        else {
            return nil
        }

        let destinationPort = UInt16(bytes[headerLength + 2]) << 8
            | UInt16(bytes[headerLength + 3])
        return UDPPacketPayload(
            destinationPort: destinationPort,
            payload: packet[(headerLength + 8)..<(headerLength + udpLength)]
        )
    }

    private static func ipv6UDPPayload(in packet: Data) -> UDPPacketPayload? {
        let bytes = [UInt8](packet)
        guard bytes.count >= 48,
              bytes[6] == 17
        else {
            return nil
        }

        let payloadLength = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        guard payloadLength >= 8,
              bytes.count >= 40 + payloadLength
        else {
            return nil
        }

        let udpLength = Int(UInt16(bytes[44]) << 8 | UInt16(bytes[45]))
        guard udpLength >= 8,
              udpLength <= payloadLength
        else {
            return nil
        }

        let destinationPort = UInt16(bytes[42]) << 8 | UInt16(bytes[43])
        return UDPPacketPayload(
            destinationPort: destinationPort,
            payload: packet[48..<(40 + udpLength)]
        )
    }

    private static func icmpPortUnreachableReply(for packet: Data) -> Data? {
        guard let first = packet.first else {
            return nil
        }

        switch first >> 4 {
        case 4:
            return ipv4ICMPPortUnreachableReply(for: packet)
        case 6:
            return ipv6ICMPPortUnreachableReply(for: packet)
        default:
            return nil
        }
    }

    private static func ipv4ICMPPortUnreachableReply(for packet: Data) -> Data? {
        let bytes = [UInt8](packet)
        guard bytes.count >= 28 else {
            return nil
        }

        let headerLength = Int(bytes[0] & 0x0f) * 4
        guard headerLength >= 20,
              bytes.count >= headerLength + 8,
              bytes[9] == 17
        else {
            return nil
        }

        let fragment = UInt16(bytes[6]) << 8 | UInt16(bytes[7])
        guard fragment & 0x3fff == 0 else {
            return nil
        }

        let packetLength = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        guard packetLength >= headerLength + 8,
              bytes.count >= packetLength
        else {
            return nil
        }

        let quoteLength = min(headerLength + 8, packetLength)
        let icmpLength = 8 + quoteLength
        let totalLength = 20 + icmpLength
        var reply = [UInt8](repeating: 0, count: totalLength)
        reply[0] = 0x45
        reply[2] = UInt8(totalLength >> 8)
        reply[3] = UInt8(totalLength & 0xff)
        reply[8] = 64
        reply[9] = 1
        reply.replaceSubrange(12..<16, with: bytes[16..<20])
        reply.replaceSubrange(16..<20, with: bytes[12..<16])

        reply[20] = 3
        reply[21] = 3
        reply.replaceSubrange(28..<(28 + quoteLength), with: bytes[0..<quoteLength])
        let icmpChecksum = internetChecksum(reply[20...])
        reply[22] = UInt8(icmpChecksum >> 8)
        reply[23] = UInt8(icmpChecksum & 0xff)
        let ipChecksum = internetChecksum(reply[0..<20])
        reply[10] = UInt8(ipChecksum >> 8)
        reply[11] = UInt8(ipChecksum & 0xff)

        return Data(reply)
    }

    private static func ipv6ICMPPortUnreachableReply(for packet: Data) -> Data? {
        let bytes = [UInt8](packet)
        guard bytes.count >= 48,
              bytes[6] == 17
        else {
            return nil
        }

        let payloadLength = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        guard payloadLength >= 8,
              bytes.count >= 40 + payloadLength
        else {
            return nil
        }

        let source = Array(bytes[8..<24])
        let destination = Array(bytes[24..<40])
        let packetLength = 40 + payloadLength
        let quoteLength = min(packetLength, 1232)
        let icmpLength = 8 + quoteLength
        let totalLength = 40 + icmpLength
        var reply = [UInt8](repeating: 0, count: totalLength)
        reply[0] = 0x60
        reply[4] = UInt8(icmpLength >> 8)
        reply[5] = UInt8(icmpLength & 0xff)
        reply[6] = 58
        reply[7] = 64
        reply.replaceSubrange(8..<24, with: destination)
        reply.replaceSubrange(24..<40, with: source)

        reply[40] = 1
        reply[41] = 4
        reply.replaceSubrange(48..<(48 + quoteLength), with: bytes[0..<quoteLength])
        let checksum = ipv6TransportChecksum(
            source: destination,
            destination: source,
            nextHeader: 58,
            payload: reply[40...]
        )
        reply[42] = UInt8(checksum >> 8)
        reply[43] = UInt8(checksum & 0xff)

        return Data(reply)
    }

    private static func ipv6TransportChecksum<C: Collection>(
        source: [UInt8],
        destination: [UInt8],
        nextHeader: UInt8,
        payload: C
    ) -> UInt16 where C.Element == UInt8 {
        var pseudo = [UInt8]()
        pseudo.reserveCapacity(40 + payload.count)
        pseudo.append(contentsOf: source)
        pseudo.append(contentsOf: destination)
        let payloadLength = UInt32(payload.count)
        pseudo.append(UInt8((payloadLength >> 24) & 0xff))
        pseudo.append(UInt8((payloadLength >> 16) & 0xff))
        pseudo.append(UInt8((payloadLength >> 8) & 0xff))
        pseudo.append(UInt8(payloadLength & 0xff))
        pseudo.append(contentsOf: [0, 0, 0, nextHeader])
        pseudo.append(contentsOf: payload)
        return internetChecksum(pseudo)
    }

    private static func internetChecksum<C: Collection>(_ bytes: C) -> UInt16 where C.Element == UInt8 {
        var sum: UInt32 = 0
        var iterator = bytes.makeIterator()
        while let high = iterator.next() {
            let low = iterator.next() ?? 0
            sum += UInt32(high) << 8 | UInt32(low)
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return UInt16(truncatingIfNeeded: ~sum)
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
