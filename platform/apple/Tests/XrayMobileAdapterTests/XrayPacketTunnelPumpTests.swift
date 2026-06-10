import XCTest
@testable import XrayMobileAdapter

final class XrayPacketTunnelPumpTests: XCTestCase {
    func testStatsDebugLogMessagesStayBelowTruncationLimit() {
        let messages = Self.sampleStats.debugLogMessages()

        XCTAssertEqual(messages.count, 7)
        XCTAssertTrue(
            messages.allSatisfy { $0.count < 512 },
            messages.map { "\($0.count): \($0)" }.joined(separator: "\n")
        )
        let joined = messages.joined(separator: "\n")
        XCTAssertTrue(joined.contains("tcpOpenAvgMs=100"))
        XCTAssertTrue(joined.contains("tcp443FirstByteMaxMs=250"))
        XCTAssertTrue(joined.contains("udpVisionUDP443Rejections=7"))
        XCTAssertTrue(joined.contains("udpQuicBlockedPackets=10"))
        XCTAssertTrue(joined.contains("udpUDP443OpenEvents=27"))
    }

    func testTunRuntimeProfileNameMapsToFfiProfile() {
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "throughput").rawValue, 4)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "low_memory").rawValue, 3)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "unknown").rawValue, 0)
    }

    func testTcpSlowFlowDebugLogMessageIncludesTargetAndDurations() {
        let event = XrayTcpSlowFlowEventSnapshot(
            kind: .firstByte,
            target: "speedtest.example:443",
            openDurationMs: 447,
            firstByteDurationMs: 2680
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug tcpSlowFlow kind=firstByte target=speedtest.example:443 openMs=447 firstByteMs=2680"
        )
    }

    func testTcpFlowSummaryDebugLogMessageIncludesThresholdDurationsAndBytes() {
        let event = XrayTcpFlowSummaryEventSnapshot(
            target: "speedtest.example:443",
            outboundTag: "proxy",
            closed: false,
            durationMs: 3288,
            openDurationMs: 320,
            firstByteDurationMs: 650,
            remoteReadBytes: 1_048_576,
            msTo64KiB: 850,
            msTo128KiB: 1_050,
            msTo256KiB: 1_400,
            msTo512KiB: 1_900,
            msTo1MiB: 3_288
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug tcpFlowSummary target=speedtest.example:443 outbound=proxy closed=false durationMs=3288 openMs=320 firstByteMs=650 remoteReadBytes=1048576 msTo64KiB=850 msTo128KiB=1050 msTo256KiB=1400 msTo512KiB=1900 msTo1MiB=3288"
        )
    }

    func testUdpSlowFlowDebugLogMessageIncludesTargetAndDurations() {
        let event = XrayUdpSlowFlowEventSnapshot(
            target: "speedtest.example:443",
            firstResponseDurationMs: 3289,
            writtenBytes: 1350,
            readBytes: 1180
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug udpSlowFlow target=speedtest.example:443 firstResponseMs=3289 writtenBytes=1350 readBytes=1180"
        )
    }

    func testUdpResponseGapDebugLogMessageIncludesTargetAndDurations() {
        let event = XrayUdpResponseGapEventSnapshot(
            target: "speedtest.example:443",
            responseGapDurationMs: 3145,
            writtenBytes: 4800,
            readBytes: 1180
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug udpResponseGap target=speedtest.example:443 responseGapMs=3145 writtenBytes=4800 readBytes=1180"
        )
    }

    func testUdpQuicBlockedDebugLogMessageIncludesTargetAndBytes() {
        let event = XrayUdpQuicBlockedEventSnapshot(
            target: "1.1.1.1:443",
            bytes: 1200
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug quicBlocked target=1.1.1.1:443 bytes=1200"
        )
    }

    func testQuicBlockingRejectsIPv4Udp443QuicInitialPacket() throws {
        let packet = Self.ipv4UDPPacket(
            destinationPort: 443,
            payload: Self.quicInitialPayload()
        )

        let reject = try XCTUnwrap(
            XrayPacketTunnelPump.quicRejectPacket(
                for: packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: true)
            )
        )
        Self.assertIPv4ICMPPortUnreachable(reject, original: packet)
    }

    func testQuicBlockingRejectsIPv6Udp443QuicInitialPacket() throws {
        let packet = Self.ipv6UDPPacket(
            destinationPort: 443,
            payload: Self.quicInitialPayload()
        )

        let reject = try XCTUnwrap(
            XrayPacketTunnelPump.quicRejectPacket(
                for: packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: true)
            )
        )
        Self.assertIPv6ICMPPortUnreachable(reject, original: packet)
    }

    func testQuicBlockingDoesNotRejectNonQuicIPv4Udp443Packet() {
        let packet = Self.ipv4UDPPacket(
            destinationPort: 443,
            payload: Data([0x13, 0x37, 0x42, 0x00])
        )

        XCTAssertNil(
            XrayPacketTunnelPump.quicRejectPacket(
                for: packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: true)
            )
        )
    }

    func testQuicBlockingDoesNotRejectIPv4Tcp443Packet() {
        let packet = Self.ipv4TCPPacket(destinationPort: 443)

        XCTAssertNil(
            XrayPacketTunnelPump.quicRejectPacket(
                for: packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: true)
            )
        )
    }

    func testQuicBlockingDoesNotRejectWhenDisabled() {
        let packet = Self.ipv4UDPPacket(
            destinationPort: 443,
            payload: Self.quicInitialPayload()
        )

        XCTAssertNil(
            XrayPacketTunnelPump.quicRejectPacket(
                for: packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: false)
            )
        )
    }

    private static func ipv4UDPPacket(destinationPort: UInt16, payload: Data) -> Data {
        var packet = [UInt8](repeating: 0, count: 28 + payload.count)
        packet[0] = 0x45
        packet[2] = UInt8(packet.count >> 8)
        packet[3] = UInt8(packet.count & 0xff)
        packet[8] = 64
        packet[9] = 17
        packet[12...15] = [10, 10, 0, 2]
        packet[16...19] = [203, 0, 113, 7]
        packet[22] = UInt8(destinationPort >> 8)
        packet[23] = UInt8(destinationPort & 0xff)
        packet[24] = UInt8((8 + payload.count) >> 8)
        packet[25] = UInt8((8 + payload.count) & 0xff)
        packet.replaceSubrange(28..., with: payload)
        let ipChecksum = Self.internetChecksum(packet[0..<20])
        packet[10] = UInt8(ipChecksum >> 8)
        packet[11] = UInt8(ipChecksum & 0xff)
        return Data(packet)
    }

    private static func ipv6UDPPacket(destinationPort: UInt16, payload: Data) -> Data {
        var packet = [UInt8](repeating: 0, count: 48 + payload.count)
        packet[0] = 0x60
        packet[4] = UInt8((8 + payload.count) >> 8)
        packet[5] = UInt8((8 + payload.count) & 0xff)
        packet[6] = 17
        packet[7] = 64
        packet[8...23] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 2,
        ]
        packet[24...39] = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 7,
        ]
        packet[42] = UInt8(destinationPort >> 8)
        packet[43] = UInt8(destinationPort & 0xff)
        packet[44] = UInt8((8 + payload.count) >> 8)
        packet[45] = UInt8((8 + payload.count) & 0xff)
        packet.replaceSubrange(48..., with: payload)
        return Data(packet)
    }

    private static func ipv4TCPPacket(destinationPort: UInt16) -> Data {
        var packet = [UInt8](repeating: 0, count: 40)
        packet[0] = 0x45
        packet[9] = 6
        packet[22] = UInt8(destinationPort >> 8)
        packet[23] = UInt8(destinationPort & 0xff)
        return Data(packet)
    }

    private static func quicInitialPayload() -> Data {
        Data([
            0xc0,
            0x00, 0x00, 0x00, 0x01,
            0x08,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00,
        ])
    }

    private static func assertIPv4ICMPPortUnreachable(_ packet: Data, original: Data) {
        let bytes = [UInt8](packet)
        let originalBytes = [UInt8](original)
        XCTAssertGreaterThanOrEqual(bytes.count, 56)
        XCTAssertEqual(bytes[0] >> 4, 4)
        XCTAssertEqual(bytes[9], 1)
        XCTAssertEqual(Array(bytes[12..<16]), [203, 0, 113, 7])
        XCTAssertEqual(Array(bytes[16..<20]), [10, 10, 0, 2])
        XCTAssertEqual(Self.internetChecksum(bytes[0..<20]), 0)

        let totalLength = Int(UInt16(bytes[2]) << 8 | UInt16(bytes[3]))
        XCTAssertEqual(totalLength, bytes.count)
        let icmp = bytes[20...]
        XCTAssertEqual(icmp[icmp.startIndex], 3)
        XCTAssertEqual(icmp[icmp.index(after: icmp.startIndex)], 3)
        XCTAssertEqual(Array(icmp.dropFirst(4).prefix(4)), [0, 0, 0, 0])
        XCTAssertEqual(Self.internetChecksum(icmp), 0)
        XCTAssertEqual(Array(icmp.dropFirst(8)), Array(originalBytes.prefix(28)))
    }

    private static func assertIPv6ICMPPortUnreachable(_ packet: Data, original: Data) {
        let bytes = [UInt8](packet)
        let originalBytes = [UInt8](original)
        XCTAssertGreaterThanOrEqual(bytes.count, 88)
        XCTAssertEqual(bytes[0] >> 4, 6)
        XCTAssertEqual(bytes[6], 58)
        XCTAssertEqual(
            Array(bytes[8..<24]),
            [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 7,
            ]
        )
        XCTAssertEqual(
            Array(bytes[24..<40]),
            [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 2,
            ]
        )

        let payloadLength = Int(UInt16(bytes[4]) << 8 | UInt16(bytes[5]))
        XCTAssertEqual(bytes.count, 40 + payloadLength)
        let icmp = bytes[40...]
        XCTAssertEqual(icmp[icmp.startIndex], 1)
        XCTAssertEqual(icmp[icmp.index(after: icmp.startIndex)], 4)
        XCTAssertEqual(Array(icmp.dropFirst(4).prefix(4)), [0, 0, 0, 0])
        XCTAssertEqual(
            Self.ipv6TransportChecksum(
                source: Array(bytes[8..<24]),
                destination: Array(bytes[24..<40]),
                nextHeader: 58,
                payload: icmp
            ),
            0
        )
        XCTAssertEqual(Array(icmp.dropFirst(8)), Array(originalBytes.prefix(1232)))
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
        return Self.internetChecksum(pseudo)
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

    private static let sampleStats = XrayTunStatsSnapshot(
        inboundPackets: 5977,
        outboundPackets: 32654,
        droppedPackets: 0,
        inboundDroppedPackets: 0,
        outboundDroppedPackets: 0,
        tcpStackToRemoteBytes: 93773,
        tcpRemoteWrittenBytes: 93773,
        tcpRemoteReadBytes: 44911642,
        tcpBackpressureEvents: 0,
        tcpStackToRemoteBackpressureEvents: 0,
        tcpRemoteToStackBackpressureEvents: 0,
        tcpRemoteWriteBatches: 236,
        tcpRemoteWriteBatchMessages: 237,
        tcpRemoteWriteBatchMaxMessages: 2,
        tcpRemoteWriteBatchMaxBytes: 15421,
        tcpPendingRemoteBytes: 0,
        tcpPendingRemoteFlows: 0,
        tcpPendingRemoteMaxBytes: 0,
        tcpRemoteBufferLimitBytes: 2097152,
        tcpRemoteBufferPressureActive: false,
        tcpRemoteWriteErrors: 0,
        tcpRemoteClosedEvents: 6,
        tcpRemoteReadErrors: 1,
        tcpOpenErrors: 0,
        tcpOpenEvents: 2,
        tcpOpenDurationMsTotal: 200,
        tcpOpenDurationMsMax: 120,
        tcpFirstByteEvents: 2,
        tcpFirstByteDurationMsTotal: 550,
        tcpFirstByteDurationMsMax: 300,
        tcp443OpenEvents: 1,
        tcp443OpenDurationMsTotal: 80,
        tcp443OpenDurationMsMax: 80,
        tcp443FirstByteEvents: 1,
        tcp443FirstByteDurationMsTotal: 250,
        tcp443FirstByteDurationMsMax: 250,
        activeTCPFlows: 15,
        activeUDPFlows: 47,
        udpFlowLimit: 256,
        udpBudgetDrops: 0,
        udpEvictedFlows: 0,
        udpChannelDroppedPackets: 0,
        udpRemoteOpenEvents: 47,
        udpRemoteUDP443OpenEvents: 27,
        udpRemoteWrittenBytes: 135783,
        udpRemoteReadBytes: 266553,
        udpOpenErrors: 0,
        udpVisionUDP443Rejections: 7,
        udpRemoteWriteErrors: 8,
        udpRemoteReadErrors: 9,
        udpRemoteClosedEvents: 6,
        udpQuicBlockedPackets: 10,
        inboundQueueDepth: 1024,
        outboundQueueDepth: 4096,
        inboundQueueMaxPackets: 11,
        outboundQueueMaxPackets: 30,
        tunFdWriteBatches: 4218,
        tunFdWriteBatchPackets: 32654,
        tunFdWriteBatchMaxPackets: 30
    )
}
