import XCTest
@testable import XrayMobileAdapter

final class XrayPacketTunnelPumpTests: XCTestCase {
    func testStatsDebugLogMessagesStayBelowTruncationLimit() {
        let messages = Self.sampleStats.debugLogMessages()

        XCTAssertEqual(messages.count, 8)
        XCTAssertTrue(
            messages.allSatisfy { $0.count < 512 },
            messages.map { "\($0.count): \($0)" }.joined(separator: "\n")
        )
        let joined = messages.joined(separator: "\n")
        XCTAssertTrue(joined.contains("tcpRemoteWriteWaitAvgMs=6"))
        XCTAssertTrue(joined.contains("tcpRemoteFlushWaitMaxMs=9"))
        XCTAssertTrue(joined.contains("tcpOpenAvgMs=100"))
        XCTAssertTrue(joined.contains("tcp443FirstByteMaxMs=250"))
        XCTAssertTrue(joined.contains("udpVisionUDP443Rejections=7"))
        XCTAssertTrue(joined.contains("udpQuicBlockedPackets=10"))
        XCTAssertTrue(joined.contains("udpUDP443OpenEvents=27"))
    }

    func testTunRuntimeProfileNameMapsToFfiProfile() {
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "mobile-plus").rawValue, 5)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "mobile_plus").rawValue, 5)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "throughput").rawValue, 4)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "low_memory").rawValue, 3)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "unknown").rawValue, 0)
    }

    func testStartupProbeOptionsDefaultTimeoutAndOutboundTag() {
        let options = XrayStartupProbeOptions(url: "https://www.google.com/generate_204")

        XCTAssertEqual(options.url, "https://www.google.com/generate_204")
        XCTAssertEqual(options.timeoutMs, 5_000)
        XCTAssertNil(options.outboundTag)
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

    func testTcpRemoteWriteSlowDebugLogMessageIncludesTargetOutboundAndBatch() {
        let event = XrayTcpRemoteWriteSlowEventSnapshot(
            target: "speedtest.example:443",
            outboundTag: "proxy",
            durationMs: 2_680,
            bytes: 2_097_152,
            messages: 257
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug tcpRemoteWriteSlow target=speedtest.example:443 outbound=proxy writeWaitMs=2680 bytes=2097152 messages=257"
        )
    }

    func testTcpOpenErrorDebugLogMessageIncludesTargetOutboundAndError() {
        let event = XrayTcpOpenErrorEventSnapshot(
            target: "youtube.example:443",
            outboundTag: "proxy",
            error: "tcp connect failed: Network is unreachable"
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug tcpOpenError target=youtube.example:443 outbound=proxy error=tcp connect failed: Network is unreachable"
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
        tcpRemoteWriteWaitEvents: 3,
        tcpRemoteWriteWaitDurationMsTotal: 18,
        tcpRemoteWriteWaitDurationMsMax: 8,
        tcpRemoteFlushWaitEvents: 2,
        tcpRemoteFlushWaitDurationMsTotal: 10,
        tcpRemoteFlushWaitDurationMsMax: 9,
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
