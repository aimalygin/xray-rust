import XCTest
@testable import XrayMobileAdapter

final class XrayPacketTunnelPumpTests: XCTestCase {
    func testMobileLogSanitizesAttackerControlledParseErrorAsOneLine() {
        let sanitized = XrayMobileLog.sanitized(
            "unsupported protocol 'evil'\n[forged]\rnext\u{001B}\u{2028}"
        )

        XCTAssertEqual(
            sanitized,
            #"unsupported protocol 'evil'\n[forged]\rnext\u{001B}\u{2028}"#
        )
        XCTAssertFalse(sanitized.contains("\n"))
        XCTAssertFalse(sanitized.contains("\r"))
        XCTAssertFalse(sanitized.contains("\u{001B}"))
    }

    func testPersistentOutputFailuresTripEachOperationExactlyOnce() {
        let cases: [
            (
                XrayPacketTunnelPumpOperation,
                XrayPacketTunnelPumpError
            )
        ] = [
            (
                .pollPackets,
                .persistentPollPacketFailures(consecutiveFailures: 3)
            ),
            (
                .writePackets,
                .persistentWritePacketFailures(consecutiveFailures: 3)
            ),
        ]

        for (operation, expectedError) in cases {
            let breaker = XrayPacketTunnelFailureCircuitBreaker(
                maxConsecutiveFailures: 3
            )
            breaker.start()

            XCTAssertNil(breaker.recordFailure(operation))
            XCTAssertNil(breaker.recordFailure(operation))
            XCTAssertEqual(breaker.recordFailure(operation), expectedError)
            XCTAssertNil(breaker.recordFailure(operation))
        }
    }

    func testTenThousandPushFailuresRemainRecoverableDrops() {
        let breaker = XrayPacketTunnelFailureCircuitBreaker(
            maxConsecutiveFailures: 3
        )
        breaker.start()

        for _ in 0..<10_000 {
            XCTAssertNil(breaker.recordRecoverablePushFailure())
        }

        XCTAssertNil(breaker.recordFailure(.pollPackets))
    }

    func testTransientPollFailureResetsAfterSuccessfulPoll() {
        let breaker = XrayPacketTunnelFailureCircuitBreaker(
            maxConsecutiveFailures: 3
        )
        breaker.start()

        XCTAssertNil(breaker.recordFailure(.pollPackets))
        XCTAssertNil(breaker.recordFailure(.pollPackets))
        breaker.recordSuccess(.pollPackets)
        XCTAssertNil(breaker.recordFailure(.pollPackets))
        XCTAssertNil(breaker.recordFailure(.pollPackets))
    }

    func testNormalStopSuppressesLateTerminalFailure() {
        let breaker = XrayPacketTunnelFailureCircuitBreaker(
            maxConsecutiveFailures: 2
        )
        breaker.start()
        breaker.stop()

        XCTAssertNil(breaker.recordFailure(.pollPackets))
        XCTAssertNil(breaker.recordFailure(.pollPackets))
        XCTAssertNil(breaker.recordFailure(.writePackets))
        XCTAssertNil(breaker.recordFailure(.writePackets))
    }

    func testTerminalFailureDeliveryIsAsyncOnceAndAllowsSelfStop() {
        let delivered = expectation(description: "terminal failure delivered")
        let owner = TerminalFailureDeliveryOwner(expectation: delivered)
        let delivery = XrayPacketTunnelTerminalFailureDelivery { error in
            owner.handle(error)
        }
        owner.delivery = delivery
        delivery.start()

        delivery.submit(
            .persistentPollPacketFailures(consecutiveFailures: 8)
        )
        delivery.submit(
            .persistentWritePacketFailures(consecutiveFailures: 8)
        )

        wait(for: [delivered], timeout: 1)
        delivery.submit(
            .persistentWritePacketFailures(consecutiveFailures: 9)
        )
        XCTAssertEqual(owner.deliveryCount, 1)
        owner.delivery = nil
    }

    func testBatchPollStorageIsReusedAcrossEmptyPolls() throws {
        let maxPackets = 64
        let maxPacketBytes = 1_500
        let byteCount = try XrayCore.validatedPacketBatchByteCount(
            maxPackets: maxPackets,
            maxPacketBytes: maxPacketBytes
        )
        let storage = XrayPacketBatchPollStorage(
            validatedMaxPackets: maxPackets,
            validatedMaxPacketBytes: maxPacketBytes,
            validatedByteCount: byteCount
        )
        let initialIdentities = storage.bufferIdentities

        for _ in 0..<10_000 {
            XCTAssertTrue(storage.materializePackets(packetCount: 0).isEmpty)
            XCTAssertEqual(storage.bufferIdentities.bytes, initialIdentities.bytes)
            XCTAssertEqual(storage.bufferIdentities.lengths, initialIdentities.lengths)
        }

        XCTAssertEqual(storage.materializedPacketCount, 0)
    }

    func testPacketPollValidationRejectsZeroNegativeOverflowAndHugeBuffers() {
        for invalidSize in [0, -1, XrayCore.maximumPolledPacketBytes + 1] {
            XCTAssertThrowsError(
                try XrayCore.validatePacketPollSize(invalidSize)
            ) { error in
                guard case let XrayCoreError.invalidPacketPollSize(actualSize) = error else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertEqual(actualSize, invalidSize)
            }
        }

        for (maxPackets, maxPacketBytes) in [(0, 1_500), (64, -1)] {
            XCTAssertThrowsError(
                try XrayCore.validatedPacketBatchByteCount(
                    maxPackets: maxPackets,
                    maxPacketBytes: maxPacketBytes
                )
            ) { error in
                guard case XrayCoreError.invalidPacketBatchLimits = error else {
                    return XCTFail("unexpected error: \(error)")
                }
            }
        }

        XCTAssertThrowsError(
            try XrayCore.validatedPacketBatchByteCount(
                maxPackets: Int.max,
                maxPacketBytes: 2
            )
        ) { error in
            guard case XrayCoreError.packetBatchSizeOverflow = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }

        XCTAssertThrowsError(
            try XrayCore.validatedPacketBatchByteCount(
                maxPackets: XrayCore.maximumPacketBatchBytes / 1_500 + 1,
                maxPacketBytes: 1_500
            )
        ) { error in
            guard case XrayCoreError.packetBatchTooLarge = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testFFIMajorVersionValidationAcceptsCurrentABI() {
        XCTAssertNoThrow(try XrayCore.validateFFIMajorVersion(1))
    }

    func testFFIMajorVersionValidationRejectsIncompatibleABI() {
        XCTAssertThrowsError(try XrayCore.validateFFIMajorVersion(2)) { error in
            guard case let XrayCoreError.incompatibleFFIMajorVersion(expected, actual) = error else {
                return XCTFail("unexpected error: \(error)")
            }
            XCTAssertEqual(expected, 1)
            XCTAssertEqual(actual, 2)
        }
    }

    func testLifecycleGateWaitsForAllDataPathCallsAndBlocksLateReaders() {
        let gate = XrayCoreCallGate()
        let readerEntered = expectation(description: "initial readers entered")
        readerEntered.expectedFulfillmentCount = 2
        let releaseReaders = DispatchSemaphore(value: 0)
        let lifecycleEntered = DispatchSemaphore(value: 0)
        let releaseLifecycle = DispatchSemaphore(value: 0)
        let lateReaderEntered = DispatchSemaphore(value: 0)

        for _ in 0..<2 {
            DispatchQueue.global().async {
                gate.withDataPath {
                    readerEntered.fulfill()
                    releaseReaders.wait()
                }
            }
        }
        wait(for: [readerEntered], timeout: 1)

        DispatchQueue.global().async {
            gate.withLifecycle {
                lifecycleEntered.signal()
                releaseLifecycle.wait()
            }
        }
        let writerDeadline = Date().addingTimeInterval(1)
        while !gate.hasWaitingLifecycleCall, Date() < writerDeadline {
            Thread.sleep(forTimeInterval: 0.001)
        }
        XCTAssertTrue(gate.hasWaitingLifecycleCall)
        let lateReaderWorkItem = DispatchWorkItem(
            qos: .unspecified,
            flags: [],
            block: {
                gate.withDataPath {
                    _ = lateReaderEntered.signal()
                }
            }
        )
        DispatchQueue.global().async(execute: lateReaderWorkItem)

        XCTAssertEqual(
            lifecycleEntered.wait(timeout: .now() + 0.05),
            .timedOut
        )
        XCTAssertEqual(
            lateReaderEntered.wait(timeout: .now() + 0.05),
            .timedOut
        )

        releaseReaders.signal()
        releaseReaders.signal()
        XCTAssertEqual(lifecycleEntered.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(
            lateReaderEntered.wait(timeout: .now() + 0.05),
            .timedOut
        )

        releaseLifecycle.signal()
        XCTAssertEqual(lateReaderEntered.wait(timeout: .now() + 1), .success)
    }

    func testLifecycleGateReleasesAfterThrowingBody() {
        enum ExpectedError: Error {
            case failure
        }

        let gate = XrayCoreCallGate()
        XCTAssertThrowsError(
            try gate.withLifecycle {
                throw ExpectedError.failure
            }
        )

        let dataPathReturned = expectation(description: "data path returned")
        DispatchQueue.global().async {
            gate.withDataPath {
                dataPathReturned.fulfill()
            }
        }
        wait(for: [dataPathReturned], timeout: 1)
    }

    func testStatsDebugLogMessagesStayBelowTruncationLimit() {
        let messages = Self.sampleStats.debugLogMessages()

        XCTAssertEqual(messages.count, 9)
        XCTAssertTrue(
            messages.allSatisfy { $0.count < 512 },
            messages.map { "\($0.count): \($0)" }.joined(separator: "\n")
        )
        let joined = messages.joined(separator: "\n")
        XCTAssertTrue(joined.contains("tcpRemoteWriteWaitAvgMs=6"))
        XCTAssertTrue(joined.contains("tcpRemoteFlushWaitMaxMs=9"))
        XCTAssertTrue(joined.contains("tcpPendingUploadMaxBytes=32768"))
        XCTAssertTrue(joined.contains("tcpBufferHardLimitBytes=41943040"))
        XCTAssertTrue(joined.contains("tcpOpenAvgMs=100"))
        XCTAssertTrue(joined.contains("tcp443FirstByteMaxMs=250"))
        XCTAssertTrue(joined.contains("udpVisionUDP443Rejections=7"))
        XCTAssertTrue(joined.contains("udpQuicBlockedPackets=10"))
        XCTAssertTrue(joined.contains("udpUDP443OpenEvents=27"))
        XCTAssertTrue(joined.contains("tunFdReadLoopExits=1"))
        XCTAssertTrue(joined.contains("tunFdWriteLoopExits=2"))
        XCTAssertTrue(joined.contains("tunFdTransientIoErrors=9"))
    }

    func testTunRuntimeProfileNameMapsToFfiProfile() {
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "mobile-plus").rawValue, 5)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "mobile_plus").rawValue, 5)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "throughput").rawValue, 4)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "low_memory").rawValue, 3)
        XCTAssertEqual(XrayCore.tunRuntimeProfile(named: "unknown").rawValue, 0)
    }

    func testStartupProbeOptionsDefaultTimeoutAndOutboundTag() {
        let options = XrayStartupProbeOptions(url: "https://probe.example/generate_204")

        XCTAssertEqual(options.url, "https://probe.example/generate_204")
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
            target: "192.0.2.1:443",
            bytes: 1200
        )

        XCTAssertEqual(
            event.debugLogMessage(),
            "Debug quicBlocked target=192.0.2.1:443 bytes=1200"
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
        tcpPendingUploadBytes: 8192,
        tcpPendingUploadMaxBytes: 32768,
        tcpPendingTotalBytes: 8192,
        tcpRemoteBufferLimitBytes: 2097152,
        tcpBufferHardLimitBytes: 41943040,
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
        tunFdWriteBatchMaxPackets: 30,
        tunFdReadLoopExits: 1,
        tunFdWriteLoopExits: 2,
        tunFdTransientIoErrors: 9
    )
}

private final class TerminalFailureDeliveryOwner: @unchecked Sendable {
    private let lock = NSLock()
    private let expectation: XCTestExpectation
    var delivery: XrayPacketTunnelTerminalFailureDelivery?
    private var count = 0

    init(expectation: XCTestExpectation) {
        self.expectation = expectation
    }

    var deliveryCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }

    func handle(_ error: XrayPacketTunnelPumpError) {
        lock.lock()
        count += 1
        lock.unlock()
        delivery?.stop()
        expectation.fulfill()
    }
}
