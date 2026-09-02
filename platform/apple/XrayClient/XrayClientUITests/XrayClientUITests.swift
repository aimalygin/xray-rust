import Foundation
import Network
import XCTest

final class XrayClientUITests: XCTestCase {
    static let campaignEnabledKey = "XRAY_DEVICE_CAMPAIGN_ENABLED"
    static let durationKey = "XRAY_DEVICE_CAMPAIGN_DURATION_SECONDS"
    static let intervalKey = "XRAY_DEVICE_CAMPAIGN_SAMPLE_INTERVAL_SECONDS"
    static let HTTPURLKey = "XRAY_DEVICE_CAMPAIGN_HTTP_URL"
    static let UDPHostKey = "XRAY_DEVICE_CAMPAIGN_UDP_HOST"
    static let UDPPortKey = "XRAY_DEVICE_CAMPAIGN_UDP_PORT"
    static let debugLoggingKey = "XRAY_DEVICE_CAMPAIGN_DEBUG_LOGGING"
    static let memoryStressEnabledKey = "XRAY_DEVICE_MEMORY_STRESS_ENABLED"
    static let memoryStressHostKey = "XRAY_DEVICE_MEMORY_STRESS_HOST"
    static let memoryStressPortKey = "XRAY_DEVICE_MEMORY_STRESS_PORT"
    static let memoryStressTokenKey = "XRAY_DEVICE_MEMORY_STRESS_TOKEN"
    static let memoryStressStageSecondsKey = "XRAY_DEVICE_MEMORY_STRESS_STAGE_SECONDS"
    static let memoryStressRecoverySecondsKey =
        "XRAY_DEVICE_MEMORY_STRESS_RECOVERY_SECONDS"
    static let memoryStressMaxPhysicalFootprintBytesKey =
        "XRAY_DEVICE_MEMORY_STRESS_MAX_PHYSICAL_FOOTPRINT_BYTES"

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    func testDNSProbeRejectsStaleAndUnrelatedResponses() {
        let firstQuery = Self.makeDNSQuery(
            transactionID: 0x1234,
            nonce: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        )
        let secondQuery = Self.makeDNSQuery(
            transactionID: 0x5678,
            nonce: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        )

        XCTAssertNotEqual(firstQuery, secondQuery)

        var validResponse = firstQuery
        validResponse[2] = 0x81
        validResponse[3] = 0x80
        validResponse[6] = 0x00
        validResponse[7] = 0x01
        validResponse.append(Self.DNSProbeAnswer)
        XCTAssertTrue(Self.isValidDNSResponse(validResponse, for: firstQuery))
        XCTAssertFalse(Self.isValidDNSResponse(validResponse, for: secondQuery))

        var wrongAddressResponse = validResponse
        wrongAddressResponse[wrongAddressResponse.index(before: wrongAddressResponse.endIndex)] ^= 0x01
        XCTAssertFalse(Self.isValidDNSResponse(wrongAddressResponse, for: firstQuery))

        var nameErrorResponse = firstQuery
        nameErrorResponse[2] = 0x81
        nameErrorResponse[3] = 0x83
        XCTAssertFalse(Self.isValidDNSResponse(nameErrorResponse, for: firstQuery))

        var serverFailureResponse = firstQuery
        serverFailureResponse[2] = 0x81
        serverFailureResponse[3] = 0x82
        XCTAssertFalse(Self.isValidDNSResponse(serverFailureResponse, for: firstQuery))

        var unrelatedQuestion = firstQuery
        unrelatedQuestion[13] ^= 0x01
        XCTAssertFalse(Self.isValidDNSResponse(unrelatedQuestion, for: firstQuery))
    }

    @MainActor
    func testPhysicalDeviceCampaign() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment[Self.campaignEnabledKey] == "1" else {
            throw XCTSkip("physical-device campaign is opt-in")
        }
        let configuration = try CampaignConfiguration(environment: environment)
        executionTimeAllowance = TimeInterval(configuration.durationSeconds + 300)

        let app = XCUIApplication()
        app.launchEnvironment[Self.debugLoggingKey] = configuration.debugLoggingEnabled ? "1" : "0"
        app.launch()
        try ensureConnected(app)

        let startedAt = ProcessInfo.processInfo.systemUptime
        var samples: [CampaignSample] = []
        var runtimeGenerations: [String: UInt64] = [:]
        var nextRuntimeGeneration: UInt64 = 1
        var nextSampleAt = startedAt
        let trafficTask = Task { @MainActor in
            await pumpTraffic(configuration: configuration)
        }

        while Int(
            ProcessInfo.processInfo.systemUptime - startedAt
        ) < configuration.durationSeconds {
            let elapsed = Int(ProcessInfo.processInfo.systemUptime - startedAt)
            try await refresh(app)
            samples.append(
                try readSample(
                    app,
                    elapsedSeconds: elapsed,
                    runtimeGenerations: &runtimeGenerations,
                    nextRuntimeGeneration: &nextRuntimeGeneration
                )
            )
            emit(samples[samples.count - 1])
            nextSampleAt += TimeInterval(configuration.sampleIntervalSeconds)
            let remaining = nextSampleAt - ProcessInfo.processInfo.systemUptime
            if remaining > 0 {
                try await Task.sleep(nanoseconds: UInt64(remaining * 1_000_000_000))
            }
        }

        trafficTask.cancel()
        let trafficSummary = await trafficTask.value
        try await sleep(seconds: 2)
        let drainResult = try await drainConnections(
            app,
            startedAt: startedAt,
            runtimeGenerations: &runtimeGenerations,
            nextRuntimeGeneration: &nextRuntimeGeneration
        )
        samples.append(drainResult.sample)
        emit(samples[samples.count - 1])
        try disconnect(app)
        let terminalElapsed = max(
            UInt64(ProcessInfo.processInfo.systemUptime - startedAt),
            drainResult.sample.elapsedSeconds + 1
        )
        let terminalSample = drainResult.sample.afterDisconnect(
            elapsedSeconds: terminalElapsed
        )
        samples.append(terminalSample)
        emit(terminalSample)
        print(
            "XRAY_DEVICE_CLOSE totalAccepted=\(drainResult.closedConnections) "
                + "lastObservedActive=\(drainResult.sample.activeConnections)"
        )
        addCampaignAttachment(samples)

        XCTAssertGreaterThan(
            trafficSummary.httpSuccesses,
            0,
            "campaign did not complete an HTTPS probe"
        )
        XCTAssertGreaterThan(
            trafficSummary.udpSuccesses,
            0,
            "campaign did not complete a round-trip UDP probe"
        )
        XCTAssertGreaterThan(
            drainResult.closedConnections,
            0,
            "provider did not accept any active connection close request"
        )
    }

    @MainActor
    @available(iOS 17.0, *)
    func testPhysicalDeviceMemoryStress() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard environment[Self.memoryStressEnabledKey] == "1" else {
            throw XCTSkip("physical-device memory stress is opt-in")
        }
        let configuration = try MemoryStressConfiguration(environment: environment)
        executionTimeAllowance = TimeInterval(configuration.durationSeconds + 300)

        let app = XCUIApplication()
        app.launchEnvironment[Self.debugLoggingKey] =
            configuration.debugLoggingEnabled ? "1" : "0"
        app.launch()
        try ensureConnected(app)

        let startedAt = ProcessInfo.processInfo.systemUptime
        var samples: [CampaignSample] = []
        var runtimeGenerations: [String: UInt64] = [:]
        var nextRuntimeGeneration: UInt64 = 1
        var heldConnections: [NWConnection] = []
        var physicalFootprintSamples: [UInt64] = []
        var closedConnections: UInt64 = 0
        var safetyLimitReached = false
        var safetyLimitStage = "none"
        var highestTCPFlowsWithinLimit = 0
        var highestUDPFlowsWithinLimit = 0

        do {
            let baselineResult = try await sampleMemoryStage(
                app,
                label: "baseline",
                seconds: configuration.stageSeconds,
                minimumActiveConnections: 0,
                safetyPhysicalFootprintLimitBytes: configuration.maxPhysicalFootprintBytes,
                startedAt: startedAt,
                samples: &samples,
                physicalFootprintSamples: &physicalFootprintSamples,
                runtimeGenerations: &runtimeGenerations,
                nextRuntimeGeneration: &nextRuntimeGeneration
            )
            let baselineSamples = samples
            let baselinePhysicalFootprintSamples = physicalFootprintSamples
            if baselineResult.safetyLimitReached {
                safetyLimitReached = true
                safetyLimitStage = "baseline"
            }

            for target in safetyLimitReached ? [] : [32, 64, 128, 192, 240] {
                let added = try await Self.openTCPHoldConnections(
                    count: target - heldConnections.count,
                    host: configuration.loadHost,
                    port: configuration.loadPort,
                    token: configuration.loadToken
                )
                heldConnections.append(contentsOf: added)
                let stageResult = try await sampleMemoryStage(
                    app,
                    label: "tcp-\(target)",
                    seconds: configuration.stageSeconds,
                    minimumActiveConnections: UInt64(target),
                    safetyPhysicalFootprintLimitBytes: configuration.maxPhysicalFootprintBytes,
                    startedAt: startedAt,
                    samples: &samples,
                    physicalFootprintSamples: &physicalFootprintSamples,
                    runtimeGenerations: &runtimeGenerations,
                    nextRuntimeGeneration: &nextRuntimeGeneration
                )
                if stageResult.safetyLimitReached {
                    safetyLimitReached = true
                    safetyLimitStage = "tcp-\(target)"
                    break
                }
                highestTCPFlowsWithinLimit = target
            }

            var drainResult = try await drainConnections(
                app,
                startedAt: startedAt,
                runtimeGenerations: &runtimeGenerations,
                nextRuntimeGeneration: &nextRuntimeGeneration
            )
            closedConnections += drainResult.closedConnections
            try validateMemorySample(drainResult.sample)
            samples.append(drainResult.sample)
            emit(drainResult.sample)
            heldConnections.forEach { $0.cancel() }
            heldConnections.removeAll()
            try await sleep(seconds: 2)

            for target in safetyLimitReached ? [] : [64, 128, 256, 384, 480] {
                let added = try await Self.openHeldUDPConnections(
                    count: target - heldConnections.count,
                    host: configuration.UDPHost,
                    port: configuration.UDPPort
                )
                heldConnections.append(contentsOf: added)
                try await Self.refreshHeldUDPConnections(heldConnections)
                let stageResult = try await sampleMemoryStage(
                    app,
                    label: "udp-\(target)",
                    seconds: configuration.stageSeconds,
                    minimumActiveConnections: UInt64(target),
                    safetyPhysicalFootprintLimitBytes: configuration.maxPhysicalFootprintBytes,
                    startedAt: startedAt,
                    samples: &samples,
                    physicalFootprintSamples: &physicalFootprintSamples,
                    runtimeGenerations: &runtimeGenerations,
                    nextRuntimeGeneration: &nextRuntimeGeneration
                )
                if stageResult.safetyLimitReached {
                    safetyLimitReached = true
                    safetyLimitStage = "udp-\(target)"
                    break
                }
                highestUDPFlowsWithinLimit = target
            }

            drainResult = try await drainConnections(
                app,
                startedAt: startedAt,
                runtimeGenerations: &runtimeGenerations,
                nextRuntimeGeneration: &nextRuntimeGeneration
            )
            closedConnections += drainResult.closedConnections
            try validateMemorySample(drainResult.sample)
            samples.append(drainResult.sample)
            emit(drainResult.sample)
            heldConnections.forEach { $0.cancel() }
            heldConnections.removeAll()

            let recoveryStart = samples.count
            let recoveryPhysicalFootprintStart = physicalFootprintSamples.count
            _ = try await sampleMemoryStage(
                app,
                label: "recovery",
                seconds: configuration.recoverySeconds,
                minimumActiveConnections: 0,
                safetyPhysicalFootprintLimitBytes: nil,
                startedAt: startedAt,
                samples: &samples,
                physicalFootprintSamples: &physicalFootprintSamples,
                runtimeGenerations: &runtimeGenerations,
                nextRuntimeGeneration: &nextRuntimeGeneration
            )
            let recoverySamples = Array(samples[recoveryStart...])
            let baselineRSS = Self.median(
                baselineSamples.map(\.residentMemoryBytes)
            )
            let recoveredRSS = Self.median(
                Array(recoverySamples.suffix(5)).map(\.residentMemoryBytes)
            )
            let baselinePhysicalFootprint = Self.median(
                baselinePhysicalFootprintSamples
            )
            let recoveryPhysicalFootprintSamples = Array(
                physicalFootprintSamples[recoveryPhysicalFootprintStart...]
            )
            let recoveredPhysicalFootprint = Self.median(
                Array(recoveryPhysicalFootprintSamples.suffix(5))
            )
            let baselineThreads = Self.median(
                baselineSamples.map(\.threadCount)
            )
            let recoveredThreads = Self.median(
                Array(recoverySamples.suffix(5)).map(\.threadCount)
            )
            let footprintAllowance = max(
                8 * 1024 * 1024,
                baselinePhysicalFootprint / 4
            )
            guard recoveredPhysicalFootprint
                <= baselinePhysicalFootprint + footprintAllowance
            else {
                throw CampaignError.memoryStressPhysicalFootprintDidNotRecover(
                    baseline: baselinePhysicalFootprint,
                    recovered: recoveredPhysicalFootprint
                )
            }
            guard recoveredThreads <= baselineThreads + 4 else {
                throw CampaignError.memoryStressThreadLeak(
                    baseline: baselineThreads,
                    recovered: recoveredThreads
                )
            }

            drainResult = try await drainConnections(
                app,
                startedAt: startedAt,
                runtimeGenerations: &runtimeGenerations,
                nextRuntimeGeneration: &nextRuntimeGeneration
            )
            closedConnections += drainResult.closedConnections
            try validateMemorySample(drainResult.sample)
            samples.append(drainResult.sample)
            emit(drainResult.sample)
            try disconnect(app)
            let terminalElapsed = max(
                UInt64(ProcessInfo.processInfo.systemUptime - startedAt),
                drainResult.sample.elapsedSeconds + 1
            )
            let terminalSample = drainResult.sample.afterDisconnect(
                elapsedSeconds: terminalElapsed
            )
            samples.append(terminalSample)
            emit(terminalSample)
            addCampaignAttachment(samples)

            let peakRSS = samples.map(\.residentMemoryBytes).max() ?? 0
            let peakPhysicalFootprint = physicalFootprintSamples.max() ?? 0
            print(
                "XRAY_DEVICE_MEMORY_RESULT baselineRSS=\(baselineRSS) "
                    + "peakRSS=\(peakRSS) recoveredRSS=\(recoveredRSS) "
                    + "baselinePhysicalFootprint=\(baselinePhysicalFootprint) "
                    + "peakPhysicalFootprint=\(peakPhysicalFootprint) "
                    + "recoveredPhysicalFootprint=\(recoveredPhysicalFootprint) "
                    + "safetyLimitPhysicalFootprint="
                    + "\(configuration.maxPhysicalFootprintBytes) "
                    + "safetyLimitReached=\(safetyLimitReached) "
                    + "stopStage=\(safetyLimitStage) "
                    + "highestTCPFlows=\(highestTCPFlowsWithinLimit) "
                    + "highestUDPFlows=\(highestUDPFlowsWithinLimit) "
                    + "closedConnections=\(closedConnections)"
            )
            XCTAssertGreaterThan(
                closedConnections,
                0,
                "provider did not accept memory-stress connection closures"
            )
        } catch {
            heldConnections.forEach { $0.cancel() }
            try? disconnect(app)
            throw error
        }
    }

    @MainActor
    func testLaunchPerformance() throws {
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }

    @MainActor
    private func ensureConnected(_ app: XCUIApplication) throws {
        let status = app.descendants(matching: .any)["xray.connection.status"]
        XCTAssertTrue(status.waitForExistence(timeout: 15), "connection status is missing")
        if status.value as? String == "Connected" {
            return
        }

        let connect = app.buttons["Connect"]
        XCTAssertTrue(connect.waitForExistence(timeout: 5), "Connect button is missing")
        try waitUntilEnabled(connect, timeout: 5, operation: "connect")
        connect.tap()
        let systemAlert = XCUIApplication(bundleIdentifier: "com.apple.springboard")
            .alerts.firstMatch
        if systemAlert.waitForExistence(timeout: 3) {
            throw CampaignError.VPNApprovalRequired
        }
        if status.value as? String == "Connected" {
            return
        }
        let connected = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "value == %@", "Connected"),
            object: status
        )
        XCTAssertEqual(
            XCTWaiter.wait(for: [connected], timeout: 45),
            .completed,
            "tunnel did not reach Connected"
        )
    }

    @MainActor
    private func disconnect(_ app: XCUIApplication) throws {
        let disconnect = app.buttons["Disconnect"]
        XCTAssertTrue(disconnect.waitForExistence(timeout: 5), "Disconnect button is missing")
        try waitUntilEnabled(disconnect, timeout: 10, operation: "disconnect")
        disconnect.tap()
        let status = app.descendants(matching: .any)["xray.connection.status"]
        let disconnected = XCTNSPredicateExpectation(
            predicate: NSPredicate(
                format: "value == %@ OR label CONTAINS %@",
                "Disconnected",
                "Disconnected"
            ),
            object: status
        )
        XCTAssertEqual(
            XCTWaiter.wait(for: [disconnected], timeout: 30),
            .completed,
            "tunnel did not reach Disconnected after teardown"
        )
    }

    @MainActor
    private func refresh(_ app: XCUIApplication) async throws {
        let refresh = app.buttons["Refresh"]
        XCTAssertTrue(refresh.waitForExistence(timeout: 5), "Refresh button is missing")
        refresh.tap()
        try await sleep(seconds: 1)
    }

    @MainActor
    private func drainConnections(
        _ app: XCUIApplication,
        startedAt: TimeInterval,
        runtimeGenerations: inout [String: UInt64],
        nextRuntimeGeneration: inout UInt64
    ) async throws -> DrainResult {
        let closeConnections = app.buttons["xray.runtime.closeConnections"]
        XCTAssertTrue(
            closeConnections.waitForExistence(timeout: 5),
            "Close active flows button is missing"
        )

        var sample: CampaignSample?
        var closedConnections: UInt64 = 0
        for _ in 0 ..< 5 {
            try waitUntilEnabled(
                closeConnections,
                timeout: 10,
                operation: "close active flows"
            )
            closeConnections.tap()
            try await Task.sleep(nanoseconds: 100_000_000)
            try waitUntilEnabled(
                closeConnections,
                timeout: 10,
                operation: "close active flows"
            )
            closedConnections += try unsignedValue(
                app,
                identifier: "xray.runtime.lastClosedConnections"
            )
            try await refresh(app)
            sample = try readSample(
                app,
                elapsedSeconds: Int(ProcessInfo.processInfo.systemUptime - startedAt),
                runtimeGenerations: &runtimeGenerations,
                nextRuntimeGeneration: &nextRuntimeGeneration
            )
            if sample?.activeConnections == 0 {
                break
            }
        }
        return DrainResult(
            sample: try XCTUnwrap(sample),
            closedConnections: closedConnections
        )
    }

    @MainActor
    private func waitUntilEnabled(
        _ element: XCUIElement,
        timeout: TimeInterval,
        operation: String
    ) throws {
        guard !element.isEnabled else {
            return
        }
        let enabled = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "enabled == true"),
            object: element
        )
        guard XCTWaiter.wait(for: [enabled], timeout: timeout) == .completed else {
            throw CampaignError.UIOperationTimedOut(operation)
        }
    }

    @MainActor
    private func readSample(
        _ app: XCUIApplication,
        elapsedSeconds: Int,
        runtimeGenerations: inout [String: UInt64],
        nextRuntimeGeneration: inout UInt64
    ) throws -> CampaignSample {
        let inbound = try unsignedValue(app, identifier: "xray.runtime.inboundPackets")
        let outbound = try unsignedValue(app, identifier: "xray.runtime.outboundPackets")
        let telemetry = try telemetryValue(app)
        let runtimeIdentifier = try requiredTelemetry("runtimeIdentifier", from: telemetry)
        let activeTCPFlows = try unsignedTelemetry("activeTCPFlows", from: telemetry)
        let activeUDPFlows = try unsignedTelemetry("activeUDPFlows", from: telemetry)
        let generation: UInt64
        if let knownGeneration = runtimeGenerations[runtimeIdentifier] {
            generation = knownGeneration
        } else {
            generation = nextRuntimeGeneration
            runtimeGenerations[runtimeIdentifier] = generation
            nextRuntimeGeneration += 1
        }

        let sample = CampaignSample(
            elapsedSeconds: UInt64(elapsedSeconds),
            runtimeGeneration: generation,
            residentMemoryBytes: try unsignedTelemetry("residentMemoryBytes", from: telemetry),
            threadCount: try unsignedTelemetry("threadCount", from: telemetry),
            activeConnections: activeTCPFlows + activeUDPFlows,
            tunInboundPackets: inbound,
            tunOutboundPackets: outbound,
            fatalTunErrors: 0,
            unrecoveredTransitions: 0
        )
        print(
            "XRAY_DEVICE_FLOW_SAMPLE elapsedSeconds=\(elapsedSeconds) "
                + "activeTCPFlows=\(activeTCPFlows) activeUDPFlows=\(activeUDPFlows)"
        )
        return sample
    }

    @MainActor
    private func unsignedValue(_ app: XCUIApplication, identifier: String) throws -> UInt64 {
        let element = app.descendants(matching: .any)[identifier]
        XCTAssertTrue(element.waitForExistence(timeout: 5), "missing \(identifier)")
        guard let rawValue = element.value as? String, let value = UInt64(rawValue) else {
            throw CampaignError.invalidAccessibilityValue(identifier)
        }
        return value
    }

    @MainActor
    private func telemetryValue(_ app: XCUIApplication) throws -> [String: String] {
        let identifier = "xray.runtime.campaignTelemetry"
        let element = app.descendants(matching: .any)[identifier]
        XCTAssertTrue(element.waitForExistence(timeout: 5), "missing \(identifier)")
        guard let rawValue = element.value as? String else {
            throw CampaignError.invalidAccessibilityValue(identifier)
        }
        return Dictionary(
            uniqueKeysWithValues: rawValue.split(separator: ";").compactMap { component in
                let fields = component.split(separator: "=", maxSplits: 1)
                guard fields.count == 2 else {
                    return nil
                }
                return (String(fields[0]), String(fields[1]))
            }
        )
    }

    private func requiredTelemetry(
        _ key: String,
        from telemetry: [String: String]
    ) throws -> String {
        guard let value = telemetry[key], !value.isEmpty else {
            throw CampaignError.missingTelemetry(key)
        }
        return value
    }

    private func unsignedTelemetry(
        _ key: String,
        from telemetry: [String: String]
    ) throws -> UInt64 {
        guard let rawValue = telemetry[key], let value = UInt64(rawValue) else {
            throw CampaignError.missingTelemetry(key)
        }
        return value
    }

    @MainActor
    private func sampleMemoryStage(
        _ app: XCUIApplication,
        label: String,
        seconds: Int,
        minimumActiveConnections: UInt64,
        safetyPhysicalFootprintLimitBytes: UInt64?,
        startedAt: TimeInterval,
        samples: inout [CampaignSample],
        physicalFootprintSamples: inout [UInt64],
        runtimeGenerations: inout [String: UInt64],
        nextRuntimeGeneration: inout UInt64
    ) async throws -> MemoryStageResult {
        let deadline = ProcessInfo.processInfo.systemUptime + TimeInterval(seconds)
        var lastSample: CampaignSample?
        var safetyLimitReached = false
        repeat {
            try await refresh(app)
            let wallElapsed = UInt64(ProcessInfo.processInfo.systemUptime - startedAt)
            let elapsed = max(wallElapsed, (samples.last?.elapsedSeconds ?? 0) + 1)
            let sample = try readSample(
                app,
                elapsedSeconds: Int(elapsed),
                runtimeGenerations: &runtimeGenerations,
                nextRuntimeGeneration: &nextRuntimeGeneration
            )
            try validateMemorySample(sample)
            let physicalFootprintBytes = try unsignedTelemetry(
                "physicalFootprintBytes",
                from: try telemetryValue(app)
            )
            guard physicalFootprintBytes > 0 else {
                throw CampaignError.missingTelemetry("physicalFootprintBytes")
            }
            samples.append(sample)
            physicalFootprintSamples.append(physicalFootprintBytes)
            emit(sample)
            lastSample = sample
            print(
                "XRAY_DEVICE_MEMORY_STAGE label=\(label) "
                    + "activeConnections=\(sample.activeConnections) "
                    + "residentMemoryBytes=\(sample.residentMemoryBytes) "
                    + "physicalFootprintBytes=\(physicalFootprintBytes)"
            )
            if let safetyPhysicalFootprintLimitBytes,
               physicalFootprintBytes > safetyPhysicalFootprintLimitBytes
            {
                safetyLimitReached = true
                break
            }
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if remaining > 0 {
                try await Task.sleep(
                    nanoseconds: UInt64(min(5, remaining) * 1_000_000_000)
                )
            }
        } while ProcessInfo.processInfo.systemUptime < deadline

        guard let lastSample,
              lastSample.activeConnections >= minimumActiveConnections
        else {
            throw CampaignError.memoryStressInsufficientFlows(
                expected: minimumActiveConnections,
                observed: lastSample?.activeConnections ?? 0
            )
        }
        return MemoryStageResult(
            safetyLimitReached: safetyLimitReached
        )
    }

    private func validateMemorySample(_ sample: CampaignSample) throws {
        guard sample.runtimeGeneration == 1 else {
            throw CampaignError.memoryStressRuntimeRestarted(sample.runtimeGeneration)
        }
    }

    private static func median(_ values: [UInt64]) -> UInt64 {
        precondition(!values.isEmpty)
        let sorted = values.sorted()
        let middle = sorted.count / 2
        if sorted.count.isMultiple(of: 2) {
            return sorted[middle - 1] + (sorted[middle] - sorted[middle - 1]) / 2
        }
        return sorted[middle]
    }

    @available(iOS 17.0, *)
    private static func openTCPHoldConnections(
        count: Int,
        host: NWEndpoint.Host,
        port: NWEndpoint.Port,
        token: String
    ) async throws -> [NWConnection] {
        try await openConnections(count: count, batchSize: 16) {
            try await openTCPHoldConnection(host: host, port: port, token: token)
        }
    }

    @available(iOS 17.0, *)
    private static func openHeldUDPConnections(
        count: Int,
        host: NWEndpoint.Host,
        port: NWEndpoint.Port
    ) async throws -> [NWConnection] {
        try await openConnections(count: count, batchSize: 32) {
            try await openHeldUDPConnection(host: host, port: port)
        }
    }

    @available(iOS 17.0, *)
    private static func openConnections(
        count: Int,
        batchSize: Int,
        operation: @escaping @Sendable () async throws -> NWConnection
    ) async throws -> [NWConnection] {
        var connections: [NWConnection] = []
        while connections.count < count {
            let currentBatch = min(batchSize, count - connections.count)
            var opened: [NWConnection] = []
            do {
                try await withThrowingTaskGroup(of: NWConnection.self) { group in
                    for _ in 0 ..< currentBatch {
                        group.addTask {
                            try await operation()
                        }
                    }
                    for try await connection in group {
                        opened.append(connection)
                    }
                }
            } catch {
                opened.forEach { $0.cancel() }
                connections.forEach { $0.cancel() }
                throw error
            }
            connections.append(contentsOf: opened)
        }
        return connections
    }

    private static func openTCPHoldConnection(
        host: NWEndpoint.Host,
        port: NWEndpoint.Port,
        token: String
    ) async throws -> NWConnection {
        let connection = NWConnection(host: host, port: port, using: .tcp)
        let request = Data("XRAY-MEMORY-HOLD/1 \(token)\n".utf8)
        let expected = Data("XRAY-MEMORY-HOLD/1 READY\n".utf8)
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let completion = UDPProbeCompletion(continuation: continuation)
                    completion.scheduleTimeout(
                        on: memoryStressNetworkQueue,
                        seconds: 15,
                        error: CampaignError.memoryStressOperationTimedOut
                    )
                    connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            connection.stateUpdateHandler = nil
                            connection.send(
                                content: request,
                                completion: .contentProcessed { error in
                                    if let error {
                                        completion.finish(.failure(error))
                                        return
                                    }
                                    connection.receive(
                                        minimumIncompleteLength: expected.count,
                                        maximumLength: expected.count
                                    ) { data, _, _, receiveError in
                                        if let receiveError {
                                            completion.finish(.failure(receiveError))
                                        } else if data == expected {
                                            completion.finish(.success(()))
                                        } else {
                                            completion.finish(
                                                .failure(
                                                    CampaignError
                                                        .memoryStressHandshakeFailed
                                                )
                                            )
                                        }
                                    }
                                }
                            )
                        case let .failed(error):
                            completion.finish(.failure(error))
                        case .cancelled:
                            completion.finish(.failure(CancellationError()))
                        default:
                            break
                        }
                    }
                    connection.start(queue: memoryStressNetworkQueue)
                }
            } onCancel: {
                connection.cancel()
            }
            return connection
        } catch {
            connection.cancel()
            throw error
        }
    }

    private static func openHeldUDPConnection(
        host: NWEndpoint.Host,
        port: NWEndpoint.Port
    ) async throws -> NWConnection {
        let connection = NWConnection(host: host, port: port, using: .udp)
        let query = makeDNSQuery()
        do {
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let completion = UDPProbeCompletion(continuation: continuation)
                    completion.scheduleTimeout(
                        on: memoryStressNetworkQueue,
                        seconds: 10,
                        error: CampaignError.memoryStressOperationTimedOut
                    )
                    connection.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            connection.stateUpdateHandler = nil
                            sendHeldUDPQuery(
                                query,
                                connection: connection,
                                completion: completion
                            )
                        case let .failed(error):
                            completion.finish(.failure(error))
                        case .cancelled:
                            completion.finish(.failure(CancellationError()))
                        default:
                            break
                        }
                    }
                    connection.start(queue: memoryStressNetworkQueue)
                }
            } onCancel: {
                connection.cancel()
            }
            return connection
        } catch {
            connection.cancel()
            throw error
        }
    }

    @available(iOS 17.0, *)
    private static func refreshHeldUDPConnections(
        _ connections: [NWConnection]
    ) async throws {
        for start in stride(from: 0, to: connections.count, by: 32) {
            let end = min(start + 32, connections.count)
            try await withThrowingTaskGroup(of: Void.self) { group in
                for connection in connections[start ..< end] {
                    group.addTask {
                        let query = makeDNSQuery()
                        try await withCheckedThrowingContinuation { continuation in
                            let completion = UDPProbeCompletion(
                                continuation: continuation
                            )
                            completion.scheduleTimeout(
                                on: memoryStressNetworkQueue,
                                seconds: 10,
                                error: CampaignError.memoryStressOperationTimedOut
                            )
                            sendHeldUDPQuery(
                                query,
                                connection: connection,
                                completion: completion
                            )
                        }
                    }
                }
                try await group.waitForAll()
            }
        }
    }

    private static func sendHeldUDPQuery(
        _ query: Data,
        connection: NWConnection,
        completion: UDPProbeCompletion
    ) {
        connection.send(
            content: query,
            completion: .contentProcessed { error in
                if let error {
                    completion.finish(.failure(error))
                    return
                }
                connection.receiveMessage { response, _, _, receiveError in
                    if let receiveError {
                        completion.finish(.failure(receiveError))
                    } else if let response,
                              isValidDNSResponse(response, for: query)
                    {
                        completion.finish(.success(()))
                    } else {
                        completion.finish(
                            .failure(CampaignError.UDPProbeInvalidResponse)
                        )
                    }
                }
            }
        )
    }

    @MainActor
    private func pumpTraffic(configuration: CampaignConfiguration) async -> TrafficProbeSummary {
        let sessionConfiguration = URLSessionConfiguration.ephemeral
        sessionConfiguration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        sessionConfiguration.timeoutIntervalForRequest = 15
        let session = URLSession(configuration: sessionConfiguration)
        defer { session.invalidateAndCancel() }
        var summary = TrafficProbeSummary()

        while !Task.isCancelled {
            do {
                var request = URLRequest(url: configuration.HTTPURL)
                request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
                let (_, response) = try await session.data(for: request)
                guard let HTTPResponse = response as? HTTPURLResponse,
                      (200 ..< 400).contains(HTTPResponse.statusCode)
                else {
                    throw CampaignError.HTTPProbeFailed
                }
                summary.httpSuccesses += 1
                print(
                    "XRAY_DEVICE_PROBE kind=http result=passed "
                        + "sequence=\(summary.httpSuccesses)"
                )
            } catch is CancellationError {
                return summary
            } catch {
                print(
                    "XRAY_DEVICE_PROBE kind=http result=failed "
                        + "error=\(Self.probeErrorCode(error))"
                )
            }

            do {
                try await sendUDPProbe(
                    host: configuration.UDPHost,
                    port: configuration.UDPPort
                )
                summary.udpSuccesses += 1
                print(
                    "XRAY_DEVICE_PROBE kind=udp result=passed "
                        + "sequence=\(summary.udpSuccesses)"
                )
            } catch is CancellationError {
                return summary
            } catch {
                print(
                    "XRAY_DEVICE_PROBE kind=udp result=failed "
                        + "error=\(Self.probeErrorCode(error))"
                )
            }

            do {
                try await sleep(seconds: 5)
            } catch {
                return summary
            }
        }
        return summary
    }

    private func sendUDPProbe(host: NWEndpoint.Host, port: NWEndpoint.Port) async throws {
        let queue = DispatchQueue(label: "org.xrayrust.device-campaign.udp")
        let connection = NWConnection(host: host, port: port, using: .udp)
        let query = Self.makeDNSQuery()
        defer { connection.cancel() }

        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (
                continuation: CheckedContinuation<Void, Error>
            ) in
                let completion = UDPProbeCompletion(continuation: continuation)
                completion.scheduleTimeout(on: queue, seconds: 5)
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        connection.stateUpdateHandler = nil
                        connection.send(
                            content: query,
                            completion: .contentProcessed { error in
                                if let error {
                                    completion.finish(.failure(error))
                                    return
                                }
                                connection.receiveMessage {
                                    response, _, _, receiveError in
                                    if let receiveError {
                                        completion.finish(.failure(receiveError))
                                    } else if let response,
                                              Self.isValidDNSResponse(response, for: query)
                                    {
                                        completion.finish(.success(()))
                                    } else {
                                        completion.finish(
                                            .failure(CampaignError.UDPProbeInvalidResponse)
                                        )
                                    }
                                }
                            }
                        )
                    case let .failed(error):
                        completion.finish(.failure(error))
                    case .cancelled:
                        completion.finish(.failure(CancellationError()))
                    default:
                        break
                    }
                }
                connection.start(queue: queue)
            }
        } onCancel: {
            connection.cancel()
        }
    }

    private static func makeDNSQuery(
        transactionID: UInt16 = UInt16.random(in: UInt16.min ... UInt16.max),
        nonce: UUID = UUID()
    ) -> Data {
        let nonceLabel = "xray-" + nonce.uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        var query = Data([
            UInt8(transactionID >> 8), UInt8(transactionID & 0xff),
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ])
        for label in [nonceLabel, "example", "com"] {
            let bytes = Array(label.utf8)
            precondition(bytes.count <= 63)
            query.append(UInt8(bytes.count))
            query.append(contentsOf: bytes)
        }
        query.append(contentsOf: [0x00, 0x00, 0x01, 0x00, 0x01])
        return query
    }

    private static func isValidDNSResponse(_ response: Data, for query: Data) -> Bool {
        guard query.count >= 12,
              response.count == query.count + DNSProbeAnswer.count
        else {
            return false
        }
        return response[0] == query[0]
            && response[1] == query[1]
            && response[2] == 0x81
            && response[3] == 0x80
            && response[4] == 0x00
            && response[5] == 0x01
            && response[6] == 0x00
            && response[7] == 0x01
            && response[8] == 0x00
            && response[9] == 0x00
            && response[10] == 0x00
            && response[11] == 0x00
            && response[12 ..< query.count] == query[12 ..< query.count]
            && response[query.count...] == DNSProbeAnswer
    }

    private static func probeErrorCode(_ error: Error) -> String {
        if let networkError = error as? NWError {
            switch networkError {
            case let .posix(code):
                return "nw-posix-\(code.rawValue)"
            case let .dns(code):
                return "nw-dns-\(code)"
            case let .tls(code):
                return "nw-tls-\(code)"
            case .wifiAware:
                return "nw-wifi-aware"
            @unknown default:
                return "nw-unknown"
            }
        }
        if let URLFailure = error as? URLError {
            return "url-\(URLFailure.code.rawValue)"
        }
        switch error {
        case CampaignError.HTTPProbeFailed:
            return "http-status"
        case CampaignError.UDPProbeInvalidResponse:
            return "udp-invalid-response"
        case CampaignError.UDPProbeTimedOut:
            return "udp-timeout"
        default:
            return "other"
        }
    }

    private func emit(_ sample: CampaignSample) {
        guard let data = try? JSONEncoder().encode(sample),
              let JSON = String(data: data, encoding: .utf8)
        else {
            XCTFail("failed to encode campaign sample")
            return
        }
        print("XRAY_DEVICE_SAMPLE \(JSON)")
    }

    private func sleep(seconds: Int) async throws {
        try await Task.sleep(nanoseconds: UInt64(seconds) * 1_000_000_000)
    }

    private func addCampaignAttachment(_ samples: [CampaignSample]) {
        guard let data = try? JSONEncoder().encode(samples) else {
            XCTFail("failed to encode campaign attachment")
            return
        }
        let attachment = XCTAttachment(data: data, uniformTypeIdentifier: "public.json")
        attachment.name = "apple-device-samples.json"
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private static let DNSProbeAnswer = Data([
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x04, 0xcb, 0x00, 0x71, 0x01,
    ])
    private static let memoryStressNetworkQueue = DispatchQueue(
        label: "org.xrayrust.device-memory-stress",
        qos: .utility,
        attributes: .concurrent
    )

}

private struct CampaignConfiguration {
    let durationSeconds: Int
    let sampleIntervalSeconds: Int
    let HTTPURL: URL
    let UDPHost: NWEndpoint.Host
    let UDPPort: NWEndpoint.Port
    let debugLoggingEnabled: Bool

    init(environment: [String: String]) throws {
        guard let duration = Int(environment[XrayClientUITests.durationKey] ?? ""),
              (30 ... 28_800).contains(duration)
        else {
            throw CampaignError.invalidConfiguration(XrayClientUITests.durationKey)
        }
        guard let interval = Int(environment[XrayClientUITests.intervalKey] ?? ""),
              (5 ... 60).contains(interval)
        else {
            throw CampaignError.invalidConfiguration(XrayClientUITests.intervalKey)
        }
        guard let rawHTTPURL = environment[XrayClientUITests.HTTPURLKey],
              let HTTPURL = URL(string: rawHTTPURL),
              HTTPURL.scheme == "https",
              HTTPURL.host != nil
        else {
            throw CampaignError.invalidConfiguration(XrayClientUITests.HTTPURLKey)
        }
        guard let rawUDPHost = environment[XrayClientUITests.UDPHostKey],
              !rawUDPHost.isEmpty
        else {
            throw CampaignError.invalidConfiguration(XrayClientUITests.UDPHostKey)
        }
        guard let rawUDPPort = environment[XrayClientUITests.UDPPortKey],
              let UDPPort = NWEndpoint.Port(rawUDPPort)
        else {
            throw CampaignError.invalidConfiguration(XrayClientUITests.UDPPortKey)
        }

        self.durationSeconds = duration
        sampleIntervalSeconds = interval
        self.HTTPURL = HTTPURL
        UDPHost = NWEndpoint.Host(rawUDPHost)
        self.UDPPort = UDPPort
        debugLoggingEnabled = environment[XrayClientUITests.debugLoggingKey] == "1"
    }
}

private struct MemoryStressConfiguration {
    let durationSeconds: Int
    let UDPHost: NWEndpoint.Host
    let UDPPort: NWEndpoint.Port
    let loadHost: NWEndpoint.Host
    let loadPort: NWEndpoint.Port
    let loadToken: String
    let stageSeconds: Int
    let recoverySeconds: Int
    let maxPhysicalFootprintBytes: UInt64
    let debugLoggingEnabled: Bool

    init(environment: [String: String]) throws {
        guard let duration = Int(environment[XrayClientUITests.durationKey] ?? ""),
              (140 ... 3_600).contains(duration)
        else {
            throw CampaignError.invalidConfiguration(XrayClientUITests.durationKey)
        }
        guard let rawUDPHost = environment[XrayClientUITests.UDPHostKey],
              !rawUDPHost.isEmpty,
              let rawUDPPort = environment[XrayClientUITests.UDPPortKey],
              let UDPPort = NWEndpoint.Port(rawUDPPort)
        else {
            throw CampaignError.invalidConfiguration(XrayClientUITests.UDPHostKey)
        }
        guard let rawLoadHost = environment[XrayClientUITests.memoryStressHostKey],
              !rawLoadHost.isEmpty,
              let rawLoadPort = environment[XrayClientUITests.memoryStressPortKey],
              let loadPort = NWEndpoint.Port(rawLoadPort)
        else {
            throw CampaignError.invalidConfiguration(
                XrayClientUITests.memoryStressHostKey
            )
        }
        guard let token = environment[XrayClientUITests.memoryStressTokenKey],
              token.utf8.count == 64,
              token.utf8.allSatisfy({
                  (48 ... 57).contains($0) || (97 ... 102).contains($0)
              })
        else {
            throw CampaignError.invalidConfiguration(
                XrayClientUITests.memoryStressTokenKey
            )
        }
        guard let stageSeconds = Int(
            environment[XrayClientUITests.memoryStressStageSecondsKey] ?? ""
        ), (10 ... 120).contains(stageSeconds) else {
            throw CampaignError.invalidConfiguration(
                XrayClientUITests.memoryStressStageSecondsKey
            )
        }
        guard let recoverySeconds = Int(
            environment[XrayClientUITests.memoryStressRecoverySecondsKey] ?? ""
        ), (30 ... 600).contains(recoverySeconds) else {
            throw CampaignError.invalidConfiguration(
                XrayClientUITests.memoryStressRecoverySecondsKey
            )
        }
        guard let maxPhysicalFootprintBytes = UInt64(
            environment[
                XrayClientUITests.memoryStressMaxPhysicalFootprintBytesKey
            ] ?? ""
        ), (24 * 1024 * 1024 ... 128 * 1024 * 1024).contains(
            maxPhysicalFootprintBytes
        ) else {
            throw CampaignError.invalidConfiguration(
                XrayClientUITests.memoryStressMaxPhysicalFootprintBytesKey
            )
        }

        durationSeconds = duration
        UDPHost = NWEndpoint.Host(rawUDPHost)
        self.UDPPort = UDPPort
        loadHost = NWEndpoint.Host(rawLoadHost)
        self.loadPort = loadPort
        loadToken = token
        self.stageSeconds = stageSeconds
        self.recoverySeconds = recoverySeconds
        self.maxPhysicalFootprintBytes = maxPhysicalFootprintBytes
        debugLoggingEnabled = environment[XrayClientUITests.debugLoggingKey] == "1"
    }
}

private struct CampaignSample: Codable {
    let elapsedSeconds: UInt64
    let runtimeGeneration: UInt64
    let residentMemoryBytes: UInt64
    let threadCount: UInt64
    let activeConnections: UInt64
    let tunInboundPackets: UInt64
    let tunOutboundPackets: UInt64
    let fatalTunErrors: UInt64
    let unrecoveredTransitions: UInt64

    func afterDisconnect(elapsedSeconds: UInt64) -> CampaignSample {
        CampaignSample(
            elapsedSeconds: elapsedSeconds,
            runtimeGeneration: runtimeGeneration,
            residentMemoryBytes: residentMemoryBytes,
            threadCount: threadCount,
            activeConnections: 0,
            tunInboundPackets: tunInboundPackets,
            tunOutboundPackets: tunOutboundPackets,
            fatalTunErrors: fatalTunErrors,
            unrecoveredTransitions: unrecoveredTransitions
        )
    }
}

private struct DrainResult {
    let sample: CampaignSample
    let closedConnections: UInt64
}

private struct MemoryStageResult {
    let safetyLimitReached: Bool
}

private struct TrafficProbeSummary: Sendable {
    var httpSuccesses = 0
    var udpSuccesses = 0
}

private enum CampaignError: Error {
    case invalidConfiguration(String)
    case invalidAccessibilityValue(String)
    case missingTelemetry(String)
    case UIOperationTimedOut(String)
    case VPNApprovalRequired
    case HTTPProbeFailed
    case UDPProbeInvalidResponse
    case UDPProbeTimedOut
    case memoryStressHandshakeFailed
    case memoryStressOperationTimedOut
    case memoryStressInsufficientFlows(expected: UInt64, observed: UInt64)
    case memoryStressRuntimeRestarted(UInt64)
    case memoryStressPhysicalFootprintDidNotRecover(
        baseline: UInt64,
        recovered: UInt64
    )
    case memoryStressThreadLeak(baseline: UInt64, recovered: UInt64)
}

private final class UDPProbeCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var timeout: DispatchWorkItem?

    init(continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    func scheduleTimeout(
        on queue: DispatchQueue,
        seconds: TimeInterval,
        error: Error = CampaignError.UDPProbeTimedOut
    ) {
        let workItem = DispatchWorkItem { [weak self] in
            self?.finish(.failure(error))
        }
        lock.withLock {
            timeout = workItem
        }
        queue.asyncAfter(deadline: .now() + seconds, execute: workItem)
    }

    func finish(_ result: Result<Void, Error>) {
        let pending: CheckedContinuation<Void, Error>? = lock.withLock {
            guard let continuation else {
                return nil
            }
            self.continuation = nil
            timeout?.cancel()
            timeout = nil
            return continuation
        }
        guard let pending else {
            return
        }
        switch result {
        case .success:
            pending.resume()
        case let .failure(error):
            pending.resume(throwing: error)
        }
    }
}
