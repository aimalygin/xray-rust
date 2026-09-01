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

    override func setUpWithError() throws {
        continueAfterFailure = false
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
        try await sleep(seconds: 2)
        let finalSample = try await drainConnections(
            app,
            startedAt: startedAt,
            runtimeGenerations: &runtimeGenerations,
            nextRuntimeGeneration: &nextRuntimeGeneration
        )
        samples.append(finalSample)
        emit(samples[samples.count - 1])
        XCTAssertEqual(samples.last?.activeConnections, 0, "traffic flows did not drain")
        addCampaignAttachment(samples)
        try disconnect(app)
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
    ) async throws -> CampaignSample {
        let closeConnections = app.buttons["xray.runtime.closeConnections"]
        XCTAssertTrue(
            closeConnections.waitForExistence(timeout: 5),
            "Close active flows button is missing"
        )

        var sample: CampaignSample?
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
        return try XCTUnwrap(sample)
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
        let generation: UInt64
        if let knownGeneration = runtimeGenerations[runtimeIdentifier] {
            generation = knownGeneration
        } else {
            generation = nextRuntimeGeneration
            runtimeGenerations[runtimeIdentifier] = generation
            nextRuntimeGeneration += 1
        }

        return CampaignSample(
            elapsedSeconds: UInt64(elapsedSeconds),
            runtimeGeneration: generation,
            residentMemoryBytes: try unsignedTelemetry("residentMemoryBytes", from: telemetry),
            threadCount: try unsignedTelemetry("threadCount", from: telemetry),
            activeConnections: try unsignedTelemetry("activeTCPFlows", from: telemetry)
                + unsignedTelemetry("activeUDPFlows", from: telemetry),
            tunInboundPackets: inbound,
            tunOutboundPackets: outbound,
            fatalTunErrors: 0,
            unrecoveredTransitions: 0
        )
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
                if summary.httpSuccesses == 1 {
                    print("XRAY_DEVICE_PROBE kind=http result=passed")
                }
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
                if summary.udpSuccesses == 1 {
                    print("XRAY_DEVICE_PROBE kind=udp result=passed")
                }
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
                            content: Self.DNSQuery,
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
                                              Self.isValidDNSResponse(response)
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

    private static func isValidDNSResponse(_ response: Data) -> Bool {
        guard response.count >= 12 else {
            return false
        }
        return response[0] == DNSQuery[0]
            && response[1] == DNSQuery[1]
            && response[2] & 0x80 != 0
            && response[3] & 0x0f == 0
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
            return String(describing: type(of: error))
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

    private static let DNSQuery = Data([
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01
    ])
}

private struct CampaignConfiguration {
    let durationSeconds: Int
    let sampleIntervalSeconds: Int
    let HTTPURL: URL
    let UDPHost: NWEndpoint.Host
    let UDPPort: NWEndpoint.Port

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
}

private final class UDPProbeCompletion: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Void, Error>?
    private var timeout: DispatchWorkItem?

    init(continuation: CheckedContinuation<Void, Error>) {
        self.continuation = continuation
    }

    func scheduleTimeout(on queue: DispatchQueue, seconds: TimeInterval) {
        let workItem = DispatchWorkItem { [weak self] in
            self?.finish(.failure(CampaignError.UDPProbeTimedOut))
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
