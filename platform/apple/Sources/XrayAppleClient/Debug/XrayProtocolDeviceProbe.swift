#if DEBUG && os(iOS)
import Foundation
import Network
@preconcurrency import NetworkExtension
import SwiftUI
import XrayAppleShared
import XrayMobileAdapter

/// Explicit, local development entry point. Normal launches never read the
/// fixture or touch the separate probe manager. No profile-store writes occur.
@available(iOS 15.0, *)
@MainActor
public struct XrayProtocolDeviceProbeView: View {
    @State private var status = "Preparing protocol checks…"
    @StateObject private var probe = ProtocolDeviceProbe()
    public init() {}
    public var body: some View {
        VStack(spacing: 16) {
            Text("Xray 0.7 device checks").font(.headline)
            Text(status).multilineTextAlignment(.center)
        }
        .padding()
        .task { await probe.run { status = $0 } }
    }
}

@MainActor
@available(iOS 15.0, *)
private final class ProtocolDeviceProbe: ObservableObject {
    private struct Fixture: Decodable {
        enum Mode: String, Decodable {
            case smoke, transitions
            case lockWake = "lock-wake"
            case transitionsReset = "transitions-reset"
        }
        let cases: [Profile]
        let tcpPort: UInt16
        let udpPort: UInt16
        let mode: Mode?
        let probeHost: String?
        var trafficHost: String { probeHost ?? "v07-probe.test" }
    }
    private struct Profile: Decodable {
        let format: XrayProfileFormat
        let text: String
        let configJSON: String
        let serverAddress: String
    }
    private enum Failure: Int, CustomNSError {
        case configuration, mismatch, missingStats, shutdown, budget, retainedFlows
        case transitionTimeout, unexpectedRuntimeRestart
        case transitionFailure
        static var errorDomain: String { "XrayProtocolDeviceProbe" }
        var errorCode: Int { rawValue }
    }
    private static let managerName = "Xray v0.7 Device Probe"
    private let controller = NetworkExtensionTunnelController(managerDescription: managerName)
    private let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    private var rows: [[String: Any]] = []
    private var label = "setup"

    func run(update: (String) -> Void) async {
        var passed = false
        do {
            let input = documents.appendingPathComponent("v07-probe.json")
            let size = try input.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard (1...524_288).contains(size) else { throw Failure.configuration }
            let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: input))
            guard (1...2).contains(fixture.cases.count), fixture.tcpPort > 0, fixture.udpPort > 0 else {
                throw Failure.configuration
            }
            let labels = fixture.trafficHost.split(separator: ".", omittingEmptySubsequences: false)
            guard fixture.trafficHost.hasSuffix(".test"), fixture.trafficHost.utf8.count <= 253,
                  labels.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 63 && $0.utf8.allSatisfy {
                      (97...122).contains($0) || (48...57).contains($0) || $0 == 45
                  } }) else { throw Failure.configuration }
            let info = XrayCore.ffiInfo
            emit(["event": "abi", "major": info.version.major, "minor": info.version.minor])
            try await cleanup()
            for item in fixture.cases {
                label = item.format.rawValue
                update("\(label): import and VPN startup")
                // Exercise the actual Swift -> FFI -> Rust import on the device.
                _ = try XrayProfileImporter.profile(from: item.text, format: item.format)
                emit(["event": "import", "result": "passed"])
                let profile = XrayClientProfile(
                    name: Self.managerName,
                    providerBundleIdentifier: XrayClientProfile.defaultProviderBundleIdentifier(
                        hostBundleIdentifier: Bundle.main.bundleIdentifier),
                    serverAddress: item.serverAddress, configJSON: item.configJSON,
                    debugLoggingEnabled: false, useTunFileDescriptor: true, tunRuntimeProfile: .mobile)
                if let mode = fixture.mode, mode != .smoke {
                    try await transitions(fixture, item: item, profile: profile, update: update)
                    try await cleanup()
                    continue
                }
                for cycle in 1...3 {
                    update("\(label): TCP, UDP and DNS — cycle \(cycle)/3")
                    let started = Date()
                    try await controller.start(profile: profile)
                    emit(["event": "connected", "cycle": cycle,
                          "seconds": Date().timeIntervalSince(started)])
                    try await traffic(fixture)
                    try await sample(cycle: cycle, stage: "after-traffic")
                    try await verifyConnectionClosure(cycle: cycle)
                    try await traffic(fixture)
                    emit(["event": "traffic-after-close", "cycle": cycle, "result": "passed"])
                    try await sample(cycle: cycle, stage: "after-recovery")
                    try await controller.stop()
                    try await waitDisconnected()
                    emit(["event": "disconnected", "cycle": cycle, "result": "passed"])
                }
                try await cleanup()
            }
            passed = true
        } catch {
            // Error domains/codes are enough to locate failures; config/key
            // material and untrusted server messages never enter the report.
            let error = error as NSError
            emit(["event": "failure", "domain": error.domain, "code": error.code])
            try? await sample(cycle: 0, stage: "failure")
        }
        do { try await cleanup() }
        catch { passed = false; emit(["event": "cleanup", "result": "failed"]) }
        do {
            let input = documents.appendingPathComponent("v07-probe.json")
            if FileManager.default.fileExists(atPath: input.path) {
                try FileManager.default.removeItem(at: input)
            }
        } catch { passed = false; emit(["event": "fixture-removal", "result": "failed"]) }
        emit(["event": "complete", "result": passed ? "passed" : "failed"])
        update(passed ? "Checks passed. Test VPN removed." : "A check failed. See the device report.")
    }

    private func transitions(_ fixture: Fixture, item: Profile, profile: XrayClientProfile,
                             update: (String) -> Void) async throws {
        guard let config = try JSONSerialization.jsonObject(with: Data(item.configJSON.utf8)) as? [String: Any],
              let outbound = (config["outbounds"] as? [[String: Any]])?.first,
              let settings = outbound["settings"] as? [String: Any] else { throw Failure.configuration }
        let port: UInt16?
        if item.format == .wireguard {
            let endpoint = ((settings["peers"] as? [[String: Any]])?.first?["endpoint"] as? String) ?? ""
            port = endpoint.split(separator: ":").last.flatMap { UInt16($0) }
        } else { port = (settings["port"] as? NSNumber).flatMap { UInt16(exactly: $0.intValue) } }
        guard let port, port > 0 else { throw Failure.configuration }
        let signals = XrayDeviceProbeSignals { [weak self] in self?.emit($0) }
        signals.start(host: item.serverAddress, port: port)
        defer { signals.stop() }
        update("\(label): включите Wi-Fi и оставьте приложение открытым")
        try await waitForSignal {
            signals.carrier == "wifi" && signals.carrierRoute == "wifi" && signals.active
                && ProcessInfo.processInfo.systemUptime - signals.carrierRouteChangedAt >= 3
        }
        try await controller.start(profile: profile)
        emit(["event": "connected", "cycle": 1])
        guard let initial = try await controller.runtimeStats() else { throw Failure.missingStats }
        try await recover(fixture, stage: "wifi-baseline", since: signals.carrierRouteChangedAt)
        var transitionFailed = false
        for interface in fixture.mode == .lockWake ? [] : ["cellular", "wifi"] {
            let instruction = interface == "cellular"
                ? "Отключите Wi-Fi, дождитесь LTE/5G и вернитесь в Xray"
                : "Включите Wi-Fi и вернитесь в Xray"
            update("\(label): \(instruction)")
            emit(["event": "action-required", "action": interface])
            try await waitForSignal { signals.carrier == interface && signals.active }
            let changedAt = signals.carrierChangedAt
            do {
                try await recover(fixture, stage: interface, since: changedAt)
                guard signals.carrier == interface else { throw Failure.transitionTimeout }
                try await sameRuntime(initial.runtimeIdentifier)
            } catch {
                transitionFailed = true
                let error = error as NSError
                emit(["event": "transition-failed", "stage": interface,
                      "domain": error.domain, "code": error.code])
                try? await sample(cycle: 1, stage: "\(interface)-failure")
                if fixture.mode == .transitionsReset, interface == "cellular", item.format == .wireguard {
                    // Diagnostic only: preserve the failed automatic recovery
                    // verdict even if explicitly closing connections helps.
                    update("\(label): проверка пересоздания соединений, оставьте LTE/5G включённым")
                    emit(["event": "diagnostic-connection-close", "stage": "cellular"])
                    do {
                        _ = try await controller.closeActiveConnections()
                        let resetAt = ProcessInfo.processInfo.systemUptime
                        try await recover(fixture, stage: "cellular-after-connection-close", since: resetAt)
                        guard signals.carrier == "cellular" else { throw Failure.transitionTimeout }
                        try await sameRuntime(initial.runtimeIdentifier)
                    } catch {
                        let error = error as NSError
                        emit(["event": "diagnostic-reset-failed", "domain": error.domain, "code": error.code])
                    }
                }
                // Still test return to Wi-Fi after cellular failure. A failed
                // Wi-Fi recovery cannot provide a useful lock/wake baseline.
                if interface == "wifi" { throw Failure.transitionFailure }
            }
        }
        signals.resetLockObservation()
        update("\(label): заблокируйте iPhone на 30 секунд, затем разблокируйте и вернитесь в Xray")
        emit(["event": "action-required", "action": "lock-30-seconds"])
        try await waitForSignal {
            guard let locked = signals.lockedAt, let unlocked = signals.unlockedAt else { return false }
            return unlocked - locked >= 15 && signals.active
        }
        let unlockedAt = signals.unlockedAt!
        emit(["event": "lock-interval", "seconds": unlockedAt - signals.lockedAt!])
        try await recover(fixture, stage: "after-unlock", since: unlockedAt)
        try await sameRuntime(initial.runtimeIdentifier)
        try await verifyConnectionClosure(cycle: 1)
        try await controller.stop()
        try await waitDisconnected()
        emit(["event": "disconnected", "cycle": 1, "result": "passed"])
        if transitionFailed { throw Failure.transitionFailure }
    }

    private func waitForSignal(_ ready: () -> Bool) async throws {
        let deadline = ProcessInfo.processInfo.systemUptime + 180
        while !ready() {
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw Failure.transitionTimeout }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    private func sameRuntime(_ identifier: String) async throws {
        guard let current = try await controller.runtimeStats(), current.runtimeIdentifier == identifier else {
            throw Failure.unexpectedRuntimeRestart
        }
    }

    private func recover(_ fixture: Fixture, stage: String, since: TimeInterval) async throws {
        let attemptStart = ProcessInfo.processInfo.systemUptime
        let deadline = attemptStart + 45
        var retries = 0
        while true {
            do {
                try await traffic(fixture, deadline: deadline)
                emit(["event": "transition-recovered", "stage": stage, "result": "passed",
                      "secondsSincePathOrUnlock": ProcessInfo.processInfo.systemUptime - since,
                      "activeRecoverySeconds": ProcessInfo.processInfo.systemUptime - attemptStart,
                      "retries": retries])
                try await sample(cycle: 1, stage: stage)
                return
            } catch {
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw error }
                retries += 1
                emit(["event": "recovery-retry", "stage": stage, "attempt": retries])
                try await Task.sleep(nanoseconds: 500_000_000)
            }
        }
    }

    private func traffic(_ fixture: Fixture, deadline: TimeInterval? = nil) async throws {
        func timeout() throws -> TimeInterval {
            let remaining = (deadline ?? (ProcessInfo.processInfo.systemUptime + 10)) - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw Failure.transitionTimeout }
            return min(10, remaining)
        }
        for host in ["198.51.100.7", "2001:db8::7", fixture.trafficHost] {
            let exchangeStarted = ProcessInfo.processInfo.systemUptime
            emit(["event": "tcp-start", "host": host])
            let payload = Data((0..<65_536).map { UInt8($0 % 251) })
            let reply = try await ProbeExchange.run(host: host, port: fixture.tcpPort,
                                                   request: payload, tcpLength: payload.count, timeout: try timeout())
            guard reply == payload else { throw Failure.mismatch }
            emit(["event": "tcp", "host": host, "bytes": payload.count, "result": "passed",
                  "exchangeSeconds": ProcessInfo.processInfo.systemUptime - exchangeStarted])
        }
        for (host, count) in [("198.51.100.7", 1392), ("2001:db8::7", 1372)] {
            let payload = Data((0..<count).map { UInt8($0 % 251) })
            let started = ProcessInfo.processInfo.systemUptime
            emit(["event": "udp-start", "host": host, "bytes": count])
            let reply: Data
            do {
                reply = try await ProbeExchange.run(host: host, port: fixture.udpPort,
                                                   request: payload, tcpLength: nil, timeout: try timeout())
            } catch {
                let detail = error as NSError
                emit(["event": "udp-failed", "host": host, "domain": detail.domain,
                      "code": detail.code, "exchangeSeconds": ProcessInfo.processInfo.systemUptime - started])
                throw error
            }
            guard reply == payload else { throw Failure.mismatch }
            emit(["event": "udp", "host": host, "bytes": count, "result": "passed",
                  "exchangeSeconds": ProcessInfo.processInfo.systemUptime - started])
        }
        let id = UInt16.random(in: 1...UInt16.max)
        var query = Data([UInt8(id >> 8), UInt8(id & 255), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        for part in fixture.trafficHost.split(separator: ".") { query.append(UInt8(part.utf8.count)); query.append(contentsOf: part.utf8) }
        query.append(contentsOf: [0, 0, 1, 0, 1])
        let reply = try await ProbeExchange.run(host: "198.18.0.1", port: 53, request: query, tcpLength: nil, timeout: try timeout())
        guard reply.count == query.count + 16, reply.prefix(2) == query.prefix(2),
              reply[2] & 0x80 != 0, reply[3] & 15 == 0, reply[6] == 0, reply[7] == 1,
              reply.suffix(4) == Data([198, 51, 100, 7]) else { throw Failure.mismatch }
        emit(["event": "dns-anchor", "result": "passed"])
    }

    private func sample(cycle: Int, stage: String) async throws {
        if let events = try await controller.protocolProbeNetworkEvents() {
            emit(["event": "network-observer", "stage": stage, "events": events])
        }
        guard let stats = try await controller.runtimeStats() else { throw Failure.missingStats }
        guard stats.physicalFootprintBytes > 0, stats.physicalFootprintBytes < 45 * 1024 * 1024,
              stats.tunFdReadLoopExits == 0, stats.tunFdWriteLoopExits == 0 else { throw Failure.budget }
        emit(["event": "sample", "cycle": cycle, "stage": stage,
              "rss": stats.residentMemoryBytes, "footprint": stats.physicalFootprintBytes,
              "threads": stats.threadCount, "tcp": stats.activeTCPFlows, "udp": stats.activeUDPFlows,
              "inboundPackets": stats.inboundPackets, "outboundPackets": stats.outboundPackets,
              "droppedPackets": stats.droppedPackets,
              "tunFDReadLoopExits": stats.tunFdReadLoopExits,
              "tunFDWriteLoopExits": stats.tunFdWriteLoopExits,
              "runtime": stats.runtimeIdentifier])

    }

    private func verifyConnectionClosure(cycle: Int) async throws {
        guard let requested = try await controller.protocolProbeConnectionIDs(close: true),
              !requested.isEmpty else { throw Failure.missingStats }
        let closed = Set(requested)
        let start = ProcessInfo.processInfo.systemUptime
        emit(["event": "connection-close-request", "cycle": cycle, "ids": requested])
        try await Task.sleep(nanoseconds: 2_000_000_000)
        while true {
            guard let current = try await controller.protocolProbeConnectionIDs() else { throw Failure.missingStats }
            let remaining = closed.intersection(current)
            if remaining.isEmpty {
                emit(["event": "connection-close-verified", "cycle": cycle,
                      "closedIDs": requested, "newIDs": current,
                      "seconds": ProcessInfo.processInfo.systemUptime - start])
                // iOS can create fresh background/DNS work after the one-shot
                // close request. Record totals, but verify the requested IDs.
                try await sample(cycle: cycle, stage: "after-close")
                return
            }
            guard ProcessInfo.processInfo.systemUptime - start < 10 else {
                emit(["event": "connection-close-retained", "cycle": cycle, "ids": remaining.sorted()])
                throw Failure.retainedFlows
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    private func waitDisconnected() async throws {
        for _ in 0..<100 {
            let status = await controller.currentStatus()
            if status == .disconnected || status == .invalid { return }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw Failure.shutdown
    }

    private func cleanup() async throws {
        let managers = try await NETunnelProviderManager.loadAllFromPreferences()
        for manager in managers where manager.localizedDescription == Self.managerName {
            guard let configuration = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  configuration.providerBundleIdentifier == XrayClientProfile.defaultProviderBundleIdentifier(
                    hostBundleIdentifier: Bundle.main.bundleIdentifier) else { throw Failure.configuration }
            manager.connection.stopVPNTunnel()
            try await waitDisconnected()
            let reference = configuration.providerConfiguration?[XrayTunnelProviderMessage.providerConfigReferenceKey] as? String
            try await manager.removeFromPreferences()
            if let reference { try XrayKeychainConfigStore().remove(reference: reference) }
        }
    }

    private func emit(_ values: [String: Any]) {
        var row = values
        row["protocol"] = label
        row["time"] = ISO8601DateFormatter().string(from: Date())
        rows.append(row)
        if let data = try? JSONSerialization.data(withJSONObject: row, options: [.sortedKeys]),
           let line = String(data: data, encoding: .utf8) { print("XRAY_V07_DEVICE \(line)") }
        if let data = try? JSONSerialization.data(withJSONObject: rows, options: [.prettyPrinted, .sortedKeys]) {
            try? data.write(to: documents.appendingPathComponent("v07-result.json"), options: [.atomic, .completeFileProtectionUnlessOpen])
        }
    }
}

/// Serial-queue completion, bounded read size and a wall-clock timeout prevent
/// failed peers from retaining an app-side connection or continuation.
private final class ProbeExchange: @unchecked Sendable {
    private enum Failure: Int, CustomNSError {
        case timeout, closed, oversized
        static var errorDomain: String { "XrayProtocolDeviceProbe.Network" }
        var errorCode: Int { rawValue }
    }
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "org.xrayrust.v07-probe")
    private let request: Data
    private let tcpLength: Int?
    private var received = Data()
    private var completion: CheckedContinuation<Data, Error>?

    private init(host: String, port: UInt16, request: Data, tcpLength: Int?, completion: CheckedContinuation<Data, Error>) {
        self.request = request; self.tcpLength = tcpLength; self.completion = completion
        connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!,
                                  using: tcpLength == nil ? .udp : .tcp)
    }
    static func run(host: String, port: UInt16, request: Data, tcpLength: Int?, timeout: TimeInterval = 10) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            let exchange = ProbeExchange(host: host, port: port, request: request, tcpLength: tcpLength, completion: continuation)
            exchange.start(timeout: timeout)
        }
    }
    private func start(timeout: TimeInterval) {
        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                connection.send(content: request, completion: .contentProcessed { [self] error in
                    if let error { finish(.failure(error)) } else { read() }
                })
            case .failed(let error): finish(.failure(error))
            case .waiting(let error): print("XRAY_V07_NETWORK waiting=\(error)")
            case .cancelled: finish(.failure(Failure.closed))
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [weak self] in self?.finish(.failure(Failure.timeout)) }
    }
    private func read() {
        if let tcpLength {
            connection.receive(minimumIncompleteLength: 1, maximumLength: min(8192, tcpLength - received.count)) { [self] data, _, closed, error in
                if let error { finish(.failure(error)); return }
                if let data { received.append(data) }
                if received.count == tcpLength { finish(.success(received)) }
                else if closed { finish(.failure(Failure.closed)) }
                else { read() }
            }
        } else {
            connection.receiveMessage { [self] data, _, _, error in
                if let error { finish(.failure(error)) }
                else if let data, data.count <= 2048 { finish(.success(data)) }
                else { finish(.failure(Failure.oversized)) }
            }
        }
    }
    private func finish(_ result: Result<Data, Error>) {
        guard let completion else { return }
        self.completion = nil
        connection.stateUpdateHandler = nil
        connection.cancel()
        completion.resume(with: result)
    }
}
#endif
