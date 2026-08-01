#if canImport(NetworkExtension)
import CoreFoundation
import Darwin
import Dispatch
import Foundation
@preconcurrency import NetworkExtension
import XrayAppleShared
import XrayMobileAdapter

public enum XrayPacketTunnelProviderError: Error, LocalizedError {
    case missingConfigJSON
    case invalidStartupProbeConfiguration
    case invalidDNSConfiguration
    case invalidDNSRoutingTopology
    case outboundServerResolutionFailed
    case dnsBootstrapTimedOut
    case startSuperseded

    public var errorDescription: String? {
        switch self {
        case .missingConfigJSON:
            return "Missing Xray JSON configuration."
        case .invalidStartupProbeConfiguration:
            return "Startup probe requires an explicit HTTP or HTTPS URL and a valid timeout."
        case .invalidDNSConfiguration:
            return "DNS requires enabled dns.fakeIp, at least one dns.servers upstream, or explicit IP servers; fake-IP cannot be combined with explicit servers."
        case .invalidDNSRoutingTopology:
            return "Fake-IP without dns.servers cannot use Freedom as the default or from a TUN domain-capable routing rule."
        case .outboundServerResolutionFailed:
            return "A proxy or DNS bootstrap hostname could not be resolved before tunnel DNS interception was enabled."
        case .dnsBootstrapTimedOut:
            return "DNS bootstrap resolution exceeded the overall preflight deadline."
        case .startSuperseded:
            return "Tunnel start was superseded by a newer lifecycle request."
        }
    }
}

enum XrayPacketTunnelStartupProbeConfiguration: Equatable {
    case disabled
    case enabled(XrayStartupProbeOptions)
    case invalid

    var logDescription: String {
        switch self {
        case .disabled:
            return "disabled"
        case .enabled:
            return "enabled"
        case .invalid:
            return "invalid"
        }
    }

    var options: XrayStartupProbeOptions? {
        guard case let .enabled(options) = self else {
            return nil
        }
        return options
    }
}

enum XrayPacketTunnelDNSConfiguration: Equatable {
    case system
    case custom([String])
    case invalid

    var logDescription: String {
        switch self {
        case .system:
            return "system"
        case let .custom(servers):
            return "custom(\(servers.count))"
        case .invalid:
            return "invalid"
        }
    }
}

enum XrayPacketTunnelResolvedDNSConfiguration: Equatable {
    case localDNSAnchor
    case custom([String])

    var logDescription: String {
        switch self {
        case .localDNSAnchor:
            return "localDnsAnchor"
        case let .custom(servers):
            return "custom(\(servers.count))"
        }
    }
}

final class XrayPacketTunnelLifecycle<Resource> {
    struct Token: Equatable {
        fileprivate let generation: UInt64
    }

    private let lock = NSRecursiveLock()
    private let stopResource: (Resource) -> Void
    private var generation: UInt64 = 0
    private var activeResource: Resource?
    private var pendingStartCancellation: (generation: UInt64, cancel: () -> Void)?

    init(stopResource: @escaping (Resource) -> Void) {
        self.stopResource = stopResource
    }

    func beginStart() -> Token {
        lock.lock()
        generation &+= 1
        let cancellation = pendingStartCancellation?.cancel
        pendingStartCancellation = nil
        let resource = activeResource
        activeResource = nil
        let token = Token(generation: generation)
        lock.unlock()

        cancellation?()
        if let resource {
            stopResource(resource)
        }
        return token
    }

    func isCurrent(_ token: Token) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return token.generation == generation
    }

    @discardableResult
    func install(_ resource: Resource, for token: Token) -> Bool {
        lock.lock()
        guard token.generation == generation, activeResource == nil else {
            lock.unlock()
            stopResource(resource)
            return false
        }
        activeResource = resource
        lock.unlock()
        return true
    }

    @discardableResult
    func finishStart(for token: Token, _ body: () -> Void) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard token.generation == generation, activeResource != nil else {
            return false
        }
        body()
        return true
    }

    @discardableResult
    func cancelStart(_ token: Token) -> Bool {
        lock.lock()
        guard token.generation == generation else {
            lock.unlock()
            return false
        }
        generation &+= 1
        let cancellation = pendingStartCancellation?.cancel
        pendingStartCancellation = nil
        lock.unlock()
        cancellation?()
        return true
    }

    @discardableResult
    func registerPendingStartCancellation(
        for token: Token,
        _ cancellation: @escaping () -> Void
    ) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard token.generation == generation,
              pendingStartCancellation == nil,
              activeResource == nil
        else {
            return false
        }
        pendingStartCancellation = (token.generation, cancellation)
        return true
    }

    @discardableResult
    func clearPendingStartCancellation(for token: Token) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard pendingStartCancellation?.generation == token.generation else {
            return false
        }
        pendingStartCancellation = nil
        return true
    }

    func stop() {
        lock.lock()
        generation &+= 1
        let cancellation = pendingStartCancellation?.cancel
        pendingStartCancellation = nil
        let resource = activeResource
        activeResource = nil
        lock.unlock()

        cancellation?()
        if let resource {
            stopResource(resource)
        }
    }

    @discardableResult
    func stop(ifCurrent token: Token) -> Bool {
        lock.lock()
        guard token.generation == generation else {
            lock.unlock()
            return false
        }
        generation &+= 1
        let cancellation = pendingStartCancellation?.cancel
        pendingStartCancellation = nil
        let resource = activeResource
        activeResource = nil
        lock.unlock()

        cancellation?()
        if let resource {
            stopResource(resource)
        }
        return true
    }

    func active() -> Resource? {
        lock.lock()
        defer { lock.unlock() }
        return activeResource
    }
}

final class XrayPacketTunnelWorkGate: @unchecked Sendable {
    private let lock = NSLock()
    private var isOccupied = false

    func tryAcquire() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !isOccupied else {
            return false
        }
        isOccupied = true
        return true
    }

    func release() {
        lock.lock()
        isOccupied = false
        lock.unlock()
    }
}

final class XrayPacketTunnelBoundedTask<Output>: @unchecked Sendable {
    typealias Work = (_ shouldContinue: @escaping () -> Bool) throws -> Output
    typealias Completion = (Result<Output, Error>) -> Void

    private enum State: Equatable {
        case initialized
        case running
        case finished
    }

    private let lock = NSLock()
    private let deadline: DispatchTime
    private let workQueue: DispatchQueue
    private let workGate: XrayPacketTunnelWorkGate?
    private let timerQueue: DispatchQueue
    private let completionQueue: DispatchQueue
    private let timeoutError: Error
    private var completion: Completion?
    private var state = State.initialized
    private var timer: DispatchSourceTimer?
    private var workItem: DispatchWorkItem?

    init(
        deadline: DispatchTime,
        workQueue: DispatchQueue,
        workGate: XrayPacketTunnelWorkGate? = nil,
        timerQueue: DispatchQueue,
        completionQueue: DispatchQueue,
        timeoutError: Error,
        completion: @escaping Completion
    ) {
        self.deadline = deadline
        self.workQueue = workQueue
        self.workGate = workGate
        self.timerQueue = timerQueue
        self.completionQueue = completionQueue
        self.timeoutError = timeoutError
        self.completion = completion
    }

    @discardableResult
    func start(_ work: @escaping Work) -> Bool {
        lock.lock()
        guard state == .initialized else {
            lock.unlock()
            return false
        }

        let timer = DispatchSource.makeTimerSource(queue: timerQueue)
        timer.schedule(deadline: deadline)
        timer.setEventHandler { [weak self] in
            guard let self else {
                return
            }
            self.finish(.failure(self.timeoutError))
        }

        let workGate = self.workGate
        let workItem = DispatchWorkItem { [weak self, workGate] in
            defer { workGate?.release() }
            guard let self else {
                return
            }
            guard self.shouldContinue() else {
                self.finish(.failure(self.timeoutError))
                return
            }
            let result = Result {
                try work { [weak self] in
                    self?.shouldContinue() == true
                }
            }
            self.finish(result, enforceDeadline: true)
        }

        state = .running
        self.timer = timer
        timer.resume()
        let acquiredWorker = workGate?.tryAcquire() ?? true
        if acquiredWorker {
            self.workItem = workItem
            workQueue.async(execute: workItem)
        }
        lock.unlock()
        return acquiredWorker
    }

    func cancel(with error: Error) {
        finish(.failure(error))
    }

    func shouldContinue() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return state != .finished && DispatchTime.now() < deadline
    }

    private func finish(
        _ result: Result<Output, Error>,
        enforceDeadline: Bool = false
    ) {
        lock.lock()
        guard state != .finished else {
            lock.unlock()
            return
        }
        let finalResult: Result<Output, Error>
        if enforceDeadline, DispatchTime.now() >= deadline {
            finalResult = .failure(timeoutError)
        } else {
            finalResult = result
        }
        state = .finished
        timer?.setEventHandler {}
        timer?.cancel()
        timer = nil
        workItem = nil
        let completion = self.completion
        self.completion = nil
        lock.unlock()

        if let completion {
            completionQueue.async {
                completion(finalResult)
            }
        }
    }
}

private final class XrayWeakReference<Value: AnyObject>: @unchecked Sendable {
    weak var value: Value?

    init(_ value: Value) {
        self.value = value
    }
}

@available(iOSApplicationExtension 15.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
open class XrayPacketTunnelProvider: NEPacketTunnelProvider {
    private static let defaultStartupProbeTimeoutMs: UInt64 = 5_000
    private static let maximumStartupProbeTimeoutMs: UInt64 = 60_000
    private static let dnsBootstrapTimeout: DispatchTimeInterval = .seconds(5)
    private static let maximumCustomDNSServers = 8
    private static let maximumDNSHostAliasDepth = 8
    private static let maximumDNSServerTimeoutMs: UInt64 = 4_611_686_018_427
    private static let dnsServerObjectFields: Set<String> = [
        "address", "port", "domains", "expectedIPs", "expectIPs", "unexpectedIPs",
        "tag", "timeoutMs", "skipFallback", "queryStrategy", "finalQuery",
    ]
    private static let dnsServerIPPolicyFields = [
        "expectedIPs", "expectIPs", "unexpectedIPs",
    ]
    static let tunnelRemoteAddress = "198.18.0.1"
    static let tunnelLocalIPv4Address = "198.18.0.2"
    static let tunnelLocalIPv6Address = "fd00:7872::2"
    private static let debugStatsHandler: @Sendable (XrayCore) -> Void = {
        logDebugStats($0)
    }
    private static let dnsBootstrapWorkQueue = DispatchQueue(
        label: "org.xrayrust.apple.packet-tunnel.dns-bootstrap.worker",
        qos: .userInitiated
    )
    private static let dnsBootstrapTimerQueue = DispatchQueue(
        label: "org.xrayrust.apple.packet-tunnel.dns-bootstrap.deadline",
        qos: .userInitiated
    )
    private static let dnsBootstrapWorkGate = XrayPacketTunnelWorkGate()

    private let debugStatsQueue = DispatchQueue(
        label: "org.xrayrust.apple.packet-tunnel.debug-stats"
    )
    private let dnsBootstrapCompletionQueue = DispatchQueue(
        label: "org.xrayrust.apple.packet-tunnel.dns-bootstrap.completion",
        qos: .userInitiated
    )
    private lazy var lifecycle = XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime> {
        $0.stop()
    }

    open override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let dnsBootstrapDeadline = DispatchTime.now() + Self.dnsBootstrapTimeout
        let optionKeys = options?.keys.sorted().joined(separator: ",") ?? "none"
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "startTunnel invoked optionKeys=\(optionKeys)"
        )
        let lifecycleToken = lifecycle.beginStart()

        guard let resolvedConfig = Self.configJSON(
            options: options,
            protocolConfiguration: protocolConfiguration
        ) else {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error("PacketTunnelProvider", "Missing config JSON")
            completionHandler(XrayPacketTunnelProviderError.missingConfigJSON)
            return
        }
        if case .invalid = resolvedConfig.startupProbeConfiguration {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Invalid explicit startup probe configuration"
            )
            completionHandler(
                XrayPacketTunnelProviderError.invalidStartupProbeConfiguration
            )
            return
        }
        if case .invalid = resolvedConfig.dnsConfiguration {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Invalid explicit DNS server configuration"
            )
            completionHandler(XrayPacketTunnelProviderError.invalidDNSConfiguration)
            return
        }
        startDNSBootstrapPreflight(
            resolvedConfig: resolvedConfig,
            deadline: dnsBootstrapDeadline,
            lifecycleToken: lifecycleToken,
            completionHandler: completionHandler
        )
    }

    private func startDNSBootstrapPreflight(
        resolvedConfig: ResolvedConfig,
        deadline: DispatchTime,
        lifecycleToken: XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime>.Token,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let task = XrayPacketTunnelBoundedTask<ResolvedConfig>(
            deadline: deadline,
            workQueue: Self.dnsBootstrapWorkQueue,
            workGate: Self.dnsBootstrapWorkGate,
            timerQueue: Self.dnsBootstrapTimerQueue,
            completionQueue: dnsBootstrapCompletionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { [weak self] result in
            guard let self else {
                completionHandler(CocoaError(.userCancelled))
                return
            }
            _ = self.lifecycle.clearPendingStartCancellation(for: lifecycleToken)
            guard self.lifecycle.isCurrent(lifecycleToken) else {
                XrayAppleLog.info(
                    "PacketTunnelProvider",
                    "Ignoring superseded DNS bootstrap preflight result"
                )
                completionHandler(XrayPacketTunnelProviderError.startSuperseded)
                return
            }
            switch result {
            case let .success(preparedConfig):
                self.applyNetworkSettingsAndStartRuntime(
                    resolvedConfig: preparedConfig,
                    lifecycleToken: lifecycleToken,
                    completionHandler: completionHandler
                )
            case let .failure(error):
                if self.lifecycle.cancelStart(lifecycleToken) {
                    XrayAppleLog.configureFileLogging(directory: nil)
                }
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "Config validation or DNS bootstrap failed before network settings: \(error.localizedDescription)"
                )
                completionHandler(error)
            }
        }

        guard lifecycle.registerPendingStartCancellation(
            for: lifecycleToken,
            { task.cancel(with: XrayPacketTunnelProviderError.startSuperseded) }
        ) else {
            task.cancel(with: XrayPacketTunnelProviderError.startSuperseded)
            return
        }

        task.start { shouldContinue in
            guard shouldContinue() else {
                throw XrayPacketTunnelProviderError.dnsBootstrapTimedOut
            }
            try Self.validateConfigBeforeApplyingNetworkSettings(resolvedConfig.json)
            guard shouldContinue() else {
                throw XrayPacketTunnelProviderError.dnsBootstrapTimedOut
            }
            let preparedConfig = try Self.configPinningOutboundServerAddresses(
                resolvedConfig,
                shouldContinue: shouldContinue
            )
            guard shouldContinue() else {
                throw XrayPacketTunnelProviderError.dnsBootstrapTimedOut
            }
            try Self.validateConfigBeforeApplyingNetworkSettings(preparedConfig.json)
            return preparedConfig
        }
    }

    private func applyNetworkSettingsAndStartRuntime(
        resolvedConfig: ResolvedConfig,
        lifecycleToken: XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime>.Token,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard let resolvedDNSConfiguration = Self.resolvedDNSConfiguration(
            configJSON: resolvedConfig.json,
            explicit: resolvedConfig.dnsConfiguration
        ) else {
            if lifecycle.cancelStart(lifecycleToken) {
                XrayAppleLog.configureFileLogging(directory: nil)
            }
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "DNS unavailable: enable dns.fakeIp, configure dns.servers, or configure explicit IP servers"
            )
            completionHandler(XrayPacketTunnelProviderError.invalidDNSConfiguration)
            return
        }
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "Resolved config source=\(resolvedConfig.source) bytes=\(resolvedConfig.json.utf8.count) debugLogging=\(resolvedConfig.debugLoggingEnabled) useTunFileDescriptor=\(resolvedConfig.useTunFileDescriptor) tunRuntimeProfile=\(resolvedConfig.tunRuntimeProfile.rawValue) startupProbe=\(resolvedConfig.startupProbeConfiguration.logDescription) dns=\(resolvedDNSConfiguration.logDescription)"
        )
        let diagnosticLogDirectory = Self.diagnosticLogDirectory(
            debugLoggingEnabled: resolvedConfig.debugLoggingEnabled
        )
        XrayAppleLog.configureFileLogging(directory: diagnosticLogDirectory)
        if resolvedConfig.debugLoggingEnabled {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Config summary \(Self.configSummary(resolvedConfig.json))"
            )
        }

        setTunnelNetworkSettings(
            Self.networkSettings(
                excludingServerAddresses: resolvedConfig.excludedServerAddresses,
                resolvedDNSConfiguration: resolvedDNSConfiguration
            )
        ) { [weak self] error in
            guard let self else {
                XrayAppleLog.error("PacketTunnelProvider", "Provider released before network settings completed")
                completionHandler(CocoaError(.userCancelled))
                return
            }
            guard self.lifecycle.isCurrent(lifecycleToken) else {
                XrayAppleLog.info(
                    "PacketTunnelProvider",
                    "Ignoring superseded network settings callback"
                )
                completionHandler(XrayPacketTunnelProviderError.startSuperseded)
                return
            }
            if let error {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "setTunnelNetworkSettings failed: \(error.localizedDescription)"
                )
                _ = self.lifecycle.cancelStart(lifecycleToken)
                XrayAppleLog.configureFileLogging(directory: nil)
                completionHandler(error)
                return
            }
            XrayAppleLog.info("PacketTunnelProvider", "Tunnel network settings applied")

            do {
                let runtime = try self.makeRuntime(
                    resolvedConfig: resolvedConfig,
                    diagnosticLogDirectory: diagnosticLogDirectory,
                    lifecycleToken: lifecycleToken
                )
                guard self.lifecycle.install(runtime, for: lifecycleToken) else {
                    completionHandler(XrayPacketTunnelProviderError.startSuperseded)
                    return
                }
                let didFinish = self.lifecycle.finishStart(for: lifecycleToken) {
                    if resolvedConfig.debugLoggingEnabled {
                        runtime.startDebugStatsLogging(
                            queue: self.debugStatsQueue,
                            handler: Self.debugStatsHandler
                        )
                    }
                    XrayAppleLog.info(
                        "PacketTunnelProvider",
                        "startTunnel completed successfully"
                    )
                    completionHandler(nil)
                }
                if !didFinish {
                    completionHandler(XrayPacketTunnelProviderError.startSuperseded)
                }
            } catch {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "startTunnel failed: \(error.localizedDescription)"
                )
                if self.lifecycle.cancelStart(lifecycleToken) {
                    XrayAppleLog.configureFileLogging(directory: nil)
                }
                completionHandler(error)
            }
        }
    }

    open override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "stopTunnel invoked reason=\(reason.xrayDescription)"
        )
        lifecycle.stop()
        XrayAppleLog.configureFileLogging(directory: nil)
        completionHandler()
    }

    open override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)?
    ) {
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "handleAppMessage bytes=\(messageData.count)"
        )
        guard String(data: messageData, encoding: .utf8) == XrayTunnelProviderMessage.statsRequest,
              let stats = try? lifecycle.active()?.core.stats()
        else {
            XrayAppleLog.info("PacketTunnelProvider", "App message ignored or stats unavailable")
            completionHandler?(nil)
            return
        }

        let runtimeStats = XrayClientRuntimeStats(
            inboundPackets: stats.inboundPackets,
            outboundPackets: stats.outboundPackets,
            droppedPackets: stats.droppedPackets,
            tcpOpenEvents: stats.tcpOpenEvents,
            tcpOpenDurationMsTotal: stats.tcpOpenDurationMsTotal,
            tcpOpenDurationMsMax: stats.tcpOpenDurationMsMax,
            tcpFirstByteEvents: stats.tcpFirstByteEvents,
            tcpFirstByteDurationMsTotal: stats.tcpFirstByteDurationMsTotal,
            tcpFirstByteDurationMsMax: stats.tcpFirstByteDurationMsMax,
            tcp443OpenEvents: stats.tcp443OpenEvents,
            tcp443OpenDurationMsTotal: stats.tcp443OpenDurationMsTotal,
            tcp443OpenDurationMsMax: stats.tcp443OpenDurationMsMax,
            tcp443FirstByteEvents: stats.tcp443FirstByteEvents,
            tcp443FirstByteDurationMsTotal: stats.tcp443FirstByteDurationMsTotal,
            tcp443FirstByteDurationMsMax: stats.tcp443FirstByteDurationMsMax,
            activeTCPFlows: stats.activeTCPFlows,
            activeUDPFlows: stats.activeUDPFlows,
            udpFlowLimit: stats.udpFlowLimit,
            udpBudgetDrops: stats.udpBudgetDrops,
            udpEvictedFlows: stats.udpEvictedFlows,
            udpChannelDroppedPackets: stats.udpChannelDroppedPackets,
            udpRemoteOpenEvents: stats.udpRemoteOpenEvents,
            udpRemoteUDP443OpenEvents: stats.udpRemoteUDP443OpenEvents,
            udpRemoteWrittenBytes: stats.udpRemoteWrittenBytes,
            udpRemoteReadBytes: stats.udpRemoteReadBytes,
            udpOpenErrors: stats.udpOpenErrors,
            udpVisionUDP443Rejections: stats.udpVisionUDP443Rejections,
            udpRemoteWriteErrors: stats.udpRemoteWriteErrors,
            udpRemoteReadErrors: stats.udpRemoteReadErrors,
            udpRemoteClosedEvents: stats.udpRemoteClosedEvents,
            udpQuicBlockedPackets: stats.udpQuicBlockedPackets,
            inboundQueueDepth: stats.inboundQueueDepth,
            outboundQueueDepth: stats.outboundQueueDepth,
            inboundQueueMaxPackets: stats.inboundQueueMaxPackets,
            outboundQueueMaxPackets: stats.outboundQueueMaxPackets,
            tunFdWriteBatches: stats.tunFdWriteBatches,
            tunFdWriteBatchPackets: stats.tunFdWriteBatchPackets,
            tunFdWriteBatchMaxPackets: stats.tunFdWriteBatchMaxPackets
        )
        XrayAppleLog.info(
            "PacketTunnelProvider",
            "Returning stats inbound=\(runtimeStats.inboundPackets) outbound=\(runtimeStats.outboundPackets) dropped=\(runtimeStats.droppedPackets)"
        )
        completionHandler?(try? XrayTunnelProviderMessage.encodeStatsResponse(runtimeStats))
    }

    static func packetIOBackend(
        discoveredTunFileDescriptor: Int32?,
        useTunFileDescriptor: Bool = true
    ) -> XrayPacketTunnelIOBackend {
        guard useTunFileDescriptor, let discoveredTunFileDescriptor else {
            return .packetFlowPump
        }
        return .darwinUtunFileDescriptor(discoveredTunFileDescriptor)
    }

    struct ResolvedConfig {
        var json: String
        var source: String
        var serverAddress: String?
        var excludedServerAddresses: [String] = []
        var debugLoggingEnabled: Bool
        var useTunFileDescriptor: Bool
        var tunRuntimeProfile: XrayTunRuntimeProfileSetting
        var startupProbeConfiguration: XrayPacketTunnelStartupProbeConfiguration
        var dnsConfiguration: XrayPacketTunnelDNSConfiguration
    }

    static func configJSON(
        options: [String: NSObject]?,
        protocolConfiguration: NEVPNProtocol,
        secureConfigStore: XraySecureConfigStoring = XrayKeychainConfigStore()
    ) -> ResolvedConfig? {
        let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol
        let serverAddress = tunnelProtocol?.serverAddress
        let isDebugLoggingEnabled = debugLoggingEnabled(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let shouldUseTunFileDescriptor = tunFileDescriptorEnabled(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let selectedTunRuntimeProfile = tunRuntimeProfile(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let selectedStartupProbeConfiguration = startupProbeConfiguration(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )
        let selectedDNSConfiguration = dnsConfiguration(
            options: options,
            providerConfiguration: tunnelProtocol?.providerConfiguration
        )

        let optionReference = stringValue(
            options?[XrayTunnelProviderMessage.configReferenceOptionKey]
        )
        let providerReference = stringValue(
            tunnelProtocol?.providerConfiguration?[
                XrayTunnelProviderMessage.providerConfigReferenceKey
            ]
        )
        guard let configReference = optionReference ?? providerReference else {
            return nil
        }
        let storedConfigJSON: String
        do {
            guard let storedConfig = try secureConfigStore.configJSON(
                reference: configReference
            ) else {
                XrayAppleLog.error(
                    "PacketTunnelProvider",
                    "Secure configuration reference could not be resolved"
                )
                return nil
            }
            storedConfigJSON = storedConfig
        } catch {
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Failed to load secure configuration: \(error.localizedDescription)"
            )
            return nil
        }
        return ResolvedConfig(
            json: storedConfigJSON,
            source: optionReference == nil ? "providerConfigurationReference" : "startOptionReference",
            serverAddress: serverAddress,
            debugLoggingEnabled: isDebugLoggingEnabled,
            useTunFileDescriptor: shouldUseTunFileDescriptor,
            tunRuntimeProfile: selectedTunRuntimeProfile,
            startupProbeConfiguration: selectedStartupProbeConfiguration,
            dnsConfiguration: selectedDNSConfiguration
        )
    }

    static func configPinningOutboundServerAddresses(
        _ resolvedConfig: ResolvedConfig,
        shouldContinue: () -> Bool = { true },
        resolveAddress: (String) -> [String]? = { systemIPAddresses($0) }
    ) throws -> ResolvedConfig {
        guard shouldContinue() else {
            throw XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        }
        guard let data = resolvedConfig.json.data(using: .utf8),
              var root = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return resolvedConfig
        }

        var requiredDomains: [String] = []
        var seenRequiredDomains = Set<String>()
        var excludedCarrierDomains = Set<String>()
        var protectedDNSDomains = Set<String>()
        var excludedAddresses = resolvedConfig.excludedServerAddresses
        guard excludedAddresses.allSatisfy({ !isTunnelOwnedIPAddress($0) }) else {
            throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
        }
        var seenExcludedAddresses = Set(excludedAddresses)
        if let serverAddress = resolvedConfig.serverAddress,
           let address = canonicalIPAddress(serverAddress)
        {
            guard !isTunnelOwnedIPAddress(address) else {
                throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
            }
            appendBootstrapAddress(
                address,
                to: &excludedAddresses,
                seen: &seenExcludedAddresses
            )
        }
        let outbounds = root["outbounds"] as? [[String: Any]] ?? []
        for outbound in outbounds {
            guard (outbound["protocol"] as? String)?.lowercased() == "vless",
                  let settings = outbound["settings"] as? [String: Any],
                  let vnext = settings["vnext"] as? [[String: Any]],
                  !vnext.isEmpty
            else {
                continue
            }
            for server in vnext {
                guard let rawAddress = server["address"] as? String else {
                    continue
                }
                if let address = canonicalIPAddress(rawAddress) {
                    guard !isTunnelOwnedIPAddress(address) else {
                        throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
                    }
                    appendBootstrapAddress(
                        address,
                        to: &excludedAddresses,
                        seen: &seenExcludedAddresses
                    )
                    continue
                }
                guard let domain = canonicalDNSBootstrapDomain(rawAddress) else {
                    throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
                }

                // Preserve the exact configured VLESS address for routing and
                // TLS metadata. Only the dns.hosts lookup key is canonical.
                appendBootstrapDomain(
                    domain,
                    to: &requiredDomains,
                    seen: &seenRequiredDomains
                )
                excludedCarrierDomains.insert(domain)
            }
        }

        var dns = root["dns"] as? [String: Any] ?? [:]
        if let servers = dns["servers"] as? [Any] {
            for rawServer in servers {
                guard let upstream = dnsBootstrapUpstream(from: rawServer) else {
                    throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
                }
                switch upstream {
                case .ip:
                    // DNS endpoints never become carrier exclusions. Routed
                    // mode uses the Xray router; local mode relies on the
                    // provider-process Network Extension policy.
                    continue
                case let .domain(domain, port, rejectsTunnelOwnedAddress):
                    appendBootstrapDomain(
                        domain,
                        to: &requiredDomains,
                        seen: &seenRequiredDomains
                    )
                    if rejectsTunnelOwnedAddress || port == 53 {
                        protectedDNSDomains.insert(domain)
                    }
                }
            }
        }

        guard !requiredDomains.isEmpty else {
            var prepared = resolvedConfig
            prepared.excludedServerAddresses = excludedAddresses
            return prepared
        }

        let rawHosts = dns["hosts"]
        guard rawHosts == nil || rawHosts is [String: Any] else {
            throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
        }
        var hosts = rawHosts as? [String: Any] ?? [:]
        var exactMappings = try canonicalExactDNSHostMappings(hosts)
        for domain in requiredDomains {
            guard shouldContinue() else {
                throw XrayPacketTunnelProviderError.dnsBootstrapTimedOut
            }
            let addresses = try bootstrapIPAddresses(
                for: domain,
                exactMappings: &exactMappings,
                shouldContinue: shouldContinue,
                resolveAddress: resolveAddress
            )
            if excludedCarrierDomains.contains(domain) || protectedDNSDomains.contains(domain) {
                guard addresses.allSatisfy({ !isTunnelOwnedIPAddress($0) }) else {
                    throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
                }
            }
            if excludedCarrierDomains.contains(domain) {
                for address in addresses {
                    appendBootstrapAddress(
                        address,
                        to: &excludedAddresses,
                        seen: &seenExcludedAddresses
                    )
                }
            }
        }

        for key in hosts.keys.filter({ isExactDNSHostKey($0) }) {
            hosts.removeValue(forKey: key)
        }
        for (domain, target) in exactMappings {
            hosts["full:\(domain)"] = target.jsonValue
        }
        dns["hosts"] = hosts
        root["dns"] = dns
        let pinnedData = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        guard let pinnedJSON = String(data: pinnedData, encoding: .utf8) else {
            throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
        }

        var prepared = resolvedConfig
        prepared.json = pinnedJSON
        prepared.excludedServerAddresses = excludedAddresses
        return prepared
    }

    private static func appendBootstrapDomain(
        _ domain: String,
        to domains: inout [String],
        seen: inout Set<String>
    ) {
        if seen.insert(domain).inserted {
            domains.append(domain)
        }
    }

    private static func appendBootstrapAddress(
        _ address: String,
        to addresses: inout [String],
        seen: inout Set<String>
    ) {
        if seen.insert(address).inserted {
            addresses.append(address)
        }
    }

    private static func dnsBootstrapDomain(fromServer server: String) -> String? {
        if isNonzeroIPLiteralDNSServer(server) {
            return nil
        }
        if let separator = server.lastIndex(of: ":"),
           !server[..<separator].contains(":"),
           UInt16(server[server.index(after: separator)...]) != nil
        {
            return canonicalDNSBootstrapDomain(String(server[..<separator]))
        }
        return canonicalDNSBootstrapDomain(server)
    }

    private static func dnsBootstrapIPAddress(fromServer server: String) -> String? {
        if let address = canonicalIPAddress(server) {
            return address
        }
        if server.first == "[", let closingBracket = server.lastIndex(of: "]") {
            let addressStart = server.index(after: server.startIndex)
            let portSeparator = server.index(after: closingBracket)
            guard portSeparator < server.endIndex,
                  server[portSeparator] == ":",
                  server.index(after: portSeparator) < server.endIndex,
                  let port = UInt16(server[server.index(after: portSeparator)...]),
                  port != 0
            else {
                return nil
            }
            return canonicalIPAddress(String(server[addressStart..<closingBracket]))
        }
        guard let separator = server.lastIndex(of: ":"),
              !server[..<separator].contains(":"),
              let port = UInt16(server[server.index(after: separator)...]),
              port != 0
        else {
            return nil
        }
        return canonicalIPAddress(String(server[..<separator]))
    }

    private enum DNSBootstrapUpstream: Equatable {
        case ip(String, port: UInt16)
        case domain(String, port: UInt16, rejectsTunnelOwnedAddress: Bool)
    }

    private static func dnsBootstrapUpstream(from rawServer: Any) -> DNSBootstrapUpstream? {
        if let server = rawServer as? String {
            if hasDNSTCPURLScheme(server) {
                return dnsTCPBootstrapUpstream(from: server)
            }
            guard server == server.trimmingCharacters(in: .whitespacesAndNewlines),
                  isNonzeroDNSServer(server),
                  let port = dnsBootstrapPort(fromServer: server)
            else {
                return nil
            }
            if let address = dnsBootstrapIPAddress(fromServer: server) {
                guard port != 53 || !isTunnelOwnedIPAddress(address) else {
                    return nil
                }
                return .ip(address, port: port)
            }
            return dnsBootstrapDomain(fromServer: server).map {
                .domain($0, port: port, rejectsTunnelOwnedAddress: false)
            }
        }

        guard let server = rawServer as? [String: Any],
              Set(server.keys).isSubset(of: dnsServerObjectFields),
              dnsServerIPPolicyStringListsAreValid(server),
              dnsServerTagIsValid(server),
              dnsServerTimeoutIsValid(server),
              let address = server["address"] as? String,
              !address.isEmpty,
              address == address.trimmingCharacters(in: .whitespacesAndNewlines)
        else {
            return nil
        }
        let port: UInt16
        if let rawPort = server["port"] {
            guard isJSONUInt32(rawPort),
                  let number = rawPort as? NSNumber,
                  number.uint64Value <= UInt64(UInt16.max)
            else {
                return nil
            }
            // Match Xray classic DNS: an explicit zero selects port 53.
            port = number.uint16Value == 0 ? 53 : number.uint16Value
        } else {
            port = 53
        }
        if hasDNSTCPURLScheme(address) {
            // Xray validates the sibling object `port` as uint16, but takes
            // the TCP endpoint entirely from the URL and preserves both.
            return dnsTCPBootstrapUpstream(from: address)
        }

        if let canonicalAddress = canonicalIPAddress(address) {
            guard port != 53 || !isTunnelOwnedIPAddress(canonicalAddress) else {
                return nil
            }
            return .ip(canonicalAddress, port: port)
        }
        guard address.caseInsensitiveCompare("localhost") != .orderedSame,
              address.caseInsensitiveCompare("fakedns") != .orderedSame,
              !address.contains(":"),
              let domain = canonicalDNSBootstrapDomain(address)
        else {
            return nil
        }
        return .domain(domain, port: port, rejectsTunnelOwnedAddress: false)
    }

    private static func hasDNSTCPURLScheme(_ server: String) -> Bool {
        guard let separator = server.firstIndex(of: ":") else {
            return false
        }
        let scheme = String(server[..<separator])
        return scheme.caseInsensitiveCompare("tcp") == .orderedSame ||
            scheme.caseInsensitiveCompare("tcp+local") == .orderedSame
    }

    private static func dnsTCPBootstrapUpstream(
        from server: String
    ) -> DNSBootstrapUpstream? {
        guard server.unicodeScalars.allSatisfy({ scalar in
            !CharacterSet.whitespacesAndNewlines.contains(scalar) &&
                !CharacterSet.controlCharacters.contains(scalar)
        }),
              let schemeSeparator = server.firstIndex(of: ":"),
              hasDNSTCPURLScheme(server)
        else {
            return nil
        }
        let authorityPrefix = server.index(after: schemeSeparator)
        guard server[authorityPrefix...].hasPrefix("//") else {
            return nil
        }
        let authorityStart = server.index(authorityPrefix, offsetBy: 2)
        let authority = String(server[authorityStart...])
        guard !authority.isEmpty,
              !authority.contains(where: { "/?#@\\%".contains($0) })
        else {
            return nil
        }

        let host: String
        let port: UInt16
        if authority.first == "[" {
            guard let closingBracket = authority.firstIndex(of: "]"),
                  closingBracket > authority.startIndex,
                  authority[authority.index(after: closingBracket)...].firstIndex(of: "]") == nil
            else {
                return nil
            }
            let hostStart = authority.index(after: authority.startIndex)
            host = String(authority[hostStart..<closingBracket])
            guard host.contains(":"), canonicalIPAddress(host) != nil else {
                return nil
            }
            let remainderStart = authority.index(after: closingBracket)
            let remainder = authority[remainderStart...]
            if remainder.isEmpty {
                port = 53
            } else {
                guard remainder.first == ":",
                      let parsedPort = dnsTCPURLPort(
                          remainder[remainder.index(after: remainder.startIndex)...]
                      )
                else {
                    return nil
                }
                port = parsedPort
            }
        } else {
            guard !authority.contains("["), !authority.contains("]") else {
                return nil
            }
            let separators = authority.indices.filter { authority[$0] == ":" }
            guard separators.count <= 1 else {
                return nil
            }
            if let separator = separators.first {
                host = String(authority[..<separator])
                let portStart = authority.index(after: separator)
                guard let parsedPort = dnsTCPURLPort(authority[portStart...])
                else {
                    return nil
                }
                port = parsedPort
            } else {
                host = authority
                port = 53
            }
            guard !host.isEmpty else {
                return nil
            }
        }

        if let address = canonicalIPAddress(host) {
            guard !isTunnelOwnedIPAddress(address) else {
                return nil
            }
            return .ip(address, port: port)
        }
        guard !host.contains(":"),
              let domain = canonicalDNSBootstrapDomain(host)
        else {
            return nil
        }
        return .domain(domain, port: port, rejectsTunnelOwnedAddress: true)
    }

    private static func dnsTCPURLPort(_ rawPort: Substring) -> UInt16? {
        guard !rawPort.isEmpty,
              rawPort.unicodeScalars.allSatisfy({ scalar in
                  scalar.value >= 48 && scalar.value <= 57
              }),
              let port = UInt16(rawPort),
              port != 0
        else {
            return nil
        }
        return port
    }

    private static func dnsServerIPPolicyStringListsAreValid(
        _ server: [String: Any]
    ) -> Bool {
        for field in dnsServerIPPolicyFields {
            guard let rawValue = server[field] else {
                continue
            }
            if rawValue is NSNull {
                continue
            }
            if rawValue is String {
                continue
            }
            guard let values = rawValue as? [Any],
                  values.allSatisfy({ $0 is String })
            else {
                return false
            }
        }
        return true
    }

    private static func dnsServerTimeoutIsValid(_ server: [String: Any]) -> Bool {
        guard let rawValue = server["timeoutMs"] else {
            return true
        }
        if rawValue is NSNull {
            return true
        }
        return isJSONUInt64(rawValue, maximum: maximumDNSServerTimeoutMs)
    }

    private static func dnsServerTagIsValid(_ server: [String: Any]) -> Bool {
        guard let rawValue = server["tag"] else {
            return true
        }
        return rawValue is NSNull || rawValue is String
    }

    private static func dnsBootstrapPort(fromServer server: String) -> UInt16? {
        if canonicalIPAddress(server) != nil {
            return 53
        }
        if server.first == "[", let closingBracket = server.lastIndex(of: "]") {
            let portSeparator = server.index(after: closingBracket)
            guard portSeparator < server.endIndex,
                  server[portSeparator] == ":",
                  server.index(after: portSeparator) < server.endIndex,
                  let port = UInt16(server[server.index(after: portSeparator)...]),
                  port != 0
            else {
                return nil
            }
            return port
        }
        if let separator = server.lastIndex(of: ":") {
            guard !server[..<separator].contains(":"),
                  let port = UInt16(server[server.index(after: separator)...]),
                  port != 0
            else {
                return nil
            }
            return port
        }
        return server.isEmpty ? nil : 53
    }

    private static func canonicalDNSBootstrapDomain(_ rawDomain: String) -> String? {
        var domain = rawDomain.trimmingCharacters(in: .whitespacesAndNewlines)
        while domain.last == "." {
            domain.removeLast()
        }
        guard !domain.isEmpty,
              !isIPAddress(domain, family: AF_INET),
              !isIPAddress(domain, family: AF_INET6)
        else {
            return nil
        }
        return domain.lowercased()
    }

    private enum DNSBootstrapHostTarget: Equatable {
        case alias(String)
        case addresses([String])

        var jsonValue: Any {
            switch self {
            case let .alias(domain):
                return domain
            case let .addresses(addresses):
                return addresses
            }
        }
    }

    private static func canonicalExactDNSHostMappings(
        _ hosts: [String: Any]
    ) throws -> [String: DNSBootstrapHostTarget] {
        var mappings: [String: DNSBootstrapHostTarget] = [:]
        for key in hosts.keys.sorted() where isExactDNSHostKey(key) {
            guard let domain = exactDNSHostIdentity(key),
                  let rawTarget = hosts[key],
                  let target = canonicalDNSHostTarget(rawTarget)
            else {
                throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
            }
            if let existing = mappings[domain], existing != target {
                throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
            }
            mappings[domain] = target
        }
        return mappings
    }

    private static func isExactDNSHostKey(_ key: String) -> Bool {
        key.hasPrefix("full:") || !key.contains(":")
    }

    private static func exactDNSHostIdentity(_ key: String) -> String? {
        guard isExactDNSHostKey(key) else {
            return nil
        }
        let domain = key.hasPrefix("full:")
            ? String(key.dropFirst("full:".count))
            : key
        return canonicalDNSBootstrapDomain(domain)
    }

    private static func canonicalDNSHostTarget(_ rawTarget: Any) -> DNSBootstrapHostTarget? {
        if let rawTarget = rawTarget as? String {
            let target = rawTarget.trimmingCharacters(in: .whitespacesAndNewlines)
            if let address = canonicalIPAddress(target) {
                return .addresses([address])
            }
            return canonicalDNSBootstrapDomain(target).map(DNSBootstrapHostTarget.alias)
        }
        guard let rawAddresses = rawTarget as? [Any], !rawAddresses.isEmpty else {
            return nil
        }
        var addresses: [String] = []
        var seen = Set<String>()
        for rawAddress in rawAddresses {
            guard let rawAddress = rawAddress as? String,
                  let address = canonicalIPAddress(rawAddress)
            else {
                return nil
            }
            if seen.insert(address).inserted {
                addresses.append(address)
            }
        }
        return .addresses(addresses)
    }

    private static func bootstrapIPAddresses(
        for domain: String,
        exactMappings: inout [String: DNSBootstrapHostTarget],
        shouldContinue: () -> Bool,
        resolveAddress: (String) -> [String]?
    ) throws -> [String] {
        var current = domain
        var visited = Set<String>()
        for depth in 0 ..< maximumDNSHostAliasDepth {
            guard shouldContinue() else {
                throw XrayPacketTunnelProviderError.dnsBootstrapTimedOut
            }
            guard visited.insert(current).inserted else {
                throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
            }
            guard let target = exactMappings[current] else {
                guard shouldContinue() else {
                    throw XrayPacketTunnelProviderError.dnsBootstrapTimedOut
                }
                guard let resolvedAddresses = resolveAddress(current),
                      let addresses = canonicalBootstrapIPAddresses(resolvedAddresses)
                else {
                    throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
                }
                exactMappings[current] = .addresses(addresses)
                return addresses
            }
            switch target {
            case let .addresses(addresses):
                return addresses
            case let .alias(alias):
                guard depth + 1 < maximumDNSHostAliasDepth else {
                    throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
                }
                current = alias
            }
        }
        throw XrayPacketTunnelProviderError.outboundServerResolutionFailed
    }

    private static func canonicalBootstrapIPAddresses(_ rawAddresses: [String]) -> [String]? {
        guard !rawAddresses.isEmpty else {
            return nil
        }
        var addresses: [String] = []
        var seen = Set<String>()
        for rawAddress in rawAddresses {
            guard let address = canonicalIPAddress(rawAddress) else {
                return nil
            }
            if seen.insert(address).inserted {
                addresses.append(address)
            }
        }
        return addresses
    }

    private static func systemIPAddresses(_ domain: String) -> [String]? {
        var hints = addrinfo()
        // AF_UNSPEC preserves getaddrinfo's reachability ordering and allows
        // DNS64 to return a synthesized IPv6 address on IPv6-only networks.
        hints.ai_family = AF_UNSPEC
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(domain, nil, &hints, &result) == 0, let result else {
            return nil
        }
        defer { freeaddrinfo(result) }

        var addresses: [String] = []
        var seen = Set<String>()
        var cursor: UnsafeMutablePointer<addrinfo>? = result
        while let current = cursor {
            let info = current.pointee
            if info.ai_family == AF_INET, let address = info.ai_addr {
                var ipv4 = address.withMemoryRebound(
                    to: sockaddr_in.self,
                    capacity: 1
                ) { $0.pointee.sin_addr }
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                if inet_ntop(AF_INET, &ipv4, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil {
                    let address = String(cString: buffer)
                    if seen.insert(address).inserted {
                        addresses.append(address)
                    }
                }
            } else if info.ai_family == AF_INET6, let address = info.ai_addr {
                let socketAddress = address.withMemoryRebound(
                    to: sockaddr_in6.self,
                    capacity: 1
                ) { $0.pointee }
                if socketAddress.sin6_scope_id == 0 {
                    var ipv6 = socketAddress.sin6_addr
                    var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                    if inet_ntop(AF_INET6, &ipv6, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil {
                        let address = String(cString: buffer)
                        if seen.insert(address).inserted {
                            addresses.append(address)
                        }
                    }
                }
            }
            cursor = info.ai_next
        }
        return addresses.isEmpty ? nil : addresses
    }

    static func debugLoggingEnabled(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> Bool {
        if let optionValue = options?[XrayTunnelProviderMessage.debugLoggingOptionKey],
           let isEnabled = boolValue(optionValue) {
            return isEnabled
        }

        if let configurationValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerDebugLoggingKey
        ],
            let isEnabled = boolValue(configurationValue) {
            return isEnabled
        }

        return false
    }

    static func diagnosticLogDirectory(
        debugLoggingEnabled: Bool,
        baseDirectory: URL = FileManager.default.urls(
            for: .cachesDirectory,
            in: .userDomainMask
        ).first ?? URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
    ) -> URL? {
        guard debugLoggingEnabled else {
            return nil
        }
        return baseDirectory
            .resolvingSymlinksInPath()
            .appendingPathComponent("XrayRustLogs", isDirectory: true)
    }

    static func configSummary(_ json: String) -> String {
        guard let data = json.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return "invalidJSON"
        }

        let inbounds = (root["inbounds"] as? [[String: Any]] ?? []).map { inbound in
            let tag = inbound["tag"] as? String ?? "untagged"
            let protocolName = inbound["protocol"] as? String ?? "unknown"
            return "\(tag):\(protocolName)"
        }

        let outbounds = (root["outbounds"] as? [[String: Any]] ?? []).map { outbound in
            outboundSummary(outbound)
        }

        let routing = root["routing"] as? [String: Any]
        let routingRules = (routing?["rules"] as? [Any])?.count ?? 0
        let dnsFakeIP = dnsFakeIPSummary(root)

        return "inbounds=\(inbounds.isEmpty ? "none" : inbounds.joined(separator: ",")) outbounds=\(outbounds.isEmpty ? "none" : outbounds.joined(separator: ", ")) routingRules=\(routingRules) dnsFakeIp=\(dnsFakeIP)"
    }

    private static func dnsFakeIPSummary(_ root: [String: Any]) -> String {
        let dns = root["dns"] as? [String: Any]
        let fakeIP = dns?["fakeIp"] as? [String: Any]
        return fakeIP?["enabled"] as? Bool == true ? "enabled" : "disabled"
    }

    private static func outboundSummary(_ outbound: [String: Any]) -> String {
        let tag = outbound["tag"] as? String ?? "untagged"
        let protocolName = outbound["protocol"] as? String ?? "unknown"
        guard protocolName == "vless" else {
            return "\(tag):\(protocolName)"
        }

        let settings = outbound["settings"] as? [String: Any]
        let vnext = settings?["vnext"] as? [[String: Any]]
        let firstServer = vnext?.first
        let users = firstServer?["users"] as? [[String: Any]]
        let flow = users?.first?["flow"] as? String ?? "none"
        let streamSettings = outbound["streamSettings"] as? [String: Any]
        let network = streamSettings?["network"] as? String ?? "unknown"
        let security = streamSettings?["security"] as? String ?? "unknown"

        return "\(tag):\(protocolName) network=\(network) security=\(security) flow=\(flow)"
    }

    static func tunFileDescriptorEnabled(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> Bool {
        if let optionValue = options?[XrayTunnelProviderMessage.useTunFileDescriptorOptionKey],
           let isEnabled = boolValue(optionValue) {
            return isEnabled
        }

        if let configurationValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerUseTunFileDescriptorKey
        ],
            let isEnabled = boolValue(configurationValue) {
            return isEnabled
        }

        return true
    }

    static func tunRuntimeProfile(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> XrayTunRuntimeProfileSetting {
        if let optionValue = options?[XrayTunnelProviderMessage.tunRuntimeProfileOptionKey],
           let profile = tunRuntimeProfileValue(optionValue) {
            return profile
        }

        if let configurationValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerTunRuntimeProfileKey
        ],
            let profile = tunRuntimeProfileValue(configurationValue) {
            return profile
        }

        return .default
    }

    static func startupProbeConfiguration(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> XrayPacketTunnelStartupProbeConfiguration {
        let enabledValue = options?[
            XrayTunnelProviderMessage.startupProbeEnabledOptionKey
        ] ?? providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeEnabledKey
        ]
        guard let enabledValue else {
            return .disabled
        }
        guard let isEnabled = boolValue(enabledValue) else {
            return .invalid
        }
        guard isEnabled else {
            return .disabled
        }

        let urlValue = options?[
            XrayTunnelProviderMessage.startupProbeURLOptionKey
        ] ?? providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeURLKey
        ]
        guard let url = stringValue(urlValue), isValidStartupProbeURL(url) else {
            return .invalid
        }
        let timeoutValue = options?[
            XrayTunnelProviderMessage.startupProbeTimeoutMsOptionKey
        ] ?? providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeTimeoutMsKey
        ]
        let timeoutMs: UInt64
        if let timeoutValue {
            guard let explicitTimeoutMs = uint64Value(timeoutValue),
                  explicitTimeoutMs <= maximumStartupProbeTimeoutMs
            else {
                return .invalid
            }
            timeoutMs = explicitTimeoutMs
        } else {
            timeoutMs = defaultStartupProbeTimeoutMs
        }
        let outboundTag: String?
        if let optionValue = options?[
            XrayTunnelProviderMessage.startupProbeOutboundTagOptionKey
        ] {
            guard let explicitOutboundTag = stringValue(optionValue) else {
                return .invalid
            }
            outboundTag = explicitOutboundTag
        } else if let providerValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerStartupProbeOutboundTagKey
        ] {
            guard let explicitOutboundTag = stringValue(providerValue) else {
                return .invalid
            }
            outboundTag = explicitOutboundTag
        } else {
            outboundTag = nil
        }

        return .enabled(
            XrayStartupProbeOptions(
                url: url,
                timeoutMs: timeoutMs,
                outboundTag: outboundTag
            )
        )
    }

    static func dnsConfiguration(
        options: [String: NSObject]?,
        providerConfiguration: [String: Any]?
    ) -> XrayPacketTunnelDNSConfiguration {
        if let optionValue = options?[XrayTunnelProviderMessage.dnsServersOptionKey] {
            return dnsConfiguration(value: optionValue)
        }
        if let providerValue = providerConfiguration?[
            XrayTunnelProviderMessage.providerDNSServersKey
        ] {
            return dnsConfiguration(value: providerValue)
        }
        return .system
    }

    static func networkSettings(
        excludingServerAddresses serverAddresses: [String] = [],
        resolvedDNSConfiguration: XrayPacketTunnelResolvedDNSConfiguration
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: tunnelRemoteAddress)
        settings.mtu = 1500

        let ipv4Settings = NEIPv4Settings(
            addresses: [tunnelLocalIPv4Address],
            subnetMasks: ["255.255.255.0"]
        )
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        let ipv4ExcludedRoutes = ipv4ExcludedRoutes(for: serverAddresses)
        if !ipv4ExcludedRoutes.isEmpty {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Excluding \(ipv4ExcludedRoutes.count) bootstrap IPv4 /32 route(s) from tunnel"
            )
            ipv4Settings.excludedRoutes = ipv4ExcludedRoutes
        }
        settings.ipv4Settings = ipv4Settings

        let ipv6Settings = NEIPv6Settings(
            addresses: [tunnelLocalIPv6Address],
            networkPrefixLengths: [128]
        )
        ipv6Settings.includedRoutes = [NEIPv6Route.default()]
        let ipv6ExcludedRoutes = ipv6ExcludedRoutes(for: serverAddresses)
        if !ipv6ExcludedRoutes.isEmpty {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Excluding \(ipv6ExcludedRoutes.count) bootstrap IPv6 /128 route(s) from tunnel"
            )
            ipv6Settings.excludedRoutes = ipv6ExcludedRoutes
        }
        settings.ipv6Settings = ipv6Settings

        // A full tunnel must install an explicit DNS destination. Otherwise
        // the system resolver can be routed into the tunnel and blackhole.
        // In locally handled DNS modes (fake-IP or raw forwarding) the
        // tunnel-local address is an interception anchor, not an upstream.
        let servers: [String]
        switch resolvedDNSConfiguration {
        case .localDNSAnchor:
            servers = [tunnelRemoteAddress]
        case let .custom(custom):
            servers = custom
        }
        let dnsSettings = NEDNSSettings(servers: servers)
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings
        return settings
    }

    static func resolvedDNSConfiguration(
        configJSON: String,
        explicit: XrayPacketTunnelDNSConfiguration
    ) -> XrayPacketTunnelResolvedDNSConfiguration? {
        let hasFakeIP = fakeIPDNSIsAvailable(configJSON)
        if fakeIPDNSIsEnabled(configJSON), !hasFakeIP {
            return nil
        }
        let hasConfiguredUpstream = configuredDNSUpstreamIsAvailable(configJSON)
        switch explicit {
        case let .custom(servers) where !hasFakeIP:
            return .custom(servers)
        case .custom:
            return nil
        case .invalid:
            return nil
        case .system:
            return hasFakeIP || hasConfiguredUpstream ? .localDNSAnchor : nil
        }
    }

    static func validateConfigBeforeApplyingNetworkSettings(
        _ configJSON: String,
        geodataSearchDirectory: URL? = Bundle.main.resourceURL
    ) throws {
        _ = try XrayCore(
            configJSON: configJSON,
            geodataSearchDirectory: geodataSearchDirectory
        )
        try validateMobileDNSRoutingTopology(configJSON)
    }

    private static func validateMobileDNSRoutingTopology(_ configJSON: String) throws {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let dns = root["dns"] as? [String: Any],
              let fakeIP = dns["fakeIp"] as? [String: Any],
              isJSONBooleanTrue(fakeIP["enabled"]),
              (dns["servers"] as? [Any] ?? []).isEmpty
        else {
            return
        }

        let outbounds = root["outbounds"] as? [[String: Any]] ?? []
        if let defaultOutbound = outbounds.first,
           (defaultOutbound["protocol"] as? String)?.lowercased() == "freedom"
        {
            throw XrayPacketTunnelProviderError.invalidDNSRoutingTopology
        }

        let freedomTags = Set(outbounds.compactMap { outbound -> String? in
            guard (outbound["protocol"] as? String)?.lowercased() == "freedom" else {
                return nil
            }
            return outbound["tag"] as? String
        })
        guard !freedomTags.isEmpty else {
            return
        }

        let inbounds = root["inbounds"] as? [[String: Any]] ?? []
        let tunInbounds = inbounds.filter {
            ($0["protocol"] as? String)?.lowercased() == "tun"
        }
        guard !tunInbounds.isEmpty else {
            return
        }
        let tunInboundTags = Set(tunInbounds.compactMap { $0["tag"] as? String })
        let routing = root["routing"] as? [String: Any]
        let rules = routing?["rules"] as? [[String: Any]] ?? []
        for rule in rules {
            guard let outboundTag = rule["outboundTag"] as? String,
                  freedomTags.contains(outboundTag),
                  routingRuleAppliesToTun(rule, tunInboundTags: tunInboundTags)
            else {
                continue
            }

            let domains = (rule["domain"] as? [Any] ?? [])
                + (rule["domains"] as? [Any] ?? [])
            let ips = rule["ip"] as? [Any] ?? []
            let isIPOnly = domains.isEmpty && !ips.isEmpty
            if !isIPOnly {
                throw XrayPacketTunnelProviderError.invalidDNSRoutingTopology
            }
        }
    }

    private static func routingRuleAppliesToTun(
        _ rule: [String: Any],
        tunInboundTags: Set<String>
    ) -> Bool {
        let inboundTags = rule["inboundTag"] as? [String] ?? []
        return inboundTags.isEmpty || !tunInboundTags.isDisjoint(with: inboundTags)
    }

    private static func fakeIPDNSIsAvailable(_ configJSON: String) -> Bool {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let dns = root["dns"] as? [String: Any],
              let fakeIP = dns["fakeIp"] as? [String: Any],
              Set(fakeIP.keys).isSubset(of: ["enabled", "ipv4Pool", "poolSize", "ttl"]),
              isJSONBooleanTrue(fakeIP["enabled"]),
              let ipv4Pool = fakeIP["ipv4Pool"] as? String
        else {
            return false
        }
        if let ttl = fakeIP["ttl"], !isJSONUInt32(ttl) {
            return false
        }
        if let poolSize = fakeIP["poolSize"],
           !isJSONUInt32(poolSize) || (poolSize as? NSNumber)?.uint64Value == 0
        {
            return false
        }
        return !usesIPv6OnlyDNSQueryStrategy(dns["queryStrategy"])
            && isValidIPv4Pool(ipv4Pool)
    }

    private static func fakeIPDNSIsEnabled(_ configJSON: String) -> Bool {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let dns = root["dns"] as? [String: Any],
              let fakeIP = dns["fakeIp"] as? [String: Any]
        else {
            return false
        }
        return isJSONBooleanTrue(fakeIP["enabled"])
    }

    private static func usesIPv6OnlyDNSQueryStrategy(_ rawStrategy: Any?) -> Bool {
        guard let strategy = (rawStrategy as? String)?.lowercased() else {
            return false
        }
        return [
            "useip6", "useipv6", "use_ip6", "use_ipv6", "use_ip_v6",
            "use-ip6", "use-ipv6", "use-ip-v6",
        ].contains(strategy)
    }

    private static func configuredDNSUpstreamIsAvailable(_ configJSON: String) -> Bool {
        guard let data = configJSON.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let dns = root["dns"] as? [String: Any],
              let servers = dns["servers"] as? [Any]
        else {
            return false
        }
        return !servers.isEmpty && servers.allSatisfy { rawServer in
            dnsBootstrapUpstream(from: rawServer) != nil
        }
    }

    private static func isNonzeroDNSServer(_ server: String) -> Bool {
        if isNonzeroIPLiteralDNSServer(server) {
            return true
        }
        if server.contains(":") {
            let components = server.split(separator: ":", omittingEmptySubsequences: false)
            guard components.count == 2,
                  !components[0].isEmpty,
                  let port = UInt16(components[1]),
                  port > 0
            else {
                return false
            }
            return true
        }
        return !server.isEmpty
    }

    private static func isNonzeroIPLiteralDNSServer(_ server: String) -> Bool {
        // Bare IP literals use the Rust parser's default DNS port 53.
        if isIPAddress(server, family: AF_INET) || isIPAddress(server, family: AF_INET6) {
            return true
        }

        // Brackets are required for an IPv6 SocketAddr with an explicit port.
        if server.first == "[", let closingBracket = server.lastIndex(of: "]") {
            let addressStart = server.index(after: server.startIndex)
            let portSeparator = server.index(after: closingBracket)
            guard portSeparator < server.endIndex,
                  server[portSeparator] == ":",
                  server.index(after: portSeparator) < server.endIndex,
                  closingBracket > addressStart,
                  isIPv6SocketAddressLiteral(String(server[addressStart..<closingBracket])),
                  let port = UInt16(server[server.index(after: portSeparator)...]),
                  port != 0
            else {
                return false
            }
            return true
        }

        // An unbracketed SocketAddr can only be IPv4; domain:port stays domain-only.
        guard let separator = server.lastIndex(of: ":"),
              !server[..<separator].contains(":"),
              isIPAddress(String(server[..<separator]), family: AF_INET),
              let port = UInt16(server[server.index(after: separator)...]),
              port != 0
        else {
            return false
        }
        return true
    }

    private static func isIPv6SocketAddressLiteral(_ address: String) -> Bool {
        if isIPAddress(address, family: AF_INET6) {
            return true
        }
        guard let scopeSeparator = address.lastIndex(of: "%"),
              scopeSeparator > address.startIndex,
              address.index(after: scopeSeparator) < address.endIndex,
              UInt32(address[address.index(after: scopeSeparator)...]) != nil
        else {
            return false
        }
        return isIPAddress(String(address[..<scopeSeparator]), family: AF_INET6)
    }

    private static func isJSONBooleanTrue(_ value: Any?) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else {
            return false
        }
        return number.boolValue
    }

    private static func isJSONUInt32(_ value: Any) -> Bool {
        isJSONUInt64(value, maximum: UInt64(UInt32.max))
    }

    private static func isJSONUInt64(_ value: Any, maximum: UInt64) -> Bool {
        guard let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else {
            return false
        }
        let integerEncodings = "cislqCISLQ"
        guard let encoding = String(cString: number.objCType).first,
              integerEncodings.contains(encoding)
        else {
            return false
        }
        guard let numericValue = UInt64(number.stringValue) else {
            return false
        }
        return numericValue <= maximum
    }

    private static func isValidIPv4Pool(_ value: String) -> Bool {
        let components = value.split(
            separator: "/",
            maxSplits: 1,
            omittingEmptySubsequences: false
        )
        guard let address = components.first,
              isIPAddress(String(address), family: AF_INET)
        else {
            return false
        }
        if components.count == 1 {
            return true
        }
        guard let prefix = UInt8(components[1]) else {
            return false
        }
        return prefix <= 32
    }

    private static func dnsConfiguration(value: Any) -> XrayPacketTunnelDNSConfiguration {
        let rawServers: [Any]
        switch value {
        case let values as NSArray:
            rawServers = values.map { $0 }
        case let value as NSString:
            rawServers = [String(value)]
        case let value as String:
            rawServers = [value]
        default:
            return .invalid
        }

        guard !rawServers.isEmpty, rawServers.count <= maximumCustomDNSServers else {
            return .invalid
        }

        var servers: [String] = []
        var seenServers = Set<String>()
        for rawServer in rawServers {
            guard let server = stringValue(rawServer),
                  let address = canonicalIPAddress(server)
            else {
                return .invalid
            }
            if seenServers.insert(address).inserted {
                servers.append(address)
            }
        }
        return servers.isEmpty ? .invalid : .custom(servers)
    }

    private static func isValidStartupProbeURL(_ rawURL: String) -> Bool {
        guard !rawURL.contains("#") else {
            return false
        }

        let remainder: Substring
        if rawURL.hasPrefix("https://") {
            remainder = rawURL.dropFirst("https://".count)
        } else if rawURL.hasPrefix("http://") {
            remainder = rawURL.dropFirst("http://".count)
        } else {
            return false
        }

        let authorityEnd = remainder.firstIndex { character in
            character == "/" || character == "?"
        } ?? remainder.endIndex
        let authority = remainder[..<authorityEnd]
        guard !authority.isEmpty,
              !authority.contains("@"),
              !authority.hasPrefix(":"),
              !authority.hasPrefix("["),
              !containsASCIIWhitespaceOrControl(authority)
        else {
            return false
        }

        let authorityParts = authority.split(
            separator: ":",
            maxSplits: 2,
            omittingEmptySubsequences: false
        )
        switch authorityParts.count {
        case 1:
            break
        case 2:
            let host = authorityParts[0]
            let port = authorityParts[1]
            guard !host.isEmpty,
                  !port.isEmpty,
                  port.unicodeScalars.allSatisfy({
                      $0.value >= 0x30 && $0.value <= 0x39
                  }),
                  UInt16(port) != nil
            else {
                return false
            }
        default:
            return false
        }

        let requestTarget = remainder[authorityEnd...]
        guard requestTarget.isEmpty
                || requestTarget.hasPrefix("/")
                || requestTarget.hasPrefix("?"),
              !containsASCIIWhitespaceOrControl(requestTarget)
        else {
            return false
        }
        return true
    }

    private static func containsASCIIWhitespaceOrControl(
        _ value: some StringProtocol
    ) -> Bool {
        value.unicodeScalars.contains { scalar in
            scalar.isASCII && (scalar.value <= 0x20 || scalar.value == 0x7F)
        }
    }

    private static func ipv4ExcludedRoutes(for serverAddresses: [String]) -> [NEIPv4Route] {
        var seen = Set<String>()
        return serverAddresses.compactMap { rawAddress in
            guard let address = canonicalIPAddress(rawAddress),
                  isIPAddress(address, family: AF_INET),
                  !isTunnelOwnedIPAddress(address),
                  seen.insert(address).inserted
            else {
                return nil
            }
            return NEIPv4Route(
                destinationAddress: address,
                subnetMask: "255.255.255.255"
            )
        }
    }

    private static func ipv6ExcludedRoutes(for serverAddresses: [String]) -> [NEIPv6Route] {
        var seen = Set<String>()
        return serverAddresses.compactMap { rawAddress in
            guard let address = canonicalIPAddress(rawAddress),
                  isIPAddress(address, family: AF_INET6),
                  !isTunnelOwnedIPAddress(address),
                  seen.insert(address).inserted
            else {
                return nil
            }
            return NEIPv6Route(
                destinationAddress: address,
                networkPrefixLength: 128
            )
        }
    }

    private static func canonicalIPAddress(_ rawAddress: String) -> String? {
        let address = rawAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            guard inet_ntop(AF_INET, &ipv4, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
                return nil
            }
            return String(cString: buffer)
        }

        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            let bytes = withUnsafeBytes(of: &ipv6) { Array($0) }
            if bytes.count == 16,
               bytes[..<10].allSatisfy({ $0 == 0 }),
               bytes[10] == 0xFF,
               bytes[11] == 0xFF
            {
                return "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            guard inet_ntop(AF_INET6, &ipv6, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
                return nil
            }
            return String(cString: buffer)
        }
        return nil
    }

    private static func isTunnelOwnedIPAddress(_ rawAddress: String) -> Bool {
        guard let address = canonicalIPAddress(rawAddress) else {
            return false
        }
        if address == tunnelRemoteAddress ||
            address == tunnelLocalIPv4Address ||
            address == tunnelLocalIPv6Address
        {
            return true
        }
        return false
    }

    private static func isIPAddress(_ address: String, family: Int32) -> Bool {
        var storage = sockaddr_storage()
        return withUnsafeMutablePointer(to: &storage) { pointer in
            address.withCString { rawAddress in
                inet_pton(family, rawAddress, pointer) == 1
            }
        }
    }

    private static func boolValue(_ value: Any) -> Bool? {
        switch value {
        case let value as Bool:
            return value
        case let value as NSNumber:
            return value.boolValue
        case let value as NSString:
            return boolValue(String(value))
        case let value as String:
            let normalizedValue = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            switch normalizedValue {
            case "1", "true", "yes":
                return true
            case "0", "false", "no":
                return false
            default:
                return nil
            }
        default:
            return nil
        }
    }

    private static func tunRuntimeProfileValue(_ value: Any) -> XrayTunRuntimeProfileSetting? {
        switch value {
        case let value as NSString:
            return XrayTunRuntimeProfileSetting(configurationValue: String(value))
        case let value as String:
            return XrayTunRuntimeProfileSetting(configurationValue: value)
        default:
            return nil
        }
    }

    private static func stringValue(_ value: Any?) -> String? {
        let raw: String?
        switch value {
        case let value as NSString:
            raw = String(value)
        case let value as String:
            raw = value
        default:
            raw = nil
        }

        let trimmed = raw?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }

    private static func uint64Value(_ value: Any?) -> UInt64? {
        switch value {
        case let value as NSNumber where value.int64Value > 0:
            return UInt64(value.int64Value)
        case let value as NSString:
            return uint64Value(String(value))
        case let value as String:
            let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
            return UInt64(trimmed).flatMap { $0 > 0 ? $0 : nil }
        default:
            return nil
        }
    }

    private func makeRuntime(
        resolvedConfig: ResolvedConfig,
        diagnosticLogDirectory: URL?,
        lifecycleToken: XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime>.Token
    ) throws -> XrayPacketTunnelRuntime {
        let backend = Self.packetIOBackend(
            discoveredTunFileDescriptor: XrayDarwinTunFileDescriptor.discoverUtunFileDescriptor(),
            useTunFileDescriptor: resolvedConfig.useTunFileDescriptor
        )
        XrayAppleLog.info("PacketTunnelProvider", "Creating XrayCore")
        let core: XrayCore
        let pump: XrayPacketTunnelPump?
        switch backend {
        case let .darwinUtunFileDescriptor(fd):
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Using Darwin utun file descriptor for packet I/O"
            )
            core = try XrayCore(
                configJSON: resolvedConfig.json,
                borrowedDarwinTunFileDescriptor: fd,
                collectTcpTimings: resolvedConfig.debugLoggingEnabled,
                tunRuntimeProfile: XrayCore.tunRuntimeProfile(
                    named: resolvedConfig.tunRuntimeProfile.rawValue
                ),
                dnsBootstrapMode: .staticOnly,
                geodataSearchDirectory: Bundle.main.resourceURL,
                startupProbe: resolvedConfig.startupProbeConfiguration.options,
                fileLogDirectory: diagnosticLogDirectory
            )
            pump = nil
        case .packetFlowPump:
            if resolvedConfig.useTunFileDescriptor {
                XrayAppleLog.info(
                    "PacketTunnelProvider",
                    "No Darwin utun fd found; using packetFlow pump for packet I/O"
                )
            } else {
                XrayAppleLog.info(
                    "PacketTunnelProvider",
                    "Darwin utun fd disabled; using packetFlow pump for packet I/O"
                )
            }
            core = try XrayCore(
                configJSON: resolvedConfig.json,
                collectTcpTimings: resolvedConfig.debugLoggingEnabled,
                tunRuntimeProfile: XrayCore.tunRuntimeProfile(
                    named: resolvedConfig.tunRuntimeProfile.rawValue
                ),
                dnsBootstrapMode: .staticOnly,
                geodataSearchDirectory: Bundle.main.resourceURL,
                startupProbe: resolvedConfig.startupProbeConfiguration.options,
                fileLogDirectory: diagnosticLogDirectory
            )
            let providerReference = XrayWeakReference(self)
            pump = XrayPacketTunnelPump(
                provider: self,
                core: core,
                terminalFailureHandler: { error in
                    providerReference.value?.handlePacketPumpTerminalFailure(
                        error,
                        lifecycleToken: lifecycleToken
                    )
                }
            )
        }

        do {
            XrayAppleLog.info("PacketTunnelProvider", "Starting XrayCore")
            try core.start()
            if let pump {
                XrayAppleLog.info("PacketTunnelProvider", "Starting packet pump")
                pump.start()
            }
            return XrayPacketTunnelRuntime(core: core, pump: pump)
        } catch {
            pump?.stop()
            try? core.stop()
            throw error
        }
    }

    private func handlePacketPumpTerminalFailure(
        _ error: XrayPacketTunnelPumpError,
        lifecycleToken: XrayPacketTunnelLifecycle<XrayPacketTunnelRuntime>.Token
    ) {
        guard lifecycle.stop(ifCurrent: lifecycleToken) else {
            XrayAppleLog.info(
                "PacketTunnelProvider",
                "Ignoring terminal failure from a superseded packet pump"
            )
            return
        }
        XrayAppleLog.error(
            "PacketTunnelProvider",
            "Packet pump failed permanently; cancelling the tunnel: \(error.localizedDescription)"
        )
        cancelTunnelWithError(error)
        XrayAppleLog.configureFileLogging(directory: nil)
    }

    private static func logDebugStats(_ core: XrayCore) {
        do {
            let stats = try core.stats()
            for message in stats.debugLogMessages() {
                XrayAppleLog.info("PacketTunnelProvider", message)
            }
            for event in try core.pollTcpSlowFlowEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollTcpFlowSummaryEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollTcpRemoteWriteSlowEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollTcpOpenErrorEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollUdpSlowFlowEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollUdpResponseGapEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
            for event in try core.pollUdpQuicBlockedEvents() {
                XrayAppleLog.info("PacketTunnelProvider", event.debugLogMessage())
            }
        } catch {
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Failed to read debug stats: \(error.localizedDescription)"
            )
        }
    }
}

@available(iOSApplicationExtension 15.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
private final class XrayPacketTunnelRuntime {
    let core: XrayCore

    private let lock = NSLock()
    private var pump: XrayPacketTunnelPump?
    private var debugStatsTimer: DispatchSourceTimer?
    private var isStopped = false

    init(core: XrayCore, pump: XrayPacketTunnelPump?) {
        self.core = core
        self.pump = pump
    }

    func startDebugStatsLogging(
        queue: DispatchQueue,
        handler: @escaping @Sendable (XrayCore) -> Void
    ) {
        lock.lock()
        defer { lock.unlock() }
        guard !isStopped, debugStatsTimer == nil else {
            return
        }

        XrayAppleLog.info("PacketTunnelProvider", "Debug stats logging enabled")
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            guard let self, let core = self.runningCore() else {
                return
            }
            handler(core)
        }
        debugStatsTimer = timer
        timer.resume()
    }

    func stop() {
        let timer: DispatchSourceTimer?
        let pump: XrayPacketTunnelPump?
        lock.lock()
        if isStopped {
            lock.unlock()
            return
        }
        isStopped = true
        timer = debugStatsTimer
        debugStatsTimer = nil
        pump = self.pump
        self.pump = nil
        lock.unlock()

        timer?.setEventHandler {}
        timer?.cancel()
        pump?.stop()
        do {
            try core.stop()
            XrayAppleLog.info("PacketTunnelProvider", "XrayCore stopped")
        } catch {
            XrayAppleLog.error(
                "PacketTunnelProvider",
                "Failed to stop XrayCore: \(error.localizedDescription)"
            )
        }
    }

    private func runningCore() -> XrayCore? {
        lock.lock()
        defer { lock.unlock() }
        return isStopped ? nil : core
    }
}

enum XrayPacketTunnelIOBackend: Equatable {
    case darwinUtunFileDescriptor(Int32)
    case packetFlowPump
}

@available(iOSApplicationExtension 15.0, tvOSApplicationExtension 17.0, macOSApplicationExtension 13.0, *)
private extension NEProviderStopReason {
    var xrayDescription: String {
        switch self {
        case .none:
            return "none"
        case .userInitiated:
            return "userInitiated"
        case .providerFailed:
            return "providerFailed"
        case .noNetworkAvailable:
            return "noNetworkAvailable"
        case .unrecoverableNetworkChange:
            return "unrecoverableNetworkChange"
        case .providerDisabled:
            return "providerDisabled"
        case .authenticationCanceled:
            return "authenticationCanceled"
        case .configurationFailed:
            return "configurationFailed"
        case .idleTimeout:
            return "idleTimeout"
        case .configurationDisabled:
            return "configurationDisabled"
        case .configurationRemoved:
            return "configurationRemoved"
        case .superceded:
            return "superceded"
        case .userLogout:
            return "userLogout"
        case .userSwitch:
            return "userSwitch"
        case .connectionFailed:
            return "connectionFailed"
        case .sleep:
            return "sleep"
        case .appUpdate:
            return "appUpdate"
        case .internalError:
            return "internalError"
        @unknown default:
            return "unknown"
        }
    }
}
#endif
