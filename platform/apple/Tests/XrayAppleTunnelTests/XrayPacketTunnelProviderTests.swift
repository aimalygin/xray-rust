import XCTest
import XrayAppleShared
import NetworkExtension
@testable import XrayAppleTunnel

@available(macOS 13.0, *)
final class XrayPacketTunnelProviderTests: XCTestCase {
    func testLifecycleStopInvalidatesDelayedNetworkSettingsCallback() {
        var stoppedResources: [Int] = []
        let lifecycle = XrayPacketTunnelLifecycle<Int> {
            stoppedResources.append($0)
        }
        let token = lifecycle.beginStart()

        lifecycle.stop()

        var didCreateRuntime = false
        if lifecycle.isCurrent(token) {
            didCreateRuntime = true
        }
        XCTAssertFalse(didCreateRuntime)
        XCTAssertFalse(lifecycle.install(1, for: token))
        XCTAssertEqual(stoppedResources, [1])
        XCTAssertNil(lifecycle.active())
    }

    func testLifecycleOverlappingStartsPublishOnlyNewestRuntime() {
        var stoppedResources: [Int] = []
        let lifecycle = XrayPacketTunnelLifecycle<Int> {
            stoppedResources.append($0)
        }
        let firstToken = lifecycle.beginStart()
        let secondToken = lifecycle.beginStart()

        XCTAssertFalse(lifecycle.install(1, for: firstToken))
        XCTAssertTrue(lifecycle.install(2, for: secondToken))

        var completedTokens: [Int] = []
        XCTAssertFalse(
            lifecycle.finishStart(for: firstToken) {
                completedTokens.append(1)
            }
        )
        XCTAssertTrue(
            lifecycle.finishStart(for: secondToken) {
                completedTokens.append(2)
            }
        )
        XCTAssertEqual(lifecycle.active(), 2)
        XCTAssertEqual(completedTokens, [2])
        XCTAssertEqual(stoppedResources, [1])

        _ = lifecycle.beginStart()
        XCTAssertEqual(stoppedResources, [1, 2])
        XCTAssertNil(lifecycle.active())
    }

    func testLifecycleTerminalFailureAndStopTearDownRuntimeOnlyOnce() {
        var stoppedResources: [Int] = []
        let lifecycle = XrayPacketTunnelLifecycle<Int> {
            stoppedResources.append($0)
        }
        let token = lifecycle.beginStart()
        XCTAssertTrue(lifecycle.install(1, for: token))

        lifecycle.stop()
        lifecycle.stop()

        XCTAssertEqual(stoppedResources, [1])
        XCTAssertNil(lifecycle.active())
    }

    func testInvalidNewStartStillSupersedesDelayedEarlierStart() {
        var stoppedResources: [Int] = []
        let lifecycle = XrayPacketTunnelLifecycle<Int> {
            stoppedResources.append($0)
        }
        let delayedStartToken = lifecycle.beginStart()
        let invalidNewStartToken = lifecycle.beginStart()

        XCTAssertTrue(lifecycle.cancelStart(invalidNewStartToken))
        XCTAssertFalse(lifecycle.isCurrent(delayedStartToken))
        XCTAssertFalse(lifecycle.install(1, for: delayedStartToken))
        XCTAssertEqual(stoppedResources, [1])
        XCTAssertNil(lifecycle.active())
    }

    func testSupersededTerminalFailureCannotStopNewRuntime() {
        var stoppedResources: [Int] = []
        let lifecycle = XrayPacketTunnelLifecycle<Int> {
            stoppedResources.append($0)
        }
        let firstToken = lifecycle.beginStart()
        XCTAssertTrue(lifecycle.install(1, for: firstToken))
        let secondToken = lifecycle.beginStart()
        XCTAssertTrue(lifecycle.install(2, for: secondToken))

        XCTAssertFalse(lifecycle.stop(ifCurrent: firstToken))
        XCTAssertEqual(lifecycle.active(), 2)
        XCTAssertEqual(stoppedResources, [1])

        XCTAssertTrue(lifecycle.stop(ifCurrent: secondToken))
        XCTAssertNil(lifecycle.active())
        XCTAssertEqual(stoppedResources, [1, 2])
    }

    func testDNSBootstrapTimeoutCompletesOnceAndIgnoresLateWorkerResult() {
        let workQueue = DispatchQueue(label: "test.dns-bootstrap.timeout.worker")
        let timerQueue = DispatchQueue(label: "test.dns-bootstrap.timeout.timer")
        let completionQueue = DispatchQueue(label: "test.dns-bootstrap.timeout.completion")
        let resolverEntered = expectation(description: "resolver entered")
        let completion = expectation(description: "deadline completion")
        let duplicateCompletion = expectation(description: "no duplicate completion")
        duplicateCompletion.isInverted = true
        let resolverGate = DispatchSemaphore(value: 0)
        var completionCount = 0
        var didContinueToNetworkSettings = false

        let task = XrayPacketTunnelBoundedTask<Int>(
            deadline: .now() + .milliseconds(200),
            workQueue: workQueue,
            timerQueue: timerQueue,
            completionQueue: completionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { result in
            completionCount += 1
            if completionCount == 1 {
                completion.fulfill()
            } else {
                duplicateCompletion.fulfill()
            }
            switch result {
            case .success:
                didContinueToNetworkSettings = true
            case let .failure(error):
                guard case XrayPacketTunnelProviderError.dnsBootstrapTimedOut = error else {
                    return XCTFail("unexpected error: \(error)")
                }
            }
        }

        task.start { _ in
            resolverEntered.fulfill()
            resolverGate.wait()
            return 1
        }

        wait(for: [resolverEntered, completion], timeout: 2)
        XCTAssertEqual(completionCount, 1)
        XCTAssertFalse(didContinueToNetworkSettings)

        resolverGate.signal()
        wait(for: [duplicateCompletion], timeout: 0.2)
        XCTAssertEqual(completionCount, 1)
        XCTAssertFalse(didContinueToNetworkSettings)
    }

    func testDNSBootstrapStopCompletesPendingStartExactlyOnce() {
        let lifecycle = XrayPacketTunnelLifecycle<Int> { _ in }
        let lifecycleToken = lifecycle.beginStart()
        let workQueue = DispatchQueue(label: "test.dns-bootstrap.stop.worker")
        let timerQueue = DispatchQueue(label: "test.dns-bootstrap.stop.timer")
        let completionQueue = DispatchQueue(label: "test.dns-bootstrap.stop.completion")
        let resolverEntered = expectation(description: "resolver entered")
        let completion = expectation(description: "stop completion")
        let duplicateCompletion = expectation(description: "no duplicate completion")
        duplicateCompletion.isInverted = true
        let resolverGate = DispatchSemaphore(value: 0)
        var completionCount = 0

        let task = XrayPacketTunnelBoundedTask<Int>(
            deadline: .now() + .seconds(5),
            workQueue: workQueue,
            timerQueue: timerQueue,
            completionQueue: completionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { result in
            completionCount += 1
            if completionCount == 1 {
                completion.fulfill()
            } else {
                duplicateCompletion.fulfill()
            }
            guard case let .failure(error) = result,
                  case XrayPacketTunnelProviderError.startSuperseded = error
            else {
                return XCTFail("expected startSuperseded, got \(result)")
            }
        }
        XCTAssertTrue(
            lifecycle.registerPendingStartCancellation(for: lifecycleToken) {
                task.cancel(with: XrayPacketTunnelProviderError.startSuperseded)
            }
        )
        task.start { _ in
            resolverEntered.fulfill()
            resolverGate.wait()
            return 1
        }

        wait(for: [resolverEntered], timeout: 1)
        lifecycle.stop()
        wait(for: [completion], timeout: 1)
        XCTAssertEqual(completionCount, 1)

        resolverGate.signal()
        wait(for: [duplicateCompletion], timeout: 0.2)
        XCTAssertEqual(completionCount, 1)
    }

    func testDNSBootstrapSupersedingStartCompletesPreviousStartExactlyOnce() {
        let lifecycle = XrayPacketTunnelLifecycle<Int> { _ in }
        let firstToken = lifecycle.beginStart()
        let workQueue = DispatchQueue(label: "test.dns-bootstrap.supersede.worker")
        let timerQueue = DispatchQueue(label: "test.dns-bootstrap.supersede.timer")
        let completionQueue = DispatchQueue(label: "test.dns-bootstrap.supersede.completion")
        let resolverEntered = expectation(description: "resolver entered")
        let completion = expectation(description: "superseded completion")
        let duplicateCompletion = expectation(description: "no duplicate completion")
        duplicateCompletion.isInverted = true
        let resolverGate = DispatchSemaphore(value: 0)
        var completionCount = 0

        let task = XrayPacketTunnelBoundedTask<Int>(
            deadline: .now() + .seconds(5),
            workQueue: workQueue,
            timerQueue: timerQueue,
            completionQueue: completionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { result in
            completionCount += 1
            if completionCount == 1 {
                completion.fulfill()
            } else {
                duplicateCompletion.fulfill()
            }
            guard case let .failure(error) = result,
                  case XrayPacketTunnelProviderError.startSuperseded = error
            else {
                return XCTFail("expected startSuperseded, got \(result)")
            }
        }
        XCTAssertTrue(
            lifecycle.registerPendingStartCancellation(for: firstToken) {
                task.cancel(with: XrayPacketTunnelProviderError.startSuperseded)
            }
        )
        task.start { _ in
            resolverEntered.fulfill()
            resolverGate.wait()
            return 1
        }

        wait(for: [resolverEntered], timeout: 1)
        let secondToken = lifecycle.beginStart()
        XCTAssertTrue(lifecycle.isCurrent(secondToken))
        wait(for: [completion], timeout: 1)
        XCTAssertEqual(completionCount, 1)

        resolverGate.signal()
        wait(for: [duplicateCompletion], timeout: 0.2)
        XCTAssertEqual(completionCount, 1)
    }

    func testQueuedDNSBootstrapHasIndependentDeadlineWhileSerialWorkerIsBlocked() {
        let workQueue = DispatchQueue(label: "test.dns-bootstrap.shared.worker")
        let timerQueue = DispatchQueue(label: "test.dns-bootstrap.shared.timer")
        let completionQueue = DispatchQueue(label: "test.dns-bootstrap.shared.completion")
        let firstWorkerEntered = expectation(description: "first worker entered")
        let firstCompletion = expectation(description: "first task cancelled")
        let secondCompletion = expectation(description: "queued task timed out")
        let secondWorkRan = expectation(description: "timed-out queued work does not run")
        secondWorkRan.isInverted = true
        let firstWorkerGate = DispatchSemaphore(value: 0)

        let firstTask = XrayPacketTunnelBoundedTask<Int>(
            deadline: .now() + .seconds(5),
            workQueue: workQueue,
            timerQueue: timerQueue,
            completionQueue: completionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { result in
            guard case let .failure(error) = result,
                  case XrayPacketTunnelProviderError.startSuperseded = error
            else {
                return XCTFail("expected cancellation, got \(result)")
            }
            firstCompletion.fulfill()
        }
        firstTask.start { _ in
            firstWorkerEntered.fulfill()
            firstWorkerGate.wait()
            return 1
        }
        wait(for: [firstWorkerEntered], timeout: 1)

        let secondTask = XrayPacketTunnelBoundedTask<Int>(
            deadline: .now() + .milliseconds(200),
            workQueue: workQueue,
            timerQueue: timerQueue,
            completionQueue: completionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { result in
            guard case let .failure(error) = result,
                  case XrayPacketTunnelProviderError.dnsBootstrapTimedOut = error
            else {
                return XCTFail("expected independent timeout, got \(result)")
            }
            secondCompletion.fulfill()
        }
        secondTask.start { _ in
            secondWorkRan.fulfill()
            return 2
        }

        wait(for: [secondCompletion], timeout: 2)
        firstTask.cancel(with: XrayPacketTunnelProviderError.startSuperseded)
        wait(for: [firstCompletion], timeout: 1)
        firstWorkerGate.signal()
        wait(for: [secondWorkRan], timeout: 0.2)
    }

    func testDNSBootstrapWorkGateDoesNotEnqueueRepeatedStartsBehindBlockedLookup() {
        let repeatedStartCount = 64
        let workQueue = DispatchQueue(label: "test.dns-bootstrap.gated.worker")
        let workGate = XrayPacketTunnelWorkGate()
        let timerQueue = DispatchQueue(label: "test.dns-bootstrap.gated.timer")
        let completionQueue = DispatchQueue(label: "test.dns-bootstrap.gated.completion")
        let firstWorkerEntered = expectation(description: "first gated worker entered")
        let firstCompletion = expectation(description: "first gated worker cancelled")
        let repeatedCompletions = expectation(description: "busy starts timed out")
        repeatedCompletions.expectedFulfillmentCount = repeatedStartCount
        let firstWorkerGate = DispatchSemaphore(value: 0)
        var workExecutionCount = 0

        let firstTask = XrayPacketTunnelBoundedTask<Int>(
            deadline: .now() + .seconds(5),
            workQueue: workQueue,
            workGate: workGate,
            timerQueue: timerQueue,
            completionQueue: completionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { result in
            guard case let .failure(error) = result,
                  case XrayPacketTunnelProviderError.startSuperseded = error
            else {
                return XCTFail("expected cancellation, got \(result)")
            }
            firstCompletion.fulfill()
        }
        XCTAssertTrue(
            firstTask.start { _ in
                workExecutionCount += 1
                firstWorkerEntered.fulfill()
                firstWorkerGate.wait()
                return 1
            }
        )
        wait(for: [firstWorkerEntered], timeout: 1)

        var repeatedTasks: [XrayPacketTunnelBoundedTask<Int>] = []
        for _ in 0 ..< repeatedStartCount {
            let task = XrayPacketTunnelBoundedTask<Int>(
                deadline: .now() + .milliseconds(200),
                workQueue: workQueue,
                workGate: workGate,
                timerQueue: timerQueue,
                completionQueue: completionQueue,
                timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
            ) { result in
                guard case let .failure(error) = result,
                      case XrayPacketTunnelProviderError.dnsBootstrapTimedOut = error
                else {
                    return XCTFail("expected busy start timeout, got \(result)")
                }
                repeatedCompletions.fulfill()
            }
            XCTAssertFalse(
                task.start { _ in
                    workExecutionCount += 1
                    return 2
                }
            )
            repeatedTasks.append(task)
        }

        wait(for: [repeatedCompletions], timeout: 3)
        XCTAssertEqual(workExecutionCount, 1)
        firstTask.cancel(with: XrayPacketTunnelProviderError.startSuperseded)
        wait(for: [firstCompletion], timeout: 1)
        firstWorkerGate.signal()
        workQueue.sync {}
        XCTAssertEqual(workExecutionCount, 1)
        withExtendedLifetime(repeatedTasks) {}
    }

    func testDNSBootstrapOverallDeadlineSkipsRemainingLookupsAfterLateReturn() {
        let config = resolvedConfig(
            json: #"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"first.example","port":443,"users":[]},{"address":"second.example","port":443,"users":[]}]}}]}"#
        )
        let workQueue = DispatchQueue(label: "test.dns-bootstrap.overall.worker")
        let timerQueue = DispatchQueue(label: "test.dns-bootstrap.overall.timer")
        let completionQueue = DispatchQueue(label: "test.dns-bootstrap.overall.completion")
        let firstLookupEntered = expectation(description: "first lookup entered")
        let deadlineCompletion = expectation(description: "overall deadline")
        let workerReturned = expectation(description: "late worker returned")
        let firstLookupGate = DispatchSemaphore(value: 0)
        var lookedUpDomains: [String] = []

        let task = XrayPacketTunnelBoundedTask<XrayPacketTunnelProvider.ResolvedConfig>(
            deadline: .now() + .milliseconds(200),
            workQueue: workQueue,
            timerQueue: timerQueue,
            completionQueue: completionQueue,
            timeoutError: XrayPacketTunnelProviderError.dnsBootstrapTimedOut
        ) { result in
            guard case let .failure(error) = result,
                  case XrayPacketTunnelProviderError.dnsBootstrapTimedOut = error
            else {
                return XCTFail("expected overall timeout, got \(result)")
            }
            deadlineCompletion.fulfill()
        }
        task.start { shouldContinue in
            defer { workerReturned.fulfill() }
            return try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
                config,
                shouldContinue: shouldContinue,
                resolveAddress: { domain in
                    lookedUpDomains.append(domain)
                    if lookedUpDomains.count == 1 {
                        firstLookupEntered.fulfill()
                        firstLookupGate.wait()
                    }
                    return ["203.0.113.10"]
                }
            )
        }

        wait(for: [firstLookupEntered, deadlineCompletion], timeout: 2)
        firstLookupGate.signal()
        wait(for: [workerReturned], timeout: 1)
        XCTAssertEqual(lookedUpDomains, ["first.example"])
    }

    func testNetworkSettingsExcludeIPv4ProxyServerFromDefaultRoute() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: ["203.0.113.10"],
            resolvedDNSConfiguration: .localDNSAnchor
        )

        let excludedRoute = settings.ipv4Settings?.excludedRoutes?.first
        XCTAssertEqual(excludedRoute?.destinationAddress, "203.0.113.10")
        XCTAssertEqual(excludedRoute?.destinationSubnetMask, "255.255.255.255")
    }

    func testNetworkSettingsExcludeIPv6ProxyServerFromDefaultRoute() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: ["64:ff9b::cb00:710a"],
            resolvedDNSConfiguration: .localDNSAnchor
        )

        let excludedRoute = settings.ipv6Settings?.excludedRoutes?.first
        XCTAssertEqual(excludedRoute?.destinationAddress, "64:ff9b::cb00:710a")
        XCTAssertEqual(excludedRoute?.destinationNetworkPrefixLength.intValue, 128)
        XCTAssertNil(settings.ipv4Settings?.excludedRoutes)
    }

    func testNetworkSettingsExcludeEveryBootstrapAddressFromDefaultRoutes() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: [
                "203.0.113.10",
                "2001:db8::10",
                "203.0.113.11",
                "2001:0DB8:0:0::10",
            ],
            resolvedDNSConfiguration: .localDNSAnchor
        )

        XCTAssertEqual(
            settings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress),
            ["203.0.113.10", "203.0.113.11"]
        )
        XCTAssertEqual(
            settings.ipv6Settings?.excludedRoutes?.map(\.destinationAddress),
            ["2001:db8::10"]
        )
        XCTAssertTrue(
            settings.ipv4Settings?.excludedRoutes?.allSatisfy {
                $0.destinationSubnetMask == "255.255.255.255"
            } == true
        )
        XCTAssertTrue(
            settings.ipv6Settings?.excludedRoutes?.allSatisfy {
                $0.destinationNetworkPrefixLength.intValue == 128
            } == true
        )
    }

    func testNetworkSettingsNeverExcludeTunnelOwnedAddresses() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: [
                "198.18.0.1",
                "198.18.0.2",
                "::ffff:198.18.0.1",
                "::ffff:198.18.0.2",
                "fd00:7872::2",
                "203.0.113.12",
            ],
            resolvedDNSConfiguration: .localDNSAnchor
        )

        XCTAssertEqual(
            settings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress),
            ["203.0.113.12"]
        )
        XCTAssertNil(settings.ipv6Settings?.excludedRoutes)
    }

    func testNetworkSettingsApplyLocalDNSAnchorForAllDomains() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: ["203.0.113.10"],
            resolvedDNSConfiguration: .localDNSAnchor
        )

        XCTAssertEqual(settings.dnsSettings?.servers, ["198.18.0.1"])
        XCTAssertEqual(settings.dnsSettings?.matchDomains, [""])
    }

    func testNetworkSettingsUseExplicitCustomDnsForAllDomains() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: ["203.0.113.10"],
            resolvedDNSConfiguration: .custom(["192.0.2.53", "198.51.100.53"])
        )

        XCTAssertEqual(settings.dnsSettings?.servers, ["192.0.2.53", "198.51.100.53"])
        XCTAssertEqual(settings.dnsSettings?.matchDomains, [""])
    }

    func testDnsConfigurationDefaultsToSystemDns() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.dnsConfiguration(
                options: nil,
                providerConfiguration: nil
            ),
            .system
        )
    }

    func testResolvedDnsConfigurationUsesLocalAnchorWhenFakeIPIsEnabled() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"}}}"#,
            explicit: .system
        )

        XCTAssertEqual(configuration, .localDNSAnchor)
    }

    func testResolvedDnsConfigurationKeepsFakeIPAnchorWithSupportedDnsPolicyFields() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"},"queryStrategy":"UseIPv4","disableFallback":true,"disableFallbackIfMatch":true}}"#,
            explicit: .system
        )

        XCTAssertEqual(configuration, .localDNSAnchor)
    }

    func testResolvedDnsConfigurationRejectsIPv4FakeIPWithIPv6OnlyStrategy() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"},"queryStrategy":"UseIPv6","servers":[{"address":"192.0.2.53"}]}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationFailsClosedWithoutFakeIPOrExplicitServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"inbounds":[]}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testDefaultDirectConfigRequiresExplicitHostDNSOverride() {
        XCTAssertNil(
            XrayPacketTunnelProvider.resolvedDNSConfiguration(
                configJSON: XrayClientProfile.directTunConfigJSON,
                explicit: .system
            )
        )
        XCTAssertEqual(
            XrayPacketTunnelProvider.resolvedDNSConfiguration(
                configJSON: XrayClientProfile.directTunConfigJSON,
                explicit: .custom(["192.0.2.53"])
            ),
            .custom(["192.0.2.53"])
        )
    }

    func testResolvedDnsConfigurationRejectsUnusableFakeIPPool() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"2001:db8::/32"}}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationRejectsExplicitServersWithFakeIP() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"}}}"#,
            explicit: .custom(["192.0.2.53"])
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationUsesExplicitServersWithoutFakeIP() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"inbounds":[]}"#,
            explicit: .custom(["192.0.2.53"])
        )

        XCTAssertEqual(configuration, .custom(["192.0.2.53"]))
    }

    func testResolvedDnsConfigurationUsesLocalAnchorForIPLiteralConfigServers() throws {
        let serverLists = [
            ["192.0.2.53"],
            ["2001:db8::53"],
            ["192.0.2.53:5353"],
            ["[2001:db8::53]:5353"],
            ["[fe80::53%2]:5353"],
            ["resolver.example", "198.51.100.53"],
        ]

        for servers in serverLists {
            let data = try JSONSerialization.data(withJSONObject: [
                "dns": ["servers": servers],
            ])
            let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
                configJSON: String(decoding: data, as: UTF8.self),
                explicit: .system
            )

            XCTAssertEqual(configuration, .localDNSAnchor, "servers=\(servers)")
        }
    }

    func testResolvedDnsConfigurationUsesLocalAnchorForDomainOnlyConfigServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"servers":["resolver.example","resolver.example:5353"]}}"#,
            explicit: .system
        )

        XCTAssertEqual(configuration, .localDNSAnchor)
    }

    func testResolvedDnsConfigurationUsesLocalAnchorForObjectAndMixedConfigServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"servers":[{"address":"resolver.example","port":0,"domains":["domain:internal.example"]},{"address":"2001:db8::53","port":5353},"192.0.2.53"]}}"#,
            explicit: .system
        )

        XCTAssertEqual(configuration, .localDNSAnchor)
    }

    func testResolvedDnsConfigurationRejectsMalformedObjectConfigServers() {
        for server in [
            #"{}"#,
            #"{"address":42}"#,
            #"{"address":"resolver.example","port":65536}"#,
            #"{"address":"tcp://resolver.example"}"#,
        ] {
            let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
                configJSON: "{\"dns\":{\"servers\":[\(server)]}}",
                explicit: .system
            )

            XCTAssertNil(configuration, "server=\(server)")
        }
    }

    func testResolvedDnsConfigurationRejectsWhitespaceAroundConfigServerAddresses() {
        for configJSON in [
            #"{"dns":{"servers":[" resolver.example"]}}"#,
            #"{"dns":{"servers":["resolver.example "]}}"#,
            #"{"dns":{"servers":[{"address":" resolver.example"}]}}"#,
            #"{"dns":{"servers":[{"address":"resolver.example "}]}}"#,
        ] {
            let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
                configJSON: configJSON,
                explicit: .system
            )

            XCTAssertNil(configuration, "configJSON=\(configJSON)")
        }
    }

    func testResolvedDnsConfigurationRejectsZeroPortIPLiteralConfigServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"servers":["192.0.2.53:0","[2001:db8::53]:0"]}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationRejectsZeroPortDomainConfigServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"servers":["resolver.example:0"]}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationExplicitServersOverrideConfigUpstreams() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"servers":["192.0.2.53","resolver.example"]}}"#,
            explicit: .custom(["198.51.100.53"])
        )

        XCTAssertEqual(configuration, .custom(["198.51.100.53"]))
    }

    func testResolvedDnsConfigurationUsesLocalAnchorForFakeIPWithConfigServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"},"servers":["192.0.2.53"]}}"#,
            explicit: .system
        )

        XCTAssertEqual(configuration, .localDNSAnchor)
    }

    func testResolvedDnsConfigurationRejectsExplicitServersForFakeIPWithConfigServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"},"servers":["192.0.2.53"]}}"#,
            explicit: .custom(["198.51.100.53"])
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationDoesNotFallBackFromInvalidExplicitServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16"}}}"#,
            explicit: .invalid
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationRejectsNumericFakeIPEnabledValue() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":1,"ipv4Pool":"198.19.0.0/16"}}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationRejectsInvalidFakeIPTTL() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","ttl":4294967296}}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationAcceptsPositiveFakeIPPoolSize() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":32768}}}"#,
            explicit: .system
        )

        XCTAssertEqual(configuration, .localDNSAnchor)
    }

    func testResolvedDnsConfigurationRejectsZeroFakeIPPoolSize() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","poolSize":0}}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testResolvedDnsConfigurationRejectsUnknownFakeIPField() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","unexpected":true}}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testConfigPreflightRejectsInvalidFakeIPBeforeNetworkSettings() throws {
        let invalidConfigJSON = try fakeIPTopologyConfig().replacingOccurrences(
            of: #""enabled":true"#,
            with: #""enabled":1"#
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.validateConfigBeforeApplyingNetworkSettings(
                invalidConfigJSON,
                geodataSearchDirectory: nil
            )
        )
    }

    func testConfigPreflightRejectsFakeIPWithoutServersAndDefaultFreedom() throws {
        let configJSON = try fakeIPTopologyConfig(freedomFirst: true)

        assertInvalidDNSRoutingTopology(configJSON)
    }

    func testConfigPreflightRejectsTunDomainRuleSelectingFreedomWithoutServers() throws {
        let configJSON = try fakeIPTopologyConfig(
            rules: [
                [
                    "type": "field",
                    "domain": ["full:captive.apple.com"],
                    "outboundTag": "direct",
                ],
            ]
        )

        assertInvalidDNSRoutingTopology(configJSON)
    }

    func testConfigPreflightRejectsTunCatchAllRuleSelectingFreedomWithoutServers() throws {
        let configJSON = try fakeIPTopologyConfig(
            rules: [
                [
                    "type": "field",
                    "inboundTag": ["tun-in"],
                    "outboundTag": "direct",
                ],
            ]
        )

        assertInvalidDNSRoutingTopology(configJSON)
    }

    func testConfigPreflightRejectsCombinedDomainAndIPFreedomRuleWithoutServers() throws {
        let configJSON = try fakeIPTopologyConfig(
            rules: [
                [
                    "type": "field",
                    "domain": ["full:internal.example"],
                    "ip": ["10.0.0.0/8"],
                    "outboundTag": "direct",
                ],
            ]
        )

        assertInvalidDNSRoutingTopology(configJSON)
    }

    func testConfigPreflightAllowsDefaultVLESSAndIPOnlyFreedomRuleWithoutServers() throws {
        let configJSON = try fakeIPTopologyConfig(
            rules: [
                [
                    "type": "field",
                    "inboundTag": ["tun-in"],
                    "ip": ["10.0.0.0/8", "fd00::/8"],
                    "outboundTag": "direct",
                ],
            ]
        )

        XCTAssertNoThrow(
            try XrayPacketTunnelProvider.validateConfigBeforeApplyingNetworkSettings(
                configJSON,
                geodataSearchDirectory: nil
            )
        )
    }

    func testConfigPreflightAllowsNonTunDomainFreedomRuleWithoutServers() throws {
        let configJSON = try fakeIPTopologyConfig(
            rules: [
                [
                    "type": "field",
                    "inboundTag": ["socks-in"],
                    "domain": ["full:captive.apple.com"],
                    "outboundTag": "direct",
                ],
            ]
        )

        XCTAssertNoThrow(
            try XrayPacketTunnelProvider.validateConfigBeforeApplyingNetworkSettings(
                configJSON,
                geodataSearchDirectory: nil
            )
        )
    }

    func testConfigPreflightAllowsDefaultFreedomWhenRoutedServersAreConfigured() throws {
        let configJSON = try fakeIPTopologyConfig(
            freedomFirst: true,
            dnsServers: ["192.0.2.53"]
        )

        XCTAssertNoThrow(
            try XrayPacketTunnelProvider.validateConfigBeforeApplyingNetworkSettings(
                configJSON,
                geodataSearchDirectory: nil
            )
        )
    }

    func testDnsConfigurationStartOptionsOverrideProviderConfiguration() {
        let configuration = XrayPacketTunnelProvider.dnsConfiguration(
            options: [
                XrayTunnelProviderMessage.dnsServersOptionKey:
                    NSArray(array: ["198.51.100.53"]),
            ],
            providerConfiguration: [
                XrayTunnelProviderMessage.providerDNSServersKey: ["192.0.2.53"],
            ]
        )

        XCTAssertEqual(configuration, .custom(["198.51.100.53"]))
    }

    func testDnsConfigurationAcceptsSingleAddressString() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.dnsConfiguration(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerDNSServersKey: "192.0.2.53",
                ]
            ),
            .custom(["192.0.2.53"])
        )
    }

    func testDnsConfigurationRejectsInvalidStartOptionsWithoutFallingBack() {
        let configuration = XrayPacketTunnelProvider.dnsConfiguration(
            options: [
                XrayTunnelProviderMessage.dnsServersOptionKey:
                    NSArray(array: ["resolver.example"]),
            ],
            providerConfiguration: [
                XrayTunnelProviderMessage.providerDNSServersKey: ["192.0.2.53"],
            ]
        )

        XCTAssertEqual(configuration, .invalid)
    }

    func testDnsConfigurationTrimsAndDeduplicatesAddresses() {
        let configuration = XrayPacketTunnelProvider.dnsConfiguration(
            options: nil,
            providerConfiguration: [
                XrayTunnelProviderMessage.providerDNSServersKey: [
                    " 192.0.2.53 ",
                    "192.0.2.53",
                    "198.51.100.53",
                ],
            ]
        )

        XCTAssertEqual(configuration, .custom(["192.0.2.53", "198.51.100.53"]))
    }

    func testDnsConfigurationAcceptsIPv6WithDualStackTunnelRouting() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.dnsConfiguration(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerDNSServersKey: "2001:db8::53",
                ]
            ),
            .custom(["2001:db8::53"])
        )
    }

    func testDnsConfigurationRejectsMoreThanEightServers() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.dnsConfiguration(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerDNSServersKey:
                        (1 ... 9).map { "192.0.2.\($0)" },
                ]
            ),
            .invalid
        )
    }

    func testNetworkSettingsInstallIPv6DefaultRoute() throws {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: ["203.0.113.10"],
            resolvedDNSConfiguration: .localDNSAnchor
        )

        let ipv6Settings = try XCTUnwrap(settings.ipv6Settings)
        XCTAssertEqual(ipv6Settings.addresses, [XrayPacketTunnelProvider.tunnelLocalIPv6Address])
        XCTAssertEqual(ipv6Settings.networkPrefixLengths.map(\.intValue), [128])
        let defaultRoute = try XCTUnwrap(ipv6Settings.includedRoutes?.first)
        XCTAssertEqual(defaultRoute.destinationAddress, "::")
        XCTAssertEqual(defaultRoute.destinationNetworkPrefixLength.intValue, 0)
        XCTAssertNil(ipv6Settings.excludedRoutes)
    }

    func testPacketIOBackendUsesDiscoveredDarwinUtunFileDescriptor() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.packetIOBackend(discoveredTunFileDescriptor: 42),
            .darwinUtunFileDescriptor(42)
        )
    }

    func testPacketIOBackendUsesPacketFlowPumpWhenTunFileDescriptorIsDisabled() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.packetIOBackend(
                discoveredTunFileDescriptor: 42,
                useTunFileDescriptor: false
            ),
            .packetFlowPump
        )
    }

    func testPacketIOBackendFallsBackToPacketFlowPumpWithoutFileDescriptor() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.packetIOBackend(discoveredTunFileDescriptor: nil),
            .packetFlowPump
        )
    }

    func testDebugLoggingDisabledWhenUnset() {
        XCTAssertFalse(
            XrayPacketTunnelProvider.debugLoggingEnabled(
                options: nil,
                providerConfiguration: nil
            )
        )
    }

    func testDebugLoggingReadsProviderConfiguration() {
        XCTAssertTrue(
            XrayPacketTunnelProvider.debugLoggingEnabled(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerDebugLoggingKey: true,
                ]
            )
        )
    }

    func testDebugLoggingStartOptionsOverrideProviderConfiguration() {
        XCTAssertTrue(
            XrayPacketTunnelProvider.debugLoggingEnabled(
                options: [
                    XrayTunnelProviderMessage.debugLoggingOptionKey: NSNumber(value: true),
                ],
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerDebugLoggingKey: false,
                ]
            )
        )
    }

    func testDiagnosticLogDirectoryIsNilWhenDebugLoggingIsDisabled() {
        let baseDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)

        XCTAssertNil(
            XrayPacketTunnelProvider.diagnosticLogDirectory(
                debugLoggingEnabled: false,
                baseDirectory: baseDirectory
            )
        )
    }

    func testDiagnosticLogDirectoryUsesXrayRustLogsWhenDebugLoggingIsEnabled() {
        let baseDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)

        let directory = XrayPacketTunnelProvider.diagnosticLogDirectory(
            debugLoggingEnabled: true,
            baseDirectory: baseDirectory
        )

        XCTAssertEqual(directory?.lastPathComponent, "XrayRustLogs")
        XCTAssertEqual(
            directory?.deletingLastPathComponent(),
            baseDirectory.resolvingSymlinksInPath()
        )
    }

    func testTunFileDescriptorEnabledDefaultsToTrue() {
        XCTAssertTrue(
            XrayPacketTunnelProvider.tunFileDescriptorEnabled(
                options: nil,
                providerConfiguration: nil
            )
        )
    }

    func testTunFileDescriptorEnabledReadsStartOptions() {
        XCTAssertFalse(
            XrayPacketTunnelProvider.tunFileDescriptorEnabled(
                options: [
                    XrayTunnelProviderMessage.useTunFileDescriptorOptionKey: NSNumber(value: false),
                ],
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerUseTunFileDescriptorKey: true,
                ]
            )
        )
    }

    func testTunRuntimeProfileDefaultsToDefault() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.tunRuntimeProfile(
                options: nil,
                providerConfiguration: nil
            ),
            .default
        )
    }

    func testTunRuntimeProfileReadsProviderConfiguration() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.tunRuntimeProfile(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerTunRuntimeProfileKey: "low-memory",
                ]
            ),
            .lowMemory
        )
    }

    func testTunRuntimeProfileStartOptionsOverrideProviderConfiguration() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.tunRuntimeProfile(
                options: [
                    XrayTunnelProviderMessage.tunRuntimeProfileOptionKey: "mobile-plus" as NSString,
                ],
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerTunRuntimeProfileKey: "low-memory",
                ]
            ),
            .mobilePlus
        )
    }

    func testStartupProbeIsDisabledByDefault() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.startupProbeConfiguration(
                options: nil,
                providerConfiguration: nil
            ),
            .disabled
        )
    }

    func testStartupProbeURLAloneDoesNotEnableNetworkAccess() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.startupProbeConfiguration(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerStartupProbeURLKey:
                        "https://probe.example/204",
                ]
            ),
            .disabled
        )
    }

    func testStartupProbeStartOptionsOverrideProviderConfiguration() {
        let configuration = XrayPacketTunnelProvider.startupProbeConfiguration(
            options: [
                XrayTunnelProviderMessage.startupProbeEnabledOptionKey: NSNumber(value: true),
                XrayTunnelProviderMessage.startupProbeURLOptionKey: "https://probe.example/204" as NSString,
                XrayTunnelProviderMessage.startupProbeTimeoutMsOptionKey: NSNumber(value: 7_500),
                XrayTunnelProviderMessage.startupProbeOutboundTagOptionKey: "proxy" as NSString,
            ],
            providerConfiguration: [
                XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                XrayTunnelProviderMessage.providerStartupProbeURLKey: "https://provider.example/204",
                XrayTunnelProviderMessage.providerStartupProbeTimeoutMsKey: 2_500,
                XrayTunnelProviderMessage.providerStartupProbeOutboundTagKey: "direct",
            ]
        )

        guard case let .enabled(probe) = configuration else {
            return XCTFail("Expected the explicit startup probe to be enabled")
        }
        XCTAssertEqual(probe.url, "https://probe.example/204")
        XCTAssertEqual(probe.timeoutMs, 7_500)
        XCTAssertEqual(probe.outboundTag, "proxy")
    }

    func testStartupProbeAcceptsCoreCompatibleCustomPortAndQuery() {
        let configuration = XrayPacketTunnelProvider.startupProbeConfiguration(
            options: nil,
            providerConfiguration: [
                XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                XrayTunnelProviderMessage.providerStartupProbeURLKey:
                    "http://probe.example:8080?check=1",
            ]
        )

        guard case let .enabled(probe) = configuration else {
            return XCTFail("Expected the explicit startup probe to be enabled")
        }
        XCTAssertEqual(probe.url, "http://probe.example:8080?check=1")
        XCTAssertEqual(probe.timeoutMs, 5_000)
        XCTAssertNil(probe.outboundTag)
    }

    func testStartupProbeStartOptionsCanDisableProviderConfiguration() {
        let configuration = XrayPacketTunnelProvider.startupProbeConfiguration(
            options: [
                XrayTunnelProviderMessage.startupProbeEnabledOptionKey:
                    NSNumber(value: false),
            ],
            providerConfiguration: [
                XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                XrayTunnelProviderMessage.providerStartupProbeURLKey:
                    "https://provider.example/204",
            ]
        )

        XCTAssertEqual(configuration, .disabled)
    }

    func testStartupProbeRejectsEnabledConfigurationWithoutURL() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.startupProbeConfiguration(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                ]
            ),
            .invalid
        )
    }

    func testStartupProbeRejectsNonHttpURL() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.startupProbeConfiguration(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                    XrayTunnelProviderMessage.providerStartupProbeURLKey:
                        "file:///private/config",
                ]
            ),
            .invalid
        )
    }

    func testStartupProbeRejectsURLsUnsupportedByCoreParser() {
        let invalidURLs = [
            "HTTPS://probe.example/204",
            "https://probe.example/204#fragment",
            "https://[2001:db8::1]/204",
            "https://probe.example:70000/204",
            "https://probe.example/a b",
        ]

        for invalidURL in invalidURLs {
            XCTAssertEqual(
                XrayPacketTunnelProvider.startupProbeConfiguration(
                    options: nil,
                    providerConfiguration: [
                        XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                        XrayTunnelProviderMessage.providerStartupProbeURLKey: invalidURL,
                    ]
                ),
                .invalid,
                invalidURL
            )
        }
    }

    func testStartupProbeRejectsInvalidExplicitTimeoutsWithoutFallingBack() {
        for invalidTimeoutMs in [0, 60_001] {
            XCTAssertEqual(
                XrayPacketTunnelProvider.startupProbeConfiguration(
                    options: [
                        XrayTunnelProviderMessage.startupProbeEnabledOptionKey:
                            NSNumber(value: true),
                        XrayTunnelProviderMessage.startupProbeTimeoutMsOptionKey:
                            NSNumber(value: invalidTimeoutMs),
                    ],
                    providerConfiguration: [
                        XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                        XrayTunnelProviderMessage.providerStartupProbeURLKey:
                            "https://provider.example/204",
                        XrayTunnelProviderMessage.providerStartupProbeTimeoutMsKey: 2_500,
                    ]
                ),
                .invalid
            )
        }
    }

    func testStartupProbeRejectsInvalidStartOptionOutboundTagWithoutFallingBack() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.startupProbeConfiguration(
                options: [
                    XrayTunnelProviderMessage.startupProbeEnabledOptionKey:
                        NSNumber(value: true),
                    XrayTunnelProviderMessage.startupProbeOutboundTagOptionKey:
                        "   " as NSString,
                ],
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerStartupProbeEnabledKey: true,
                    XrayTunnelProviderMessage.providerStartupProbeURLKey:
                        "https://provider.example/204",
                    XrayTunnelProviderMessage.providerStartupProbeOutboundTagKey: "proxy",
                ]
            ),
            .invalid
        )
    }

    func testConfigIsResolvedFromOpaqueSecureReference() throws {
        let secureStore = TunnelTestSecureConfigStore()
        try secureStore.store(configJSON: #"{"inbounds":[]}"#, reference: "opaque-reference")
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerConfiguration = [
            XrayTunnelProviderMessage.providerConfigReferenceKey: "opaque-reference",
        ]

        let resolved = XrayPacketTunnelProvider.configJSON(
            options: nil,
            protocolConfiguration: tunnelProtocol,
            secureConfigStore: secureStore
        )

        XCTAssertEqual(resolved?.json, #"{"inbounds":[]}"#)
        XCTAssertEqual(resolved?.source, "providerConfigurationReference")
        XCTAssertEqual(resolved?.startupProbeConfiguration, .disabled)
        XCTAssertEqual(resolved?.dnsConfiguration, .system)
    }

    func testConfigResolutionDoesNotMigrateLegacyDirectProfileForOnDemandStart() throws {
        let secureStore = TunnelTestSecureConfigStore()
        try secureStore.store(
            configJSON: legacyDirectTunConfigJSON,
            reference: "legacy-reference"
        )
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerConfiguration = [
            XrayTunnelProviderMessage.providerConfigReferenceKey: "legacy-reference",
        ]

        let resolved = XrayPacketTunnelProvider.configJSON(
            options: nil,
            protocolConfiguration: tunnelProtocol,
            secureConfigStore: secureStore
        )

        XCTAssertEqual(resolved?.json, legacyDirectTunConfigJSON)
    }

    func testConfigResolutionPreservesLegacyDirectProfileWithProviderDNS() throws {
        let secureStore = TunnelTestSecureConfigStore()
        try secureStore.store(
            configJSON: legacyDirectTunConfigJSON,
            reference: "legacy-reference"
        )
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerConfiguration = [
            XrayTunnelProviderMessage.providerConfigReferenceKey: "legacy-reference",
            XrayTunnelProviderMessage.providerDNSServersKey: ["192.0.2.53"],
        ]

        let resolved = XrayPacketTunnelProvider.configJSON(
            options: nil,
            protocolConfiguration: tunnelProtocol,
            secureConfigStore: secureStore
        )

        XCTAssertEqual(resolved?.json, legacyDirectTunConfigJSON)
        XCTAssertEqual(resolved?.dnsConfiguration, .custom(["192.0.2.53"]))
    }

    func testConfigResolutionPreservesLegacyDirectProfileWithStartOptionDNSOverride() throws {
        let secureStore = TunnelTestSecureConfigStore()
        try secureStore.store(
            configJSON: legacyDirectTunConfigJSON,
            reference: "legacy-reference"
        )
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerConfiguration = [
            XrayTunnelProviderMessage.providerConfigReferenceKey: "legacy-reference",
            XrayTunnelProviderMessage.providerDNSServersKey: ["192.0.2.53"],
        ]

        let resolved = XrayPacketTunnelProvider.configJSON(
            options: [
                XrayTunnelProviderMessage.dnsServersOptionKey:
                    NSArray(array: ["198.51.100.53"]),
            ],
            protocolConfiguration: tunnelProtocol,
            secureConfigStore: secureStore
        )

        XCTAssertEqual(resolved?.json, legacyDirectTunConfigJSON)
        XCTAssertEqual(resolved?.dnsConfiguration, .custom(["198.51.100.53"]))
    }

    func testConfigSummaryIncludesRoutingSurfaceWithoutSecrets() {
        let summary = XrayPacketTunnelProvider.configSummary(
            """
            {
              "inbounds": [
                {
                  "tag": "tun-in",
                  "protocol": "tun"
                }
              ],
              "outbounds": [
                {
                  "tag": "proxy",
                  "protocol": "vless",
                  "settings": {
                    "vnext": [
                      {
                        "address": "203.0.113.10",
                        "port": 32134,
                        "users": [
                          {
                            "id": "secret-id",
                            "flow": "xtls-rprx-vision"
                          }
                        ]
                      }
                    ]
                  },
                  "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                      "publicKey": "secret-public-key"
                    }
                  }
                },
                {
                  "tag": "direct",
                  "protocol": "freedom"
                }
              ],
              "routing": {
                "rules": [
                  {},
                  {}
                ]
              },
              "dns": {
                "fakeIp": {
                  "enabled": true,
                  "ipv4Pool": "198.19.0.0/16"
                }
              }
            }
            """
        )

        XCTAssertEqual(
            summary,
            "inbounds=tun-in:tun outbounds=proxy:vless network=tcp security=reality flow=xtls-rprx-vision, direct:freedom routingRules=2 dnsFakeIp=enabled"
        )
        XCTAssertFalse(summary.contains("secret"))
        XCTAssertFalse(summary.contains("203.0.113.10"))
    }

    func testConfigPinningAddsExactBootstrapHostsAndKeepsVLESSDomain() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":["Resolver.Example.:5353","192.0.2.53"],"hosts":{"full:existing.example":"198.51.100.9"}},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"Proxy.Example.","port":443,"users":[]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{}}}]}"#,
            serverAddress: "proxy.example"
        )
        var resolvedDomains: [String] = []

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                resolvedDomains.append(domain)
                switch domain {
                case "proxy.example":
                    return ["2001:db8::44", "203.0.113.44"]
                case "resolver.example":
                    return ["198.51.100.53", "2001:db8::53"]
                default:
                    return nil
                }
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])
        let stream = try XCTUnwrap(outbounds[0]["streamSettings"] as? [String: Any])
        let tls = try XCTUnwrap(stream["tlsSettings"] as? [String: Any])
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(vnext[0]["address"] as? String, "Proxy.Example.")
        XCTAssertNil(tls["serverName"])
        XCTAssertEqual(
            hosts["full:proxy.example"] as? [String],
            ["2001:db8::44", "203.0.113.44"]
        )
        XCTAssertEqual(
            hosts["full:resolver.example"] as? [String],
            ["198.51.100.53", "2001:db8::53"]
        )
        XCTAssertEqual(hosts["full:existing.example"] as? [String], ["198.51.100.9"])
        XCTAssertEqual(prepared.serverAddress, "proxy.example")
        XCTAssertEqual(
            prepared.excludedServerAddresses,
            [
                "2001:db8::44",
                "203.0.113.44",
            ]
        )
        XCTAssertEqual(resolvedDomains, ["proxy.example", "resolver.example"])
    }

    func testConfigPinningAddsHostsForObjectAndMixedDnsServersWithoutCarrierExclusions() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":[{"address":"Object-DNS.Example.","port":0,"domains":["domain:internal.example"]},"String-DNS.Example.:5353"]},"outbounds":[{"protocol":"freedom"}]}"#
        )
        var resolvedDomains: [String] = []

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                resolvedDomains.append(domain)
                switch domain {
                case "object-dns.example":
                    return ["2001:db8::53", "192.0.2.53"]
                case "string-dns.example":
                    return ["198.51.100.53"]
                default:
                    return nil
                }
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(
            hosts["full:object-dns.example"] as? [String],
            ["2001:db8::53", "192.0.2.53"]
        )
        XCTAssertEqual(
            hosts["full:string-dns.example"] as? [String],
            ["198.51.100.53"]
        )
        XCTAssertEqual(resolvedDomains, ["object-dns.example", "string-dns.example"])
        XCTAssertEqual(prepared.excludedServerAddresses, [])
    }

    func testConfigPinningAcceptsIPv6OnlySystemBootstrapAndPreservesVLESSAddress() throws {
        let resolved = resolvedConfig(
            json: #"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"Proxy.Example.","port":443,"users":[]}]}}]}"#,
            serverAddress: "proxy.example"
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTAssertEqual(domain, "proxy.example")
                return ["64:ff9b::cb00:712c"]
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])

        XCTAssertEqual(vnext[0]["address"] as? String, "Proxy.Example.")
        XCTAssertEqual(hosts["full:proxy.example"] as? [String], ["64:ff9b::cb00:712c"])
        XCTAssertEqual(prepared.serverAddress, "proxy.example")
        XCTAssertEqual(prepared.excludedServerAddresses, ["64:ff9b::cb00:712c"])
        let networkSettings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: prepared.excludedServerAddresses,
            resolvedDNSConfiguration: .localDNSAnchor
        )
        XCTAssertEqual(
            networkSettings.ipv6Settings?.excludedRoutes?.first?.destinationAddress,
            "64:ff9b::cb00:712c"
        )
    }

    func testConfigPinningCanonicalizesIPv4MappedCarrierBeforeRouting() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"hosts":{"full:proxy.example":["::ffff:203.0.113.10","203.0.113.11"]}},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"proxy.example","port":443,"users":[]}]}}]}"#,
            serverAddress: "proxy.example"
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(
            hosts["full:proxy.example"] as? [String],
            ["203.0.113.10", "203.0.113.11"]
        )
        XCTAssertEqual(
            prepared.excludedServerAddresses,
            ["203.0.113.10", "203.0.113.11"]
        )
        let networkSettings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: prepared.excludedServerAddresses,
            resolvedDNSConfiguration: .localDNSAnchor
        )
        XCTAssertEqual(
            networkSettings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress),
            ["203.0.113.10", "203.0.113.11"]
        )
        XCTAssertNil(networkSettings.ipv6Settings?.excludedRoutes)
    }

    func testConfigPinningAcceptsExistingIPv6AliasTerminal() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"hosts":{"full:proxy.example":"Alias.Example.","full:alias.example":"2001:0DB8:0:0::45"}},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"Proxy.Example.","port":443,"users":[]}]}}]}"#,
            serverAddress: "Proxy.Example."
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(hosts["full:proxy.example"] as? String, "alias.example")
        XCTAssertEqual(hosts["full:alias.example"] as? [String], ["2001:db8::45"])
        XCTAssertEqual(prepared.serverAddress, "Proxy.Example.")
        XCTAssertEqual(prepared.excludedServerAddresses, ["2001:db8::45"])
    }

    func testConfigPinningUsesBareExactAliasAndAddressArrayWithoutSystemLookup() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"hosts":{"Proxy.Example.":"Alias.Example.","Alias.Example.":["2001:0DB8:0:0::47","203.0.113.47"]}},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"proxy.example","port":443,"users":[]}]}}]}"#,
            serverAddress: "proxy.example"
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(hosts["full:proxy.example"] as? String, "alias.example")
        XCTAssertEqual(
            hosts["full:alias.example"] as? [String],
            ["2001:db8::47", "203.0.113.47"]
        )
        XCTAssertNil(hosts["Proxy.Example."])
        XCTAssertNil(hosts["Alias.Example."])
        XCTAssertEqual(
            prepared.excludedServerAddresses,
            ["2001:db8::47", "203.0.113.47"]
        )
    }

    func testConfigPinningBootstrapsEveryDomainVLESSServer() throws {
        let resolved = resolvedConfig(
            json: #"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"First.Example.","port":443,"users":[]},{"address":"192.0.2.10","port":443,"users":[]}]}},{"protocol":"vless","settings":{"vnext":[{"address":"Second.Example","port":8443,"users":[]}]}}]}"#
        )
        var resolvedDomains: [String] = []

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                resolvedDomains.append(domain)
                return [
                    "first.example": ["2001:db8::41", "203.0.113.41"],
                    "second.example": ["203.0.113.42", "2001:db8::42"],
                ][domain]
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let firstSettings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let firstVnext = try XCTUnwrap(firstSettings["vnext"] as? [[String: Any]])
        let secondSettings = try XCTUnwrap(outbounds[1]["settings"] as? [String: Any])
        let secondVnext = try XCTUnwrap(secondSettings["vnext"] as? [[String: Any]])

        XCTAssertEqual(firstVnext[0]["address"] as? String, "First.Example.")
        XCTAssertEqual(firstVnext[1]["address"] as? String, "192.0.2.10")
        XCTAssertEqual(secondVnext[0]["address"] as? String, "Second.Example")
        XCTAssertEqual(
            hosts["full:first.example"] as? [String],
            ["2001:db8::41", "203.0.113.41"]
        )
        XCTAssertEqual(
            hosts["full:second.example"] as? [String],
            ["203.0.113.42", "2001:db8::42"]
        )
        XCTAssertEqual(
            prepared.excludedServerAddresses,
            [
                "192.0.2.10",
                "2001:db8::41",
                "203.0.113.41",
                "203.0.113.42",
                "2001:db8::42",
            ]
        )
        XCTAssertEqual(resolvedDomains, ["first.example", "second.example"])
    }

    func testConfigPinningRetainsExistingAddressArrayWithoutSystemLookup() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"hosts":{"full:proxy.example":["2001:0DB8:0:0::46","203.0.113.46","203.0.113.46"]}},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"proxy.example","port":443,"users":[]}]}}]}"#
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(
            hosts["full:proxy.example"] as? [String],
            ["2001:db8::46", "203.0.113.46"]
        )
        XCTAssertEqual(
            prepared.excludedServerAddresses,
            ["2001:db8::46", "203.0.113.46"]
        )
    }

    func testConfigPinningExcludesOnlyIPCarrierEndpointsWithoutLookup() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":["198.51.100.53"]},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.60","port":443,"users":[]},{"address":"2001:db8::60","port":443,"users":[]}]}}]}"#,
            serverAddress: "203.0.113.60"
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )

        XCTAssertEqual(
            prepared.excludedServerAddresses,
            ["203.0.113.60", "2001:db8::60"]
        )
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddresses: prepared.excludedServerAddresses,
            resolvedDNSConfiguration: .localDNSAnchor
        )
        XCTAssertEqual(
            settings.ipv4Settings?.excludedRoutes?.map(\.destinationAddress),
            ["203.0.113.60"]
        )
        XCTAssertEqual(
            settings.ipv6Settings?.excludedRoutes?.map(\.destinationAddress),
            ["2001:db8::60"]
        )
    }

    func testConfigPinningUsesAndCanonicalizesExistingExactAliasChain() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"hosts":{"full:Proxy.Example.":"Alias.Example.","full:Alias.Example.":"203.0.113.45"}},"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"Proxy.Example.","port":443,"users":[]}]}}]}"#,
            serverAddress: "Proxy.Example."
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])
        let outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
        let settings = try XCTUnwrap(outbounds[0]["settings"] as? [String: Any])
        let vnext = try XCTUnwrap(settings["vnext"] as? [[String: Any]])

        XCTAssertEqual(hosts["full:proxy.example"] as? String, "alias.example")
        XCTAssertEqual(hosts["full:alias.example"] as? [String], ["203.0.113.45"])
        XCTAssertNil(hosts["full:Proxy.Example."])
        XCTAssertNil(hosts["full:Alias.Example."])
        XCTAssertEqual(vnext[0]["address"] as? String, "Proxy.Example.")
        XCTAssertEqual(prepared.serverAddress, "Proxy.Example.")
        XCTAssertEqual(prepared.excludedServerAddresses, ["203.0.113.45"])
    }

    func testConfigPinningResolvesMissingAliasTerminalForDomainDNSUpstream() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":["Resolver.Example.:5353"],"hosts":{"full:resolver.example":"Bootstrap.Example."}},"outbounds":[{"protocol":"freedom"}]}"#
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTAssertEqual(domain, "bootstrap.example")
                return ["198.51.100.54", "2001:db8::54"]
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(hosts["full:resolver.example"] as? String, "bootstrap.example")
        XCTAssertEqual(
            hosts["full:bootstrap.example"] as? [String],
            ["198.51.100.54", "2001:db8::54"]
        )
        XCTAssertEqual(
            prepared.excludedServerAddresses,
            []
        )
    }

    func testConfigPinningAcceptsEightExactMappingSteps() throws {
        var hosts: [String: String] = [:]
        for index in 0 ..< 7 {
            hosts["full:alias\(index).example"] = "alias\(index + 1).example"
        }
        hosts["full:alias7.example"] = "203.0.113.47"
        let resolved = try resolvedConfigWithDNSHosts(
            hosts,
            server: "alias0.example"
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )

        XCTAssertFalse(prepared.json.isEmpty)
    }

    func testConfigPinningRejectsAliasCycle() {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":["cycle-a.example"],"hosts":{"full:cycle-a.example":"cycle-b.example","full:cycle-b.example":"cycle-a.example"}},"outbounds":[{"protocol":"freedom"}]}"#
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
                resolved,
                resolveAddress: { domain in
                    XCTFail("unexpected system lookup for \(domain)")
                    return nil
                }
            )
        ) { error in
            guard case XrayPacketTunnelProviderError.outboundServerResolutionFailed = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testConfigPinningRejectsCarrierResolutionContainingTunnelOwnedAddress() {
        let resolved = resolvedConfig(
            json: #"{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"proxy.example","port":443,"users":[]}]}}]}"#,
            serverAddress: "proxy.example"
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
                resolved,
                resolveAddress: { domain in
                    XCTAssertEqual(domain, "proxy.example")
                    return ["198.18.0.1", "203.0.113.61"]
                }
            )
        ) { error in
            guard case XrayPacketTunnelProviderError.outboundServerResolutionFailed = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testConfigPinningRejectsDefaultPortDNSResolutionContainingTunnelOwnedAddress() {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":["resolver.example"]},"outbounds":[{"protocol":"freedom"}]}"#
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
                resolved,
                resolveAddress: { domain in
                    XCTAssertEqual(domain, "resolver.example")
                    return ["198.18.0.1", "203.0.113.62"]
                }
            )
        ) { error in
            guard case XrayPacketTunnelProviderError.outboundServerResolutionFailed = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testConfigPinningRejectsPort53DNSAliasEndingAtTunnelOwnedAddress() {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":[{"address":"resolver.example","port":0}],"hosts":{"full:resolver.example":"bootstrap.example","full:bootstrap.example":"198.18.0.2"}},"outbounds":[{"protocol":"freedom"}]}"#
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
                resolved,
                resolveAddress: { domain in
                    XCTFail("unexpected system lookup for \(domain)")
                    return nil
                }
            )
        ) { error in
            guard case XrayPacketTunnelProviderError.outboundServerResolutionFailed = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testConfigPinningAllowsNonstandardPortDNSAliasEndingAtTunnelOwnedAddress() throws {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":[{"address":"resolver.example","port":5353}],"hosts":{"full:resolver.example":"bootstrap.example","full:bootstrap.example":"198.18.0.1"}},"outbounds":[{"protocol":"freedom"}]}"#
        )

        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            resolved,
            resolveAddress: { domain in
                XCTFail("unexpected system lookup for \(domain)")
                return nil
            }
        )
        let root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(prepared.json.utf8)) as? [String: Any]
        )
        let dns = try XCTUnwrap(root["dns"] as? [String: Any])
        let hosts = try XCTUnwrap(dns["hosts"] as? [String: Any])

        XCTAssertEqual(hosts["full:resolver.example"] as? String, "bootstrap.example")
        XCTAssertEqual(hosts["full:bootstrap.example"] as? [String], ["198.18.0.1"])
        XCTAssertEqual(prepared.excludedServerAddresses, [])
    }

    func testConfigPinningRejectsAliasChainBeyondEightSteps() throws {
        var hosts: [String: String] = [:]
        for index in 0 ..< 8 {
            hosts["full:alias\(index).example"] = "alias\(index + 1).example"
        }
        hosts["full:alias8.example"] = "203.0.113.48"
        let resolved = try resolvedConfigWithDNSHosts(
            hosts,
            server: "alias0.example"
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
                resolved,
                resolveAddress: { domain in
                    XCTFail("unexpected system lookup for \(domain)")
                    return nil
                }
            )
        ) { error in
            guard case XrayPacketTunnelProviderError.outboundServerResolutionFailed = error else {
                return XCTFail("unexpected error: \(error)")
            }
        }
    }

    func testConfigPinningFailsClosedForUnresolvedDomainDNSUpstream() {
        let resolved = resolvedConfig(
            json: #"{"dns":{"servers":["unresolved.example"]},"outbounds":[{"protocol":"freedom"}]}"#
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
                resolved,
                resolveAddress: { _ in nil }
            )
        )
    }

    private func fakeIPTopologyConfig(
        freedomFirst: Bool = false,
        rules: [[String: Any]]? = nil,
        dnsServers: [String] = []
    ) throws -> String {
        let profile = try XrayVlessURLImporter.profile(
            from: "vless://11111111-1111-4111-8111-111111111111@203.0.113.10:443?type=tcp&encryption=none&security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&fp=chrome&sni=example.com&sid=0123456789ab&spx=%2F&flow=xtls-rprx-vision#topology-test",
            hostBundleIdentifier: "org.example.XrayClient"
        )
        var root = try XCTUnwrap(
            JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any]
        )
        if freedomFirst {
            var outbounds = try XCTUnwrap(root["outbounds"] as? [[String: Any]])
            outbounds.swapAt(0, 1)
            root["outbounds"] = outbounds
        }
        if let rules {
            var routing = root["routing"] as? [String: Any] ?? [:]
            routing["rules"] = rules
            root["routing"] = routing
        }
        if !dnsServers.isEmpty {
            var dns = try XCTUnwrap(root["dns"] as? [String: Any])
            dns["servers"] = dnsServers
            root["dns"] = dns
        }
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private func assertInvalidDNSRoutingTopology(
        _ configJSON: String,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.validateConfigBeforeApplyingNetworkSettings(
                configJSON,
                geodataSearchDirectory: nil
            ),
            file: file,
            line: line
        ) { error in
            guard case XrayPacketTunnelProviderError.invalidDNSRoutingTopology = error else {
                return XCTFail("unexpected error: \(error)", file: file, line: line)
            }
        }
    }

    private func resolvedConfig(
        json: String,
        serverAddress: String? = nil
    ) -> XrayPacketTunnelProvider.ResolvedConfig {
        XrayPacketTunnelProvider.ResolvedConfig(
            json: json,
            source: "test",
            serverAddress: serverAddress,
            debugLoggingEnabled: false,
            useTunFileDescriptor: true,
            tunRuntimeProfile: .default,
            startupProbeConfiguration: .disabled,
            dnsConfiguration: .system
        )
    }

    private func resolvedConfigWithDNSHosts(
        _ hosts: [String: String],
        server: String
    ) throws -> XrayPacketTunnelProvider.ResolvedConfig {
        let root: [String: Any] = [
            "dns": [
                "servers": [server],
                "hosts": hosts,
            ],
            "outbounds": [
                ["protocol": "freedom"],
            ],
        ]
        let data = try JSONSerialization.data(withJSONObject: root, options: [.sortedKeys])
        return resolvedConfig(json: String(decoding: data, as: UTF8.self))
    }

}

private let legacyDirectTunConfigJSON = """
{
  "inbounds": [
    {
      "tag": "tun-in",
      "protocol": "tun",
      "listen": "127.0.0.1",
      "port": 0,
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
"""

private final class TunnelTestSecureConfigStore: XraySecureConfigStoring, @unchecked Sendable {
    private var values: [String: String] = [:]

    func store(configJSON: String, reference: String) throws {
        values[reference] = configJSON
    }

    func configJSON(reference: String) throws -> String? {
        values[reference]
    }

    func remove(reference: String) throws {
        values.removeValue(forKey: reference)
    }
}
