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

    func testNetworkSettingsExcludeIPv4ProxyServerFromDefaultRoute() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "203.0.113.10",
            resolvedDNSConfiguration: .localFakeIPAnchor
        )

        let excludedRoute = settings.ipv4Settings?.excludedRoutes?.first
        XCTAssertEqual(excludedRoute?.destinationAddress, "203.0.113.10")
        XCTAssertEqual(excludedRoute?.destinationSubnetMask, "255.255.255.255")
    }

    func testNetworkSettingsApplyLocalFakeIPAnchorForAllDomains() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "203.0.113.10",
            resolvedDNSConfiguration: .localFakeIPAnchor
        )

        XCTAssertEqual(settings.dnsSettings?.servers, ["198.18.0.1"])
        XCTAssertEqual(settings.dnsSettings?.matchDomains, [""])
    }

    func testNetworkSettingsUseExplicitCustomDnsForAllDomains() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "203.0.113.10",
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

        XCTAssertEqual(configuration, .localFakeIPAnchor)
    }

    func testResolvedDnsConfigurationFailsClosedWithoutFakeIPOrExplicitServers() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"inbounds":[]}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
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

    func testResolvedDnsConfigurationRejectsUnknownFakeIPField() {
        let configuration = XrayPacketTunnelProvider.resolvedDNSConfiguration(
            configJSON: #"{"dns":{"fakeIp":{"enabled":true,"ipv4Pool":"198.19.0.0/16","unexpected":true}}}"#,
            explicit: .system
        )

        XCTAssertNil(configuration)
    }

    func testConfigPreflightRejectsInvalidFakeIPBeforeNetworkSettings() {
        let invalidConfigJSON = XrayClientProfile.directTunConfigJSON.replacingOccurrences(
            of: #""enabled": true"#,
            with: #""enabled": 1"#
        )

        XCTAssertThrowsError(
            try XrayPacketTunnelProvider.validateConfigBeforeApplyingNetworkSettings(
                invalidConfigJSON,
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

    func testDnsConfigurationRejectsIPv6UntilIPv6TunnelRoutingIsInstalled() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.dnsConfiguration(
                options: nil,
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerDNSServersKey: "2001:db8::53",
                ]
            ),
            .invalid
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

    func testNetworkSettingsDoNotInstallIPv6DefaultRouteYet() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "203.0.113.10",
            resolvedDNSConfiguration: .localFakeIPAnchor
        )

        XCTAssertNil(settings.ipv6Settings)
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

    func testConfigResolutionMigratesLegacyDirectProfileForOnDemandStart() throws {
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

        XCTAssertEqual(resolved?.json, XrayClientProfile.directTunConfigJSON)
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
