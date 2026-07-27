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
            excludingServerAddress: "203.0.113.10"
        )

        let excludedRoute = settings.ipv4Settings?.excludedRoutes?.first
        XCTAssertEqual(excludedRoute?.destinationAddress, "203.0.113.10")
        XCTAssertEqual(excludedRoute?.destinationSubnetMask, "255.255.255.255")
    }

    func testNetworkSettingsUseVpnDnsForAllDomains() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "203.0.113.10"
        )

        XCTAssertEqual(settings.dnsSettings?.servers, ["1.1.1.1", "8.8.8.8"])
        XCTAssertEqual(settings.dnsSettings?.matchDomains, [""])
    }

    func testNetworkSettingsDoNotInstallIPv6DefaultRouteYet() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "203.0.113.10"
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

    func testStartupProbeDefaultsToGenerate204() {
        let probe = XrayPacketTunnelProvider.startupProbe(
            options: nil,
            providerConfiguration: nil
        )

        XCTAssertEqual(probe?.url, "https://www.google.com/generate_204")
        XCTAssertEqual(probe?.timeoutMs, 5_000)
        XCTAssertNil(probe?.outboundTag)
    }

    func testStartupProbeStartOptionsOverrideProviderConfiguration() {
        let probe = XrayPacketTunnelProvider.startupProbe(
            options: [
                XrayTunnelProviderMessage.startupProbeURLOptionKey: "https://probe.example/204" as NSString,
                XrayTunnelProviderMessage.startupProbeTimeoutMsOptionKey: NSNumber(value: 7_500),
                XrayTunnelProviderMessage.startupProbeOutboundTagOptionKey: "proxy" as NSString,
            ],
            providerConfiguration: [
                XrayTunnelProviderMessage.providerStartupProbeURLKey: "https://provider.example/204",
                XrayTunnelProviderMessage.providerStartupProbeTimeoutMsKey: 2_500,
                XrayTunnelProviderMessage.providerStartupProbeOutboundTagKey: "direct",
            ]
        )

        XCTAssertEqual(probe?.url, "https://probe.example/204")
        XCTAssertEqual(probe?.timeoutMs, 7_500)
        XCTAssertEqual(probe?.outboundTag, "proxy")
    }

    func testStartupProbeCanBeDisabledFromProviderConfiguration() {
        let probe = XrayPacketTunnelProvider.startupProbe(
            options: nil,
            providerConfiguration: [
                XrayTunnelProviderMessage.providerStartupProbeEnabledKey: false,
            ]
        )

        XCTAssertNil(probe)
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
