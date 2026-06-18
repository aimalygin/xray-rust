import XCTest
import XrayAppleShared
@testable import XrayAppleTunnel

@available(macOS 13.0, *)
final class XrayPacketTunnelProviderTests: XCTestCase {
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
            "inbounds=tun-in:tun outbounds=proxy:vless@203.0.113.10:32134 network=tcp security=reality flow=xtls-rprx-vision, direct:freedom routingRules=2 dnsFakeIp=enabled"
        )
        XCTAssertFalse(summary.contains("secret"))
    }

}
