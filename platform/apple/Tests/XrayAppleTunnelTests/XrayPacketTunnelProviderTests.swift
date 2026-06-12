import XCTest
import XrayAppleShared
@testable import XrayAppleTunnel

@available(macOS 13.0, *)
final class XrayPacketTunnelProviderTests: XCTestCase {
    func testNetworkSettingsExcludeIPv4ProxyServerFromDefaultRoute() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "217.154.252.68"
        )

        let excludedRoute = settings.ipv4Settings?.excludedRoutes?.first
        XCTAssertEqual(excludedRoute?.destinationAddress, "217.154.252.68")
        XCTAssertEqual(excludedRoute?.destinationSubnetMask, "255.255.255.255")
    }

    func testNetworkSettingsUseVpnDnsForAllDomains() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "217.154.252.68"
        )

        XCTAssertEqual(settings.dnsSettings?.servers, ["1.1.1.1", "8.8.8.8"])
        XCTAssertEqual(settings.dnsSettings?.matchDomains, [""])
    }

    func testNetworkSettingsDoNotInstallIPv6DefaultRouteYet() {
        let settings = XrayPacketTunnelProvider.networkSettings(
            excludingServerAddress: "217.154.252.68"
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

    func testPacketIOBackendKeepsFileDescriptorWhenQuicBlockingIsEnabled() {
        XCTAssertEqual(
            XrayPacketTunnelProvider.packetIOBackend(
                discoveredTunFileDescriptor: 42,
                useTunFileDescriptor: true,
                blockQUIC: true
            ),
            .darwinUtunFileDescriptor(42)
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

    func testQuicBlockingDisabledWhenUnset() {
        XCTAssertFalse(
            XrayPacketTunnelProvider.quicBlockingEnabled(
                options: nil,
                providerConfiguration: nil
            )
        )
    }

    func testQuicBlockingReadsStartOptions() {
        XCTAssertTrue(
            XrayPacketTunnelProvider.quicBlockingEnabled(
                options: [
                    XrayTunnelProviderMessage.blockQUICOptionKey: NSNumber(value: true),
                ],
                providerConfiguration: [
                    XrayTunnelProviderMessage.providerBlockQUICKey: false,
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
                        "address": "217.154.252.68",
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
              }
            }
            """
        )

        XCTAssertEqual(
            summary,
            "inbounds=tun-in:tun outbounds=proxy:vless@217.154.252.68:32134 network=tcp security=reality flow=xtls-rprx-vision, direct:freedom routingRules=2"
        )
        XCTAssertFalse(summary.contains("secret"))
    }
}
