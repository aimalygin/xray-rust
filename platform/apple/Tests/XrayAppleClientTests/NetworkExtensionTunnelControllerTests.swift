import XCTest
@testable import XrayAppleClient

#if canImport(NetworkExtension)
import NetworkExtension

@available(macOS 13.0, *)
@MainActor
final class NetworkExtensionTunnelControllerTests: XCTestCase {
    func testDefaultStartupProbeIsDisabledForTvOSBringup() {
        XCTAssertFalse(
            NetworkExtensionTunnelController.defaultStartupProbeEnabled(platform: .tvOS)
        )
    }
}
#endif
