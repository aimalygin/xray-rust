#if os(macOS)
import XCTest
import XrayAppleShared
@testable import XrayAppleClient

@available(macOS 13.0, *)
final class XrayMacPresentationTests: XCTestCase {
    func testMenuBarSystemImagePrioritizesIssueThenBusyThenConnectionStatus() {
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .connected,
                isBusy: false,
                lastErrorMessage: "failed"
            ),
            "exclamationmark.triangle"
        )
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .connected,
                isBusy: true,
                lastErrorMessage: nil
            ),
            "arrow.triangle.2.circlepath"
        )
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .connected,
                isBusy: false,
                lastErrorMessage: nil
            ),
            "network"
        )
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .disconnected,
                isBusy: false,
                lastErrorMessage: nil
            ),
            "network.slash"
        )
    }

    func testPrimaryTunnelActionReflectsConnectionStatus() {
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionTitle(for: .connected),
            "Disconnect"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionSystemImage(for: .connected),
            "stop.circle"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionTitle(for: .connecting),
            "Disconnect"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionTitle(for: .disconnected),
            "Connect"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionSystemImage(for: .disconnected),
            "power"
        )
    }
}
#endif
