import XCTest
@testable import XrayMobileAdapter

final class XrayTunMtuTests: XCTestCase {
    func testRangeIsEnforcedWithoutClamping() throws {
        XCTAssertEqual(XrayTunMtu.standard.value, 1_500)
        for value: UInt32 in [1_280, 1_500, 4_000, 9_000] {
            XCTAssertEqual(try XrayTunMtu(value).value, value)
        }
        for value: UInt32 in [0, 576, 1_279, 9_001, UInt32.max] {
            XCTAssertThrowsError(try XrayTunMtu(value))
        }
    }

    func testCurrentLibraryRunsTheRequestedMtu() throws {
        let jumbo = try XrayTunMtu(9_000)
        XCTAssertEqual(XrayCore.supportedTunMtu(jumbo), jumbo)
        let core = try XrayCore(
            configJSON: #"{"inbounds":[{"protocol":"tun"}],"outbounds":[{"protocol":"freedom"}]}"#,
            tunMtu: jumbo
        )
        XCTAssertEqual(core.tunMtu, jumbo)
        let standard = try XrayCore(configJSON: #"{"outbounds":[{"protocol":"freedom"}]}"#)
        XCTAssertEqual(standard.tunMtu, .standard)
    }
}
