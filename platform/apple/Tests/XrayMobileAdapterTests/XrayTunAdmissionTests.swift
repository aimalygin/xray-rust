import Foundation
import XCTest
@testable import XrayMobileAdapter

final class XrayTunAdmissionTests: XCTestCase {
    func testAdmissionRequiresBoundedTimeoutAndLoadsOnlyWhenSupported() throws {
        XCTAssertThrowsError(try XrayTunAdmissionOptions(timeoutMilliseconds: 0) { _ in true })
        XCTAssertThrowsError(try XrayTunAdmissionOptions(timeoutMilliseconds: 5001) { _ in true })
        XCTAssertTrue(XrayCore.ffiInfo.supports(.tunAdmission))
        let options = try XrayTunAdmissionOptions { _ in false }
        let core = try XrayCore(configJSON:
            """
            {"inbounds":[{"protocol":"tun"}],"outbounds":[{"protocol":"freedom"}]}
            """, tunAdmission: options)
        try core.start()
        try core.stop()
    }
}
