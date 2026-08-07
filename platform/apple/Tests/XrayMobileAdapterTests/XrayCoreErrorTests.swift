import XCTest
import XrayRust
@testable import XrayMobileAdapter

final class XrayCoreErrorTests: XCTestCase {
    func testStatusErrorSurvivesTheNSErrorBridge() {
        let error = XrayCoreError.status(code: XRAY_STATUS_PANIC, message: "config rejected")
        let bridged = error as NSError

        XCTAssertEqual(bridged.domain, XrayCoreError.errorDomain)
        XCTAssertTrue(
            bridged.localizedDescription.contains("config rejected"),
            "expected the engine message, got \(bridged.localizedDescription)"
        )
    }

    func testEveryCaseHasADistinctErrorCode() {
        let codes = [
            XrayCoreError.status(code: XRAY_STATUS_PANIC, message: "x").errorCode,
            XrayCoreError.incompatibleFFIMajorVersion(expected: 1, actual: 2).errorCode,
            XrayCoreError.missingHandle.errorCode,
            XrayCoreError.notRunning.errorCode,
            XrayCoreError.invalidUtf8.errorCode,
        ]
        XCTAssertEqual(Set(codes).count, codes.count)
    }
}
