import XCTest
@testable import XrayMobileAdapter

final class XrayRuntimeWorkerThreadsTests: XCTestCase {
    func testCurrentLibrarySetsTheRequestedWorkerCount() throws {
        XCTAssertTrue(XrayCore.ffiInfo.supports(.runtimeWorkerThreads))
        for workers: UInt32 in [1, 2, 6] {
            XCTAssertNoThrow(
                try XrayCore(
                    configJSON: #"{"outbounds":[{"protocol":"freedom"}]}"#,
                    runtimeWorkerThreads: workers
                )
            )
        }
    }

    func testOutOfRangeWorkerCountFailsBeforeConfigLoad() {
        XCTAssertThrowsError(
            try XrayCore(
                configJSON: #"{"outbounds":[{"protocol":"freedom"}]}"#,
                runtimeWorkerThreads: 65
            )
        )
    }
}
