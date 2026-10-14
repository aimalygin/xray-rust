import XCTest
@testable import XrayMobileAdapter

final class XrayHysteriaStreamLimitsTests: XCTestCase {
    func testDefaultAndBoundaryLimits() throws {
        XCTAssertEqual(try XrayHysteriaStreamLimits().maxTcpStreams, 64)
        XCTAssertEqual(try XrayHysteriaStreamLimits().maxUdpSessions, 32)
        XCTAssertNoThrow(try XrayHysteriaStreamLimits(maxTcpStreams: 1, maxUdpSessions: 1))
        XCTAssertNoThrow(try XrayHysteriaStreamLimits(maxTcpStreams: 256, maxUdpSessions: 128))
        XCTAssertThrowsError(try XrayHysteriaStreamLimits(maxTcpStreams: 0))
        XCTAssertThrowsError(try XrayHysteriaStreamLimits(maxTcpStreams: 257))
        XCTAssertThrowsError(try XrayHysteriaStreamLimits(maxUdpSessions: 0))
        XCTAssertThrowsError(try XrayHysteriaStreamLimits(maxUdpSessions: 129))
    }
}
