#if canImport(Darwin)
import Darwin
import XCTest
@testable import XrayMobileAdapter

final class XrayDarwinTunFileDescriptorTests: XCTestCase {
    func testReturnsNilWhenNoUtunControlSocketIsOpen() {
        // A unit-test process holds no utun control socket, so discovery must
        // decline rather than latch onto an unrelated descriptor.
        XCTAssertNil(XrayDarwinTunFileDescriptor.discoverUtunFileDescriptor())
    }

    func testIgnoresAnOrdinaryConnectedSocket() throws {
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer {
            close(pair[0])
            close(pair[1])
        }

        // Both ends are connected, so getpeername succeeds on them. Discovery
        // must still reject them because sc_family is not AF_SYSTEM.
        XCTAssertNil(XrayDarwinTunFileDescriptor.discoverUtunFileDescriptor())
    }

    func testInterfaceNameIsNilForANonUtunDescriptor() throws {
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer {
            close(pair[0])
            close(pair[1])
        }

        XCTAssertNil(XrayDarwinTunFileDescriptor.interfaceName(for: pair[0]))
    }
}
#endif
