#if canImport(Darwin)
import XCTest
import XrayKernelControl

/// The shim hand-declares an ABI the iOS and tvOS SDKs do not ship, so its
/// layout is pinned here as well as by the static assertions in the shim
/// itself. A mismatch would not fail loudly at runtime: `getpeername` and
/// `ioctl` would fill the wrong offsets and discovery would quietly stop
/// finding the utun.
final class XrayKernelControlTests: XCTestCase {
    func testControlInfoMatchesTheKernelLayout() {
        // u_int32_t ctl_id + char ctl_name[96]
        XCTAssertEqual(MemoryLayout<xray_ctl_info>.size, 100)
    }

    func testControlAddressMatchesTheKernelLayout() {
        // sc_len + sc_family + ss_sysaddr + sc_id + sc_unit + sc_reserved[5]
        XCTAssertEqual(MemoryLayout<xray_sockaddr_ctl>.size, 32)
    }

    func testControlInfoRequestEncodesCtliocginfo() {
        // _IOWR('N', 3, struct ctl_info) with a 100-byte payload.
        XCTAssertEqual(XRAY_CTLIOCGINFO, 0xc064_4e03)
    }
}
#endif
