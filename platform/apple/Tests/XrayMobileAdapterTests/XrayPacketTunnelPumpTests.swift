import XCTest
@testable import XrayMobileAdapter

final class XrayPacketTunnelPumpTests: XCTestCase {
    func testQuicBlockingDropsIPv4Udp443QuicInitialPacket() {
        let packet = Self.ipv4UDPPacket(
            destinationPort: 443,
            payload: Self.quicInitialPayload()
        )

        XCTAssertTrue(
            XrayPacketTunnelPump.shouldDropPacket(
                packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: true)
            )
        )
    }

    func testQuicBlockingDoesNotDropNonQuicIPv4Udp443Packet() {
        let packet = Self.ipv4UDPPacket(
            destinationPort: 443,
            payload: Data([0x13, 0x37, 0x42, 0x00])
        )

        XCTAssertFalse(
            XrayPacketTunnelPump.shouldDropPacket(
                packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: true)
            )
        )
    }

    func testQuicBlockingDoesNotDropIPv4Tcp443Packet() {
        let packet = Self.ipv4TCPPacket(destinationPort: 443)

        XCTAssertFalse(
            XrayPacketTunnelPump.shouldDropPacket(
                packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: true)
            )
        )
    }

    func testQuicBlockingDoesNotDropWhenDisabled() {
        let packet = Self.ipv4UDPPacket(
            destinationPort: 443,
            payload: Self.quicInitialPayload()
        )

        XCTAssertFalse(
            XrayPacketTunnelPump.shouldDropPacket(
                packet,
                options: XrayPacketTunnelPumpOptions(blockQUIC: false)
            )
        )
    }

    private static func ipv4UDPPacket(destinationPort: UInt16, payload: Data) -> Data {
        var packet = [UInt8](repeating: 0, count: 28 + payload.count)
        packet[0] = 0x45
        packet[9] = 17
        packet[22] = UInt8(destinationPort >> 8)
        packet[23] = UInt8(destinationPort & 0xff)
        packet.replaceSubrange(28..., with: payload)
        return Data(packet)
    }

    private static func ipv4TCPPacket(destinationPort: UInt16) -> Data {
        var packet = [UInt8](repeating: 0, count: 40)
        packet[0] = 0x45
        packet[9] = 6
        packet[22] = UInt8(destinationPort >> 8)
        packet[23] = UInt8(destinationPort & 0xff)
        return Data(packet)
    }

    private static func quicInitialPayload() -> Data {
        Data([
            0xc0,
            0x00, 0x00, 0x00, 0x01,
            0x08,
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x00,
        ])
    }
}
