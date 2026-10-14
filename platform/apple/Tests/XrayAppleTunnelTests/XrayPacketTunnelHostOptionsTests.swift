import Darwin
import XCTest
import XrayAppleShared
import XrayMobileAdapter
@testable import XrayAppleTunnel

@available(macOS 13.0, *)
final class XrayPacketTunnelHostOptionsTests: XCTestCase {
    func testDefaultsLeaveHostOptionsDisabled() throws {
        let resolved = try XrayPacketTunnelProvider.resolvingHostOptions(
            configuration(), hysteriaStreamLimits: { nil }, tunAdmissionOptions: { nil })
        XCTAssertNil(resolved.hysteriaStreamLimits)
        XCTAssertNil(resolved.tunAdmission)
    }

    func testHostOptionsAreCapturedOnceAndSurviveDNSPreparation() throws {
        let provider = HostOptions()
        let resolved = try XrayPacketTunnelProvider.resolvingHostOptions(configuration(),
            hysteriaStreamLimits: provider.hysteriaStreamLimits,
            tunAdmissionOptions: provider.tunAdmissionOptions)
        let prepared = try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(resolved)
        XCTAssertEqual(prepared.hysteriaStreamLimits, try XrayHysteriaStreamLimits(
            maxTcpStreams: 128, maxUdpSessions: 64))
        XCTAssertEqual(prepared.tunAdmission?.timeoutMilliseconds, 500)
        XCTAssertEqual(prepared.tunAdmission?.failOpen, true)
        XCTAssertEqual(provider.limitsCalls, 1)
        XCTAssertEqual(provider.admissionCalls, 1)
    }

    func testInvalidHostSettingsFailResolution() throws {
        let provider = HostOptions()
        provider.invalidLimits = true
        XCTAssertThrowsError(try XrayPacketTunnelProvider.resolvingHostOptions(configuration(),
            hysteriaStreamLimits: provider.hysteriaStreamLimits,
            tunAdmissionOptions: provider.tunAdmissionOptions))
        XCTAssertEqual(provider.admissionCalls, 0)
        provider.invalidLimits = false
        provider.invalidAdmission = true
        XCTAssertThrowsError(try XrayPacketTunnelProvider.resolvingHostOptions(configuration(),
            hysteriaStreamLimits: provider.hysteriaStreamLimits,
            tunAdmissionOptions: provider.tunAdmissionOptions))
    }

    func testDefaultsStillForwardUDPThroughBothBackends() throws {
        for useFD in [false, true] {
            try exerciseUDP(useFD: useFD, decision: nil)
        }
    }

    func testAdmissionAllowsUDPAndCachesDecisionThroughBothBackends() throws {
        for useFD in [false, true] {
            try exerciseUDP(useFD: useFD, decision: true)
        }
    }

    func testExplicitDenialCannotFailOpenThroughEitherBackend() throws {
        for useFD in [false, true] {
            try exerciseUDP(useFD: useFD, decision: false)
        }
    }

    private func exerciseUDP(useFD: Bool, decision: Bool?) throws {
        let receiver = socket(AF_INET, SOCK_DGRAM, 0)
        XCTAssertGreaterThanOrEqual(receiver, 0)
        defer { close(receiver) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(receiver, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        XCTAssertEqual(bound, 0)
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(receiver, $0, &size)
            }
        }, 0)
        let port = UInt16(bigEndian: address.sin_port)
        var pair: [Int32] = [-1, -1]
        // Exercise the real borrowed-fd path with Darwin's four-byte packet prefix.
        // No Network Extension entitlement or system route changes are needed.
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_DGRAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        let provider = HostOptions()
        let called = expectation(description: "admission \(useFD)")
        called.assertForOverFulfill = true
        if let decision {
            provider.admit = { flow in
                XCTAssertEqual(flow.protocolNumber, 17)
                XCTAssertEqual(flow.addressFamily, 4)
                XCTAssertEqual(flow.sourceAddress, Data([10, 10, 0, 2]))
                XCTAssertEqual(flow.sourcePort, 41000)
                XCTAssertEqual(flow.destinationAddress, Data([127, 0, 0, 1]))
                XCTAssertEqual(flow.destinationPort, port)
                called.fulfill()
                return decision
            }
        }
        let resolved = try XrayPacketTunnelProvider.resolvingHostOptions(configuration(),
            hysteriaStreamLimits: { try decision == nil ? nil : provider.hysteriaStreamLimits() },
            tunAdmissionOptions: { try decision == nil ? nil : provider.tunAdmissionOptions() })
        let core = try XrayPacketTunnelProvider.makeCore(
            resolvedConfig: resolved,
            borrowedDarwinTunFileDescriptor: useFD ? pair[0] : nil,
            diagnosticLogDirectory: nil)
        try core.start()
        defer { try? core.stop() }
        for _ in 0..<3 {
            let packet = udpPacket(port: port)
            if useFD {
                let frame = Data([0, 0, 0, UInt8(AF_INET)]) + packet
                XCTAssertEqual(frame.withUnsafeBytes { write(pair[1], $0.baseAddress, $0.count) }, frame.count)
            } else {
                try core.pushPacket(packet)
            }
            var fd = pollfd(fd: receiver, events: Int16(POLLIN), revents: 0)
            XCTAssertEqual(poll(&fd, 1, decision == false ? 200 : 2_000), decision == false ? 0 : 1)
            if decision != false, fd.revents & Int16(POLLIN) != 0 {
                var buffer = [UInt8](repeating: 0, count: 64)
                let count = recv(receiver, &buffer, buffer.count, 0)
                XCTAssertEqual(count, 9)
                if count > 0 { XCTAssertEqual(Data(buffer.prefix(count)), Data("admission".utf8)) }
            }
        }
        if decision != nil {
            wait(for: [called], timeout: 2)
        } else {
            // No callback is registered in the default path.
            called.fulfill()
            wait(for: [called], timeout: 0)
        }
    }

    private func configuration() -> XrayPacketTunnelProvider.ResolvedConfig {
        .init(json: #"{"inbounds":[{"protocol":"tun"}],"outbounds":[{"protocol":"freedom"}]}"#,
              source: "test", serverAddress: nil, debugLoggingEnabled: false,
              useTunFileDescriptor: true, tunRuntimeProfile: .default,
              startupProbeConfiguration: .disabled, dnsConfiguration: .system)
    }

    private func udpPacket(port: UInt16) -> Data {
        var bytes = [UInt8](repeating: 0, count: 37)
        func put16(_ offset: Int, _ value: UInt16) {
            bytes[offset] = UInt8(value >> 8); bytes[offset + 1] = UInt8(value & 255)
        }
        bytes[0] = 0x45; put16(2, UInt16(bytes.count))
        bytes[8] = 64; bytes[9] = 17
        bytes.replaceSubrange(12..<20, with: [10, 10, 0, 2, 127, 0, 0, 1])
        var sum = stride(from: 0, to: 20, by: 2).reduce(0) {
            $0 + (Int(bytes[$1]) << 8) + Int(bytes[$1 + 1])
        }
        while sum > 65535 { sum = (sum & 65535) + (sum >> 16) }
        put16(10, ~UInt16(sum)); put16(20, 41000); put16(22, port); put16(24, 17)
        bytes.replaceSubrange(28..<37, with: "admission".utf8)
        return Data(bytes)
    }
}

@available(macOS 13.0, *)
private final class HostOptions {
    var limitsCalls = 0
    var admissionCalls = 0
    var invalidLimits = false
    var invalidAdmission = false
    var admit: @Sendable (XrayTunFlow) -> Bool = { _ in false }

    func hysteriaStreamLimits() throws -> XrayHysteriaStreamLimits? {
        limitsCalls += 1
        return try .init(maxTcpStreams: invalidLimits ? 0 : 128, maxUdpSessions: 64)
    }

    func tunAdmissionOptions() throws -> XrayTunAdmissionOptions? {
        admissionCalls += 1
        return try .init(timeoutMilliseconds: invalidAdmission ? 0 : 500,
                         failOpen: true, admit: admit)
    }
}
