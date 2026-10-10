import Foundation
import XrayRust

/// Original application tuple before FakeDNS restoration. Addresses are network
/// byte order (4 or 16 bytes); ports are host endian. Protocol is TCP=6 or UDP=17.
public struct XrayTunFlow: Equatable, Sendable {
    public let id: UInt64
    public let protocolNumber: UInt8
    public let addressFamily: UInt8
    public let sourceAddress: Data
    public let sourcePort: UInt16
    public let destinationAddress: Data
    public let destinationPort: UInt16
}

/// Called concurrently off the packet loop. Never call core lifecycle methods
/// from the callback. A timeout bounds the decision, not callback execution.
public struct XrayTunAdmissionOptions: Sendable {
    public let timeoutMilliseconds: UInt32
    public let failOpen: Bool
    public let admit: @Sendable (XrayTunFlow) -> Bool

    public init(timeoutMilliseconds: UInt32 = 100, failOpen: Bool = false,
                admit: @escaping @Sendable (XrayTunFlow) -> Bool) throws {
        guard (1...5000).contains(timeoutMilliseconds) else {
            throw XrayCoreError.status(code: XRAY_STATUS_INVALID_ARGUMENT,
                                      message: "TUN admission timeout must be in 1...5000 ms")
        }
        self.timeoutMilliseconds = timeoutMilliseconds
        self.failOpen = failOpen
        self.admit = admit
    }
}

final class XrayTunAdmissionContext: Sendable {
    let admit: @Sendable (XrayTunFlow) -> Bool
    init(_ options: XrayTunAdmissionOptions) { admit = options.admit }
}

let xrayTunAdmissionCallback: XrayTunAdmissionCallback = { pointer, userData in
    guard let pointer, let userData else { return 0 }
    let context = Unmanaged<XrayTunAdmissionContext>.fromOpaque(userData).takeUnretainedValue()
    var raw = pointer.pointee
    let length = raw.address_family == 4 ? 4 : 16
    let source = withUnsafeBytes(of: &raw.source_address) { Data($0.prefix(length)) }
    let destination = withUnsafeBytes(of: &raw.destination_address) { Data($0.prefix(length)) }
    return context.admit(XrayTunFlow(id: raw.id, protocolNumber: raw.`protocol`,
        addressFamily: raw.address_family, sourceAddress: source, sourcePort: raw.source_port,
        destinationAddress: destination, destinationPort: raw.destination_port)) ? 1 : 0
}

let xrayTunAdmissionRelease: XrayTunAdmissionRelease = { pointer in
    if let pointer { Unmanaged<XrayTunAdmissionContext>.fromOpaque(pointer).release() }
}
