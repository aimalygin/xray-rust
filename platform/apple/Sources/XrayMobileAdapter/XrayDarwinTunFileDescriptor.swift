import Darwin
import Foundation
import XrayKernelControl

public enum XrayDarwinTunFileDescriptor {
    private static let utunControlName = "com.apple.net.utun_control"
    private static let sysprotoControl: Int32 = 2
    private static let utunOptionInterfaceName: Int32 = 2

    /// `CTLIOCGINFO`, evaluated by the C shim.
    ///
    /// Swift refuses to import a macro whose value depends on the size of a
    /// struct, so this used to be rebuilt from the `_IOC` encoding by hand.
    /// `XrayKernelControl` evaluates the SDK's own macro instead — and declares
    /// the two structures below, which `<sys/kern_control.h>` provides on macOS
    /// but not on iOS or tvOS.
    private static let controlInfoRequest = XRAY_CTLIOCGINFO

    /// Locates the descriptor of the utun device the Network Extension opened
    /// for this provider.
    ///
    /// A descriptor qualifies only when it is a connected `AF_SYSTEM` socket
    /// whose control id matches `com.apple.net.utun_control`. Matching on the
    /// interface name alone is not sufficient: option 2 is defined per control,
    /// so another `AF_SYSTEM` socket type can answer it with unrelated bytes.
    ///
    /// The control id is resolved through the candidate socket itself because
    /// the extension sandbox does not permit opening a fresh `AF_SYSTEM` socket.
    public static func discoverUtunFileDescriptor(maximum: Int32 = 1024) -> Int32? {
        var controlInfo = utunControlInfo()

        for fileDescriptor in 0 ... maximum {
            guard let address = controlPeerAddress(of: fileDescriptor) else {
                continue
            }
            if controlInfo.ctl_id == 0 {
                guard ioctl(fileDescriptor, controlInfoRequest, &controlInfo) == 0 else {
                    continue
                }
            }
            if address.sc_id == controlInfo.ctl_id {
                return fileDescriptor
            }
        }

        return nil
    }

    /// Reports the interface name behind an already-identified utun descriptor,
    /// for diagnostics. Returns nil when the descriptor is not a utun.
    ///
    /// The control id is confirmed before the name is read, for the same reason
    /// discovery confirms it: an unrelated socket answers option 2 instead of
    /// refusing it. An `AF_UNIX` pair returns four bytes of something else, so
    /// a successful `getsockopt` on its own says nothing about being a utun.
    public static func interfaceName(for fileDescriptor: Int32) -> String? {
        guard isUtunControlSocket(fileDescriptor) else {
            return nil
        }

        var buffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
        var length = socklen_t(buffer.count)
        let result = buffer.withUnsafeMutableBufferPointer { pointer in
            getsockopt(
                fileDescriptor,
                sysprotoControl,
                utunOptionInterfaceName,
                pointer.baseAddress,
                &length
            )
        }
        guard result == 0 else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func isUtunControlSocket(_ fileDescriptor: Int32) -> Bool {
        guard let address = controlPeerAddress(of: fileDescriptor) else {
            return false
        }
        var controlInfo = utunControlInfo()
        guard ioctl(fileDescriptor, controlInfoRequest, &controlInfo) == 0 else {
            return false
        }
        return address.sc_id == controlInfo.ctl_id
    }

    /// Returns the peer address only for a connected `AF_SYSTEM` socket, which
    /// is the precondition for asking it which kernel control it belongs to.
    private static func controlPeerAddress(of fileDescriptor: Int32) -> xray_sockaddr_ctl? {
        var address = xray_sockaddr_ctl()
        var length = socklen_t(MemoryLayout.size(ofValue: address))
        var result: Int32 = -1
        withUnsafeMutablePointer(to: &address) { addressPointer in
            addressPointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
                result = getpeername(fileDescriptor, generic, &length)
            }
        }
        guard result == 0, address.sc_family == AF_SYSTEM else {
            return nil
        }
        return address
    }

    private static func utunControlInfo() -> xray_ctl_info {
        var controlInfo = xray_ctl_info()
        withUnsafeMutablePointer(to: &controlInfo.ctl_name) { namePointer in
            namePointer.withMemoryRebound(
                to: CChar.self,
                capacity: MemoryLayout.size(ofValue: namePointer.pointee)
            ) { characters in
                _ = strcpy(characters, utunControlName)
            }
        }
        return controlInfo
    }
}
