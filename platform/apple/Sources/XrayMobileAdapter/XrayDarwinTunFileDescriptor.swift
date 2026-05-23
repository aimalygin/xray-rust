import Darwin
import Foundation

public enum XrayDarwinTunFileDescriptor {
    private static let sysprotoControl: Int32 = 2
    private static let utunOptionInterfaceName: Int32 = 2

    public static func discoverUtunFileDescriptor(maximum: Int32 = 1024) -> Int32? {
        let prefix = Array("utun".utf8CString.dropLast())

        for fd in 0 ... maximum {
            var buffer = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            var length = socklen_t(buffer.count)
            let result = buffer.withUnsafeMutableBufferPointer { pointer in
                getsockopt(
                    fd,
                    sysprotoControl,
                    utunOptionInterfaceName,
                    pointer.baseAddress,
                    &length
                )
            }
            guard result == 0 else {
                continue
            }
            guard buffer.starts(with: prefix) else {
                continue
            }
            return fd
        }

        return nil
    }
}
