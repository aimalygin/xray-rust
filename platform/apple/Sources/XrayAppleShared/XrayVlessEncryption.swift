import Foundation

// Mirrors the Rust parser's resource bounds. X25519 low-order encodings
// (including the RFC 7748 ignored high bit) are checked without implementing
// key agreement. Rust remains the authority when the generated config is used.
enum XrayVlessEncryption {
    static let expected = "none or bounded mlkem768x25519plus.{native|xorpub|random}.{1rtt|0rtt}.[padding.]<1-8 public keys>"
    private static let lowOrder: Set<String> = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    ]

    static func isSupported(_ value: String) -> Bool {
        if value == "none" { return true }
        guard value.utf8.count <= 16_384 else { return false }
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 4, parts[0] == "mlkem768x25519plus",
              ["native", "xorpub", "random"].contains(parts[1]),
              ["1rtt", "0rtt"].contains(parts[2]),
              let keyStart = parts[3...].firstIndex(where: { $0.utf8.count >= 20 })
        else { return false }
        let padding = Array(parts[3..<keyStart])
        let keys = parts[keyStart...]
        guard padding.count <= 32, (1...8).contains(keys.count),
              validPadding(padding), keys.allSatisfy({ validKey(String($0)) })
        else { return false }
        return true
    }

    private static func validPadding(_ parts: [Substring]) -> Bool {
        var totalLength: UInt64 = 0
        var totalGap: UInt64 = 0
        for (index, part) in parts.enumerated() {
            guard part.utf8.count < 20 else { return false }
            let fields = part.split(separator: "-", omittingEmptySubsequences: false)
            guard fields.count == 3,
                  fields.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) }),
                  let probability = UInt32(fields[0]),
                  let first = UInt32(fields[1]),
                  let second = UInt32(fields[2]), probability <= 100
            else { return false }
            let low = min(first, second)
            let high = max(first, second)
            if index == 0 && (probability != 100 || low < 35) { return false }
            if index.isMultiple(of: 2) {
                totalLength += UInt64(high)
                if totalLength > 65_553 { return false }
            } else {
                totalGap += UInt64(high)
                if high > 1_000 || totalGap > 5_000 { return false }
            }
        }
        return true
    }

    private static func validKey(_ encoded: String) -> Bool {
        guard [43, 1579].contains(encoded.utf8.count) else { return false }
        let base64 = encoded.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/") + "="
        guard let data = Data(base64Encoded: base64),
              data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "") == encoded else { return false }
        var bytes = [UInt8](data)
        if bytes.count == 32 {
            bytes[31] &= 0x7f
            return !lowOrder.contains(bytes.map { String(format: "%02x", $0) }.joined())
        }
        guard bytes.count == 1184 else { return false }
        // ML-KEM-768: 768 packed 12-bit coefficients, followed by 32-byte rho.
        for i in stride(from: 0, to: 1152, by: 3) {
            let a = Int(bytes[i]) | (Int(bytes[i + 1] & 15) << 8)
            let b = (Int(bytes[i + 1]) >> 4) | (Int(bytes[i + 2]) << 4)
            if a >= 3329 || b >= 3329 { return false }
        }
        return true
    }
}
