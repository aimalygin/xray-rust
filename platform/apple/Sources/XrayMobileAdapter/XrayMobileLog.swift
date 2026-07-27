import Foundation
import XrayAppleShared

enum XrayMobileLog {
    static func info(_ category: String, _ message: String) {
        NSLog(
            "%@",
            "[XrayRust][\(sanitized(category))] \(sanitized(message))"
        )
    }

    static func error(_ category: String, _ message: String) {
        NSLog(
            "%@",
            "[XrayRust][\(sanitized(category))][error] \(sanitized(message))"
        )
    }

    static func sanitized(_ message: String) -> String {
        XrayLogSanitizer.sanitize(message)
    }
}
