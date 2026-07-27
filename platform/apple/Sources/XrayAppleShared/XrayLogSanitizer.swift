import Foundation

public enum XrayLogSanitizer {
    public static func sanitize(_ message: String) -> String {
        let redacted = [
            (#"(?i)\b(?:https?|vless)://[^\s"'<>]+"#, "<redacted-url>"),
            (#"(?<![A-Za-z0-9_])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?"#, "<redacted-endpoint>"),
            (#"\[[0-9A-Fa-f:]+\](?::\d{1,5})?"#, "<redacted-endpoint>"),
            (#"(?i)(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d{1,5})?"#, "<redacted-endpoint>"),
        ].reduce(message) { partial, rule in
            partial.replacingOccurrences(
                of: rule.0,
                with: rule.1,
                options: .regularExpression
            )
        }
        return singleLine(redacted)
    }

    public static func singleLine(_ value: String) -> String {
        var result = ""
        result.reserveCapacity(value.utf8.count)
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x0A:
                result.append(#"\n"#)
            case 0x0D:
                result.append(#"\r"#)
            case 0x09:
                result.append(#"\t"#)
            case 0x00...0x1F, 0x7F...0x9F, 0x2028, 0x2029:
                result.append(
                    String(format: #"\u{%04X}"#, scalar.value)
                )
            default:
                result.unicodeScalars.append(scalar)
            }
        }
        return result
    }
}
