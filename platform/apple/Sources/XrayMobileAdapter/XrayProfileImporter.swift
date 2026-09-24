import Foundation
import XrayAppleShared
import XrayRust

public enum XrayProfileFormat: String, Codable, Sendable {
    case hysteria2
    case wireguard

    var capability: XrayFFICapabilities {
        self == .hysteria2 ? .hysteria2Outbound : .wireguardOutbound
    }
}

public enum XrayProfileImportError: Error, LocalizedError, Equatable {
    case unavailable
    case invalidInput
    case invalidResult

    public var errorDescription: String? {
        switch self {
        case .unavailable: return "This native library does not support the requested profile import."
        case .invalidInput: return "Invalid or oversized profile import input."
        case .invalidResult: return "The native library returned an invalid imported profile."
        }
    }
}

/// The explicit configJSON property contains credentials. Store it securely.
public struct XrayImportedProfile: Decodable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let name: String
    public let serverAddress: String
    public let configJSON: String
    let schemaVersion: Int

    public var description: String { "XrayImportedProfile(<redacted>)" }
    public var debugDescription: String { description }

    public func clientProfile(
        providerBundleIdentifier: String? = nil,
        hostBundleIdentifier: String? = Bundle.main.bundleIdentifier
    ) -> XrayClientProfile {
        XrayClientProfile(
            name: name,
            providerBundleIdentifier: providerBundleIdentifier ?? XrayClientProfile.defaultProviderBundleIdentifier(
                hostBundleIdentifier: hostBundleIdentifier
            ),
            serverAddress: serverAddress,
            configJSON: configJSON
        )
    }
}

public extension XrayFFIInfo {
    func supportsProfileImport(_ format: XrayProfileFormat) -> Bool {
        version.major == 1 && version.minor >= 5 && supports(.profileImport) && supports(format.capability)
    }
}

/// Imports text already read by the host. No file access, network or VPN startup.
public enum XrayProfileImporter {
    public static func profile(
        from text: String,
        format: XrayProfileFormat,
        name: String? = nil,
        dnsServers: [String] = []
    ) throws -> XrayImportedProfile {
        try importProfile(text: text, format: format, name: name, dnsServers: dnsServers,
                          info: XrayCore.ffiInfo, nativeImport: nativeImport)
    }

    // Injectable boundary verifies availability before invoking a new native API.
    static func importProfile(
        text: String, format: XrayProfileFormat, name: String?, dnsServers: [String],
        info: XrayFFIInfo, nativeImport: (Data) throws -> Data
    ) throws -> XrayImportedProfile {
        guard info.supportsProfileImport(format) else { throw XrayProfileImportError.unavailable }
        guard text.utf8.count <= 64 * 1024, dnsServers.count <= 8,
              name.map({ $0.utf8.count <= 128 }) ?? true,
              dnsServers.allSatisfy({ $0.utf8.count <= 253 }) else {
            throw XrayProfileImportError.invalidInput
        }
        var request: [String: Any] = ["format": format.rawValue, "text": text, "dnsServers": dnsServers]
        if let name { request["name"] = name }
        var data = try JSONSerialization.data(withJSONObject: request)
        defer { data.resetBytes(in: 0..<data.count) }
        guard data.count <= 256 * 1024 else { throw XrayProfileImportError.invalidInput }
        var response = try nativeImport(data)
        defer { response.resetBytes(in: 0..<response.count) }
        guard response.count <= 256 * 1024,
              let profile = try? JSONDecoder().decode(XrayImportedProfile.self, from: response),
              profile.schemaVersion == 1 else { throw XrayProfileImportError.invalidResult }
        return profile
    }

    private static func nativeImport(_ data: Data) throws -> Data {
        try data.withUnsafeBytes { raw in
            let input = raw.bindMemory(to: UInt8.self)
            var error: OpaquePointer?
            var written = 0
            func check(_ status: XrayStatus) throws {
                defer { xray_error_free(error); error = nil }
                guard status == XRAY_STATUS_OK else {
                    let message = error.flatMap { xray_error_message($0) }.map { String(cString: $0) }
                        ?? "Profile import failed."
                    throw XrayCoreError.status(code: status, message: message)
                }
            }
            try check(xray_profile_import_json(input.baseAddress, input.count, nil, 0, &written, &error))
            guard written > 0, written <= 256 * 1024 else { throw XrayProfileImportError.invalidResult }
            var buffer = Data(count: written + 1)
            defer { buffer.resetBytes(in: 0..<buffer.count) }
            let status = buffer.withUnsafeMutableBytes { output in
                xray_profile_import_json(input.baseAddress, input.count,
                    output.bindMemory(to: CChar.self).baseAddress, output.count, &written, &error)
            }
            try check(status)
            guard written < buffer.count else { throw XrayProfileImportError.invalidResult }
            return buffer.prefix(written)
        }
    }
}
