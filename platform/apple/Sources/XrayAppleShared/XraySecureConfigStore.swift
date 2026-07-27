import Foundation

#if canImport(Security)
import Security
#endif

public protocol XraySecureConfigStoring: AnyObject, Sendable {
    func store(configJSON: String, reference: String) throws
    func configJSON(reference: String) throws -> String?
    func remove(reference: String) throws
}

public enum XraySecureConfigReference {
    public static func profile(_ id: UUID) -> String {
        "profile.\(id.uuidString.lowercased())"
    }

    public static func tunnel(_ id: UUID) -> String {
        "tunnel.\(id.uuidString.lowercased())"
    }
}

public enum XraySecureConfigStoreError: Error, LocalizedError {
    case unavailable
    case invalidUTF8
    case keychain(status: Int32)

    public var errorDescription: String? {
        switch self {
        case .unavailable:
            return "Secure configuration storage is unavailable on this platform."
        case .invalidUTF8:
            return "Secure configuration storage returned invalid UTF-8."
        case let .keychain(status):
            return "Secure configuration storage failed with status \(status)."
        }
    }
}

public final class XrayKeychainConfigStore: XraySecureConfigStoring, @unchecked Sendable {
    private let service: String
    private let lock = NSLock()

    public init(service: String = "org.xrayrust.apple.secure-config") {
        self.service = service
    }

    public func store(configJSON: String, reference: String) throws {
#if canImport(Security)
        let data = Data(configJSON.utf8)
        lock.lock()
        defer { lock.unlock() }

        let lookup = baseQuery(reference: reference)
        let attributes: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(
            lookup as CFDictionary,
            attributes as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw XraySecureConfigStoreError.keychain(status: updateStatus)
        }

        var insert = lookup
        attributes.forEach { insert[$0.key] = $0.value }
        let insertStatus = SecItemAdd(insert as CFDictionary, nil)
        guard insertStatus == errSecSuccess else {
            throw XraySecureConfigStoreError.keychain(status: insertStatus)
        }
#else
        throw XraySecureConfigStoreError.unavailable
#endif
    }

    public func configJSON(reference: String) throws -> String? {
#if canImport(Security)
        lock.lock()
        defer { lock.unlock() }

        var query = baseQuery(reference: reference)
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = item as? Data else {
            throw XraySecureConfigStoreError.keychain(status: status)
        }
        guard let configJSON = String(data: data, encoding: .utf8) else {
            throw XraySecureConfigStoreError.invalidUTF8
        }
        return configJSON
#else
        throw XraySecureConfigStoreError.unavailable
#endif
    }

    public func remove(reference: String) throws {
#if canImport(Security)
        lock.lock()
        defer { lock.unlock() }

        let status = SecItemDelete(baseQuery(reference: reference) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw XraySecureConfigStoreError.keychain(status: status)
        }
#else
        throw XraySecureConfigStoreError.unavailable
#endif
    }

#if canImport(Security)
    private func baseQuery(reference: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: reference,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
    }
#endif
}
