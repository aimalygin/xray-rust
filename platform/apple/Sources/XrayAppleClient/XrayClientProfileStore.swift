import Foundation
import XrayAppleShared

public final class XrayClientProfileStore {
    private let defaults: UserDefaults
    private let key: String
    private let secureConfigStore: XraySecureConfigStoring

    public init(
        defaults: UserDefaults = .standard,
        key: String = "org.xrayrust.apple.client.profile",
        secureConfigStore: XraySecureConfigStoring = XrayKeychainConfigStore()
    ) {
        self.defaults = defaults
        self.key = key
        self.secureConfigStore = secureConfigStore
    }

    public func load() -> XrayClientProfile {
        guard let data = defaults.data(forKey: key) else {
            return XrayClientProfile.defaultProfile()
        }

        if let envelope = try? JSONDecoder().decode(PersistedProfileEnvelope.self, from: data) {
            do {
                guard let configJSON = try secureConfigStore.configJSON(
                    reference: envelope.configReference
                ) else {
                    XrayAppleLog.error(
                        "ProfileStore",
                        "Saved profile is missing its secure configuration"
                    )
                    return XrayClientProfile.defaultProfile()
                }
                var profile = envelope.profile
                profile.configJSON = configJSON
                return profile
            } catch {
                XrayAppleLog.error(
                    "ProfileStore",
                    "Failed to load secure profile configuration: \(error.localizedDescription)"
                )
                return XrayClientProfile.defaultProfile()
            }
        }

        // One-time migration from the legacy format, which embedded the complete
        // configuration (including the VLESS credential) in UserDefaults.
        guard let legacyProfile = try? JSONDecoder().decode(XrayClientProfile.self, from: data) else {
            return XrayClientProfile.defaultProfile()
        }
        do {
            try save(legacyProfile)
        } catch {
            XrayAppleLog.error(
                "ProfileStore",
                "Failed to migrate the legacy profile into secure storage: \(error.localizedDescription)"
            )
            // Do not leave the credential-bearing legacy blob in preferences
            // even when Keychain migration fails. The in-memory profile remains
            // usable for this process and can be saved again after recovery.
            defaults.removeObject(forKey: key)
        }
        return legacyProfile
    }

    public func save(_ profile: XrayClientProfile) throws {
        let reference = XraySecureConfigReference.profile(profile.id)
        var metadata = profile
        metadata.configJSON = ""
        let envelope = PersistedProfileEnvelope(
            configReference: reference,
            profile: metadata
        )
        let data = try JSONEncoder().encode(envelope)
        let previousReference = defaults
            .data(forKey: key)
            .flatMap { try? JSONDecoder().decode(PersistedProfileEnvelope.self, from: $0) }
            .map(\.configReference)

        try secureConfigStore.store(configJSON: profile.configJSON, reference: reference)
        defaults.set(data, forKey: key)
        if let previousReference, previousReference != reference {
            do {
                try secureConfigStore.remove(reference: previousReference)
            } catch {
                // The new profile and secure configuration are already committed.
                // Cleanup is intentionally best effort so callers never see a
                // failed save after the visible state has changed.
                XrayAppleLog.error(
                    "ProfileStore",
                    "Failed to remove obsolete secure profile configuration: \(error.localizedDescription)"
                )
            }
        }
    }
}

private struct PersistedProfileEnvelope: Codable {
    let version: Int
    let configReference: String
    let profile: XrayClientProfile

    init(configReference: String, profile: XrayClientProfile) {
        version = 1
        self.configReference = configReference
        self.profile = profile
    }
}
