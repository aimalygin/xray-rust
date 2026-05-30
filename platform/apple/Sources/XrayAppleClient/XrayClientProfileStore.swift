import Foundation
import XrayAppleShared

public final class XrayClientProfileStore {
    private let defaults: UserDefaults
    private let key: String

    public init(
        defaults: UserDefaults = .standard,
        key: String = "org.xrayrust.apple.client.profile"
    ) {
        self.defaults = defaults
        self.key = key
    }

    public func load() -> XrayClientProfile {
        guard let data = defaults.data(forKey: key),
              let profile = try? JSONDecoder().decode(XrayClientProfile.self, from: data)
        else {
            return XrayClientProfile.defaultProfile()
        }
        return profile
    }

    public func save(_ profile: XrayClientProfile) throws {
        let data = try JSONEncoder().encode(profile)
        defaults.set(data, forKey: key)
    }
}
