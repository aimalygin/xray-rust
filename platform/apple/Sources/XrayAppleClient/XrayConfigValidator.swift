import Foundation
import XrayMobileAdapter

public enum XrayConfigValidationError: Error, LocalizedError {
    case rootIsNotObject

    public var errorDescription: String? {
        switch self {
        case .rootIsNotObject:
            return "Config must be a JSON object."
        }
    }
}

public enum XrayConfigValidator {
    public static func validate(
        _ configJSON: String,
        geodataSearchDirectory: URL? = Bundle.main.resourceURL
    ) throws {
        let data = Data(configJSON.utf8)
        let json = try JSONSerialization.jsonObject(with: data)
        guard json is [String: Any] else {
            throw XrayConfigValidationError.rootIsNotObject
        }

        _ = try XrayCore(
            configJSON: configJSON,
            geodataSearchDirectory: geodataSearchDirectory
        )
    }
}
