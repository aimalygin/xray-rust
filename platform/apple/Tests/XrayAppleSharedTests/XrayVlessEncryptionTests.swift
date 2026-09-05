import XCTest
@testable import XrayAppleShared

final class XrayVlessEncryptionTests: XCTestCase {
    func testSessionChainAndPaddingBounds() {
        let key = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        for value in [
            "mlkem768x25519plus.native.0rtt.\(key)",
            "mlkem768x25519plus.random.1rtt.100-35-64.100-0-1000.50-128-512.\(key).\(key)",
        ] {
            XCTAssertTrue(XrayVlessEncryption.isSupported(value), value)
        }
        for value in [
            "mlkem768x25519plus.native.1rtt.99-35-35.\(key)",
            "mlkem768x25519plus.native.1rtt.100-34-35.\(key)",
            "mlkem768x25519plus.native.1rtt.100-35-35.100-0-1001.\(key)",
            "mlkem768x25519plus.native.1rtt.100-35-65554.\(key)",
            "mlkem768x25519plus.native.1rtt." + Array(repeating: key, count: 9).joined(separator: "."),
            "mlkem768x25519plus.native.1rtt." + Array(repeating: "100-35-35", count: 33).joined(separator: ".") + ".\(key)",
        ] {
            XCTAssertFalse(XrayVlessEncryption.isSupported(value), value)
        }
    }

    func testSharedKeyAndProfileFixtures() throws {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 { root.deleteLastPathComponent() }
        let data = try Data(contentsOf: root.appendingPathComponent("tests/fixtures/vless-encryption/imports.json"))
        let fixture = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        for test in try XCTUnwrap(fixture["keys"] as? [[String: Any]]) {
            let value = try XCTUnwrap(test["encryption"] as? String)
            XCTAssertEqual(XrayVlessEncryption.isSupported(value), test["accepted"] as? Bool, "\(test["name"]!)")
        }
        for test in try XCTUnwrap(fixture["profiles"] as? [[String: Any]]) {
            let url = try XCTUnwrap(test["url"] as? String)
            if let parameter = test["errorParameter"] as? String {
                XCTAssertThrowsError(try XrayVlessURLImporter.profile(from: url), "\(test["name"]!)") { error in
                    switch error as? XrayVlessURLImportError {
                    case let .unsupportedQueryValue(name, value, _):
                        XCTAssertEqual(name, parameter)
                        if parameter == "encryption" { XCTAssertEqual(value, "<redacted>") }
                    case let .unsupportedQueryParameter(name): XCTAssertEqual(name, parameter)
                    default: XCTFail("Unexpected error kind for \(test["name"]!)")
                    }
                }
            } else {
                let profile = try XrayVlessURLImporter.profile(from: url)
                let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(profile.configJSON.utf8)) as? [String: Any])
                let actual = try XCTUnwrap((json["outbounds"] as? [[String: Any]])?.first)
                let expected = try XCTUnwrap(test["outbound"] as? [String: Any])
                XCTAssertTrue(NSDictionary(dictionary: actual).isEqual(to: expected), "\(test["name"]!)")
                XCTAssertEqual(profile.name, "encrypted-profile")
            }
        }
    }
}
