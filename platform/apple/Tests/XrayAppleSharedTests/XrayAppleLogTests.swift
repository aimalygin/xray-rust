import Darwin
import XCTest
@testable import XrayAppleShared

final class XrayAppleLogTests: XCTestCase {
    override func tearDown() {
        XrayAppleLog.configureFileLogging(directory: nil)
        super.tearDown()
    }

    func testRedactionRemovesURLQueriesAndEndpoints() {
        let message = XrayAppleLog.redacted(
            "probe=https://example.com/check?token=secret#fragment server=203.0.113.10:443"
        )

        XCTAssertFalse(message.contains("secret"))
        XCTAssertFalse(message.contains("example.com"))
        XCTAssertFalse(message.contains("203.0.113.10"))
        XCTAssertEqual(
            message,
            "probe=<redacted-url> server=<redacted-endpoint>"
        )
    }

    func testRedactionEscapesNewlinesAndControlCharacters() {
        let message = XrayAppleLog.redacted(
            "first\nsecond\rthird\t\u{0000}\u{001B}\u{0085}\u{2028}\u{2029}"
        )

        XCTAssertEqual(
            message,
            #"first\nsecond\rthird\t\u{0000}\u{001B}\u{0085}\u{2028}\u{2029}"#
        )
        XCTAssertFalse(message.contains("\n"))
        XCTAssertFalse(message.contains("\r"))
        XCTAssertFalse(message.contains("\u{001B}"))
    }

    func testFileLoggerKeepsOneSecureDescriptorAndWritesSingleLineRecords() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }

        XrayAppleLog.configureFileLogging(directory: directory)
        let descriptor = try XCTUnwrap(XrayAppleLog.activeFileDescriptor)

        XrayAppleLog.info("Test", "first")
        XrayAppleLog.error("Test", "second\n[forged]\u{001B}")

        XCTAssertEqual(XrayAppleLog.activeFileDescriptor, descriptor)
        XrayAppleLog.configureFileLogging(directory: nil)
        let logURL = directory.appendingPathComponent("xray-apple.log")
        let contents = try String(contentsOf: logURL, encoding: .utf8)
        let records = contents.split(separator: "\n", omittingEmptySubsequences: true)
        XCTAssertEqual(records.count, 2)
        XCTAssertTrue(contents.contains(#"second\n[forged]\u{001B}"#))

        let attributes = try FileManager.default.attributesOfItem(
            atPath: logURL.path
        )
        let permissions = try XCTUnwrap(
            attributes[.posixPermissions] as? NSNumber
        )
        XCTAssertEqual(permissions.intValue & 0o777, 0o600)
    }

    func testFileLoggerRejectsFinalSymlink() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let victimURL = directory.appendingPathComponent("victim.log")
        try Data("unchanged".utf8).write(to: victimURL)
        try FileManager.default.createSymbolicLink(
            at: directory.appendingPathComponent("xray-apple.log"),
            withDestinationURL: victimURL
        )

        XrayAppleLog.configureFileLogging(directory: directory)
        XrayAppleLog.info("Test", "must not reach victim")

        XCTAssertNil(XrayAppleLog.activeFileDescriptor)
        XCTAssertEqual(
            try String(contentsOf: victimURL, encoding: .utf8),
            "unchanged"
        )
    }

    func testFileLoggerRejectsIntermediateSymlink() throws {
        let baseDirectory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: baseDirectory) }
        let targetDirectory = baseDirectory.appendingPathComponent("target")
        try FileManager.default.createDirectory(
            at: targetDirectory,
            withIntermediateDirectories: false
        )
        let linkURL = baseDirectory.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(
            at: linkURL,
            withDestinationURL: targetDirectory
        )

        XrayAppleLog.configureFileLogging(
            directory: linkURL.appendingPathComponent("logs")
        )
        XrayAppleLog.info("Test", "must not follow directory link")

        XCTAssertNil(XrayAppleLog.activeFileDescriptor)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: targetDirectory
                    .appendingPathComponent("logs/xray-apple.log")
                    .path
            )
        )
    }

    func testFileLoggerRejectsFIFONonblocking() throws {
        let directory = try makeTemporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fifoURL = directory.appendingPathComponent("xray-apple.log")
        let result = fifoURL.path.withCString {
            mkfifo($0, 0o600)
        }
        XCTAssertEqual(result, 0)

        let startedAt = Date()
        XrayAppleLog.configureFileLogging(directory: directory)
        let elapsed = Date().timeIntervalSince(startedAt)

        XCTAssertNil(XrayAppleLog.activeFileDescriptor)
        XCTAssertLessThan(elapsed, 0.5)
    }

    private func makeTemporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .resolvingSymlinksInPath()
            .appendingPathComponent(
                "xray-apple-log-tests-\(UUID().uuidString)",
                isDirectory: true
            )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
        return directory
    }
}
