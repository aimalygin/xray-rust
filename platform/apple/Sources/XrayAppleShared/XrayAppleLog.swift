import Foundation

public enum XrayAppleLog {
    private static let lock = NSLock()
    private static var fileURL: URL?

    public static func configureFileLogging(directory: URL?) {
        lock.lock()
        defer { lock.unlock() }

        guard let directory else {
            fileURL = nil
            return
        }

        do {
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
            let nextURL = directory.appendingPathComponent("xray-apple.log")
            if !FileManager.default.fileExists(atPath: nextURL.path) {
                FileManager.default.createFile(atPath: nextURL.path, contents: nil)
            }
            fileURL = nextURL
        } catch {
            fileURL = nil
            NSLog("[XrayRust][Log][error] Failed to configure file logging: \(error)")
        }
    }

    public static func info(_ category: String, _ message: @autoclosure () -> String) {
        write(category: category, level: nil, message: message())
    }

    public static func error(_ category: String, _ message: @autoclosure () -> String) {
        write(category: category, level: "error", message: message())
    }

    private static func write(category: String, level: String?, message: String) {
        let rendered: String
        if let level {
            rendered = "[XrayRust][\(category)][\(level)] \(message)"
        } else {
            rendered = "[XrayRust][\(category)] \(message)"
        }
        NSLog("%@", rendered)
        appendToFile(rendered)
    }

    private static func appendToFile(_ line: String) {
        lock.lock()
        let url = fileURL
        lock.unlock()

        guard let url,
              let data = "\(Date()) \(line)\n".data(using: .utf8)
        else {
            return
        }

        lock.lock()
        defer { lock.unlock() }
        guard let handle = try? FileHandle(forWritingTo: url) else {
            return
        }
        defer {
            try? handle.close()
        }
        try? handle.seekToEnd()
        try? handle.write(contentsOf: data)
    }
}
