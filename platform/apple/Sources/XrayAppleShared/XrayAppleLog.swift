import Darwin
import Foundation

private enum XrayAppleLogFileError: Error {
    case invalidDirectory
    case systemCall(operation: String, code: Int32)
    case unsafeLogFile
}

private final class XrayAppleLogState: @unchecked Sendable {
    let lock = NSLock()
    var fileDescriptor: Int32 = -1
}

public enum XrayAppleLog {
    private static let state = XrayAppleLogState()

    public static func configureFileLogging(directory: URL?) {
        state.lock.lock()
        closeFileLocked()

        guard let directory else {
            state.lock.unlock()
            return
        }

        do {
            state.fileDescriptor = try openLogFile(in: directory)
            state.lock.unlock()
        } catch {
            state.lock.unlock()
            NSLog(
                "%@",
                "[XrayRust][Log][error] Failed to configure secure file logging"
            )
        }
    }

    public static func info(_ category: String, _ message: @autoclosure () -> String) {
        write(category: category, level: nil, message: message())
    }

    public static func error(_ category: String, _ message: @autoclosure () -> String) {
        write(category: category, level: "error", message: message())
    }

    private static func write(category: String, level: String?, message: String) {
        let category = XrayLogSanitizer.singleLine(category)
        let message = redacted(message)
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
        guard let data = "\(Date()) \(line)\n".data(using: .utf8) else {
            return
        }

        state.lock.lock()
        defer { state.lock.unlock() }
        guard state.fileDescriptor >= 0 else {
            return
        }

        let didWrite = data.withUnsafeBytes { rawBuffer -> Bool in
            guard var pointer = rawBuffer.baseAddress else {
                return true
            }
            var remaining = rawBuffer.count
            while remaining > 0 {
                let written = Darwin.write(
                    state.fileDescriptor,
                    pointer,
                    remaining
                )
                if written > 0 {
                    remaining -= written
                    pointer = pointer.advanced(by: written)
                    continue
                }
                if written < 0, errno == EINTR {
                    continue
                }
                return false
            }
            return true
        }
        if !didWrite {
            closeFileLocked()
        }
    }

    static func redacted(_ message: String) -> String {
        XrayLogSanitizer.sanitize(message)
    }

    static var activeFileDescriptor: Int32? {
        state.lock.lock()
        defer { state.lock.unlock() }
        return state.fileDescriptor >= 0 ? state.fileDescriptor : nil
    }

    private static func openLogFile(in directory: URL) throws -> Int32 {
        guard directory.isFileURL else {
            throw XrayAppleLogFileError.invalidDirectory
        }
        let path = normalizedTrustedRootAliasPath(directory.path)
        guard path.hasPrefix("/") else {
            throw XrayAppleLogFileError.invalidDirectory
        }
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
        guard !components.contains(where: { $0 == "." || $0 == ".." }) else {
            throw XrayAppleLogFileError.invalidDirectory
        }

        let directoryFlags = O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
        var currentDescriptor = Darwin.open("/", directoryFlags)
        guard currentDescriptor >= 0 else {
            throw XrayAppleLogFileError.systemCall(
                operation: "open root",
                code: errno
            )
        }

        do {
            for componentSubstring in components {
                let component = String(componentSubstring)
                var nextDescriptor = component.withCString {
                    openat(currentDescriptor, $0, directoryFlags)
                }
                if nextDescriptor < 0, errno == ENOENT {
                    let createResult = component.withCString {
                        mkdirat(currentDescriptor, $0, 0o700)
                    }
                    if createResult < 0, errno != EEXIST {
                        throw XrayAppleLogFileError.systemCall(
                            operation: "mkdirat",
                            code: errno
                        )
                    }
                    nextDescriptor = component.withCString {
                        openat(currentDescriptor, $0, directoryFlags)
                    }
                }
                guard nextDescriptor >= 0 else {
                    throw XrayAppleLogFileError.systemCall(
                        operation: "openat directory",
                        code: errno
                    )
                }
                Darwin.close(currentDescriptor)
                currentDescriptor = nextDescriptor
            }

            let fileFlags =
                O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
            let logDescriptor = "xray-apple.log".withCString {
                openat(currentDescriptor, $0, fileFlags, 0o600)
            }
            guard logDescriptor >= 0 else {
                throw XrayAppleLogFileError.systemCall(
                    operation: "openat log",
                    code: errno
                )
            }

            var shouldCloseLog = true
            defer {
                if shouldCloseLog {
                    Darwin.close(logDescriptor)
                }
            }
            var status = stat()
            guard fstat(logDescriptor, &status) == 0 else {
                throw XrayAppleLogFileError.systemCall(
                    operation: "fstat",
                    code: errno
                )
            }
            guard status.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
                  status.st_uid == geteuid(),
                  status.st_nlink == 1
            else {
                throw XrayAppleLogFileError.unsafeLogFile
            }
            guard fchmod(logDescriptor, 0o600) == 0 else {
                throw XrayAppleLogFileError.systemCall(
                    operation: "fchmod",
                    code: errno
                )
            }

            shouldCloseLog = false
            Darwin.close(currentDescriptor)
            return logDescriptor
        } catch {
            Darwin.close(currentDescriptor)
            throw error
        }
    }

    private static func closeFileLocked() {
        if state.fileDescriptor >= 0 {
            Darwin.close(state.fileDescriptor)
            state.fileDescriptor = -1
        }
    }

    private static func normalizedTrustedRootAliasPath(_ path: String) -> String {
        for (alias, destination) in [
            ("/var", "/private/var"),
            ("/tmp", "/private/tmp"),
            ("/etc", "/private/etc"),
        ] {
            if path == alias {
                return destination
            }
            if path.hasPrefix("\(alias)/") {
                return destination + path.dropFirst(alias.count)
            }
        }
        return path
    }
}
