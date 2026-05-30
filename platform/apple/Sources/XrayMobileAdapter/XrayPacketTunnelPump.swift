#if canImport(NetworkExtension)
import Darwin
import Foundation
import NetworkExtension

private enum XrayMobileLog {
    static func info(_ category: String, _ message: String) {
        NSLog("[XrayRust][\(category)] \(message)")
    }

    static func error(_ category: String, _ message: String) {
        NSLog("[XrayRust][\(category)][error] \(message)")
    }
}

@available(iOS 9.0, tvOS 17.0, macOS 10.11, *)
public final class XrayPacketTunnelPump: @unchecked Sendable {
    private let provider: NEPacketTunnelProvider
    private let core: XrayCore
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var running = false
    private var pushPacketErrorCount = 0
    private var pollPacketErrorCount = 0

    public init(
        provider: NEPacketTunnelProvider,
        core: XrayCore,
        queue: DispatchQueue = DispatchQueue(label: "org.xrayrust.packet-tunnel-pump")
    ) {
        self.provider = provider
        self.core = core
        self.queue = queue
    }

    public func start() {
        lock.lock()
        guard !running else {
            lock.unlock()
            return
        }
        running = true
        lock.unlock()

        XrayMobileLog.info("PacketPump", "Starting packet pump")
        readPackets()
        pollPackets()
    }

    public func stop() {
        lock.lock()
        running = false
        lock.unlock()
        XrayMobileLog.info("PacketPump", "Stopping packet pump")
    }

    private func readPackets() {
        guard isRunning else {
            return
        }

        provider.packetFlow.readPackets { [weak self] packets, _ in
            guard let self else {
                return
            }
            for packet in packets {
                do {
                    try self.core.pushPacket(packet)
                } catch {
                    let count = self.incrementPushPacketErrorCount()
                    if Self.shouldLogPacketError(count) {
                        XrayMobileLog.error(
                            "PacketPump",
                            "pushPacket failed count=\(count) bytes=\(packet.count) error=\(error)"
                        )
                    }
                }
            }
            self.readPackets()
        }
    }

    private func pollPackets() {
        queue.async { [weak self] in
            guard let self else {
                return
            }

            while self.isRunning {
                autoreleasepool {
                    while self.isRunning {
                        let packet: Data?
                        do {
                            packet = try self.core.pollPacket()
                        } catch {
                            let count = self.incrementPollPacketErrorCount()
                            if Self.shouldLogPacketError(count) {
                                XrayMobileLog.error(
                                    "PacketPump",
                                    "pollPacket failed count=\(count) error=\(error)"
                                )
                            }
                            break
                        }
                        guard let packet else {
                            break
                        }
                        let protocolFamily = NSNumber(value: Self.protocolFamily(for: packet))
                        _ = self.provider.packetFlow.writePackets(
                            [packet],
                            withProtocols: [protocolFamily]
                        )
                    }
                }
                Thread.sleep(forTimeInterval: 0.005)
            }
            XrayMobileLog.info("PacketPump", "Packet pump poll loop exited")
        }
    }

    private var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
    }

    private func incrementPushPacketErrorCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        pushPacketErrorCount += 1
        return pushPacketErrorCount
    }

    private func incrementPollPacketErrorCount() -> Int {
        lock.lock()
        defer { lock.unlock() }
        pollPacketErrorCount += 1
        return pollPacketErrorCount
    }

    private static func shouldLogPacketError(_ count: Int) -> Bool {
        count <= 5 || count.isMultiple(of: 100)
    }

    private static func protocolFamily(for packet: Data) -> Int32 {
        guard let first = packet.first else {
            return AF_INET
        }

        switch first >> 4 {
        case 6:
            return AF_INET6
        default:
            return AF_INET
        }
    }
}
#endif
