#if canImport(NetworkExtension)
import Darwin
import Foundation
import NetworkExtension

@available(iOS 9.0, tvOS 17.0, macOS 10.11, *)
public final class XrayPacketTunnelPump: @unchecked Sendable {
    private let provider: NEPacketTunnelProvider
    private let core: XrayCore
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var running = false

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

        readPackets()
        pollPackets()
    }

    public func stop() {
        lock.lock()
        running = false
        lock.unlock()
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
                try? self.core.pushPacket(packet)
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
                        guard let packet = try? self.core.pollPacket() else {
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
        }
    }

    private var isRunning: Bool {
        lock.lock()
        defer { lock.unlock() }
        return running
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
