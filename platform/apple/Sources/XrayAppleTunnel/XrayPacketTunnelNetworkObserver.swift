#if canImport(NetworkExtension)
import Darwin
import Foundation
import Network

/// One coalesced callback after a burst of path changes. stop() also fences
/// already-enqueued callbacks so a superseded runtime cannot be rebound.
final class XrayPacketTunnelRebindScheduler: @unchecked Sendable {
    private let lock = NSRecursiveLock()
    private let queue: DispatchQueue
    private let delay: DispatchTimeInterval
    private let action: @Sendable () -> Void
    private var pending: DispatchWorkItem?
    private var generation: UInt64 = 0
    private var stopped = false

    init(queue: DispatchQueue, delay: DispatchTimeInterval = .milliseconds(500),
         action: @escaping @Sendable () -> Void) {
        self.queue = queue
        self.delay = delay
        self.action = action
    }

    func schedule() {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { return }
        generation &+= 1
        let expected = generation
        pending?.cancel()
        let work = DispatchWorkItem { [weak self] in
            guard let self else { return }
            lock.lock()
            defer { lock.unlock() }
            guard !stopped, generation == expected else { return }
            pending = nil
            action()
        }
        pending = work
        queue.asyncAfter(deadline: .now() + delay, execute: work)
    }

    func cancelPending() {
        lock.lock()
        defer { lock.unlock() }
        generation &+= 1
        pending?.cancel()
        pending = nil
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        stopped = true
        pending?.cancel()
        pending = nil
    }
}

/// Ignore changes to DNS, VPN routes and secondary interfaces. Rebinding a live
/// QUIC socket for those events can lose an in-flight, unreliable UDP reply.
/// Include assigned addresses so DHCP/address changes on the same NIC still act.
struct XrayPacketTunnelCarrierSignature: Equatable {
    let interfaceName: String
    let interfaceIndex: Int
    let addresses: [String]

    init(interfaceName: String, interfaceIndex: Int, addresses: [String]) {
        self.interfaceName = interfaceName
        self.interfaceIndex = interfaceIndex
        self.addresses = Array(Set(addresses)).sorted()
    }

    static func capture(_ path: NWPath) -> Self? {
        // availableInterfaces is in preference order. Ignore the tunnel's own
        // utun/loopback interfaces, which do not carry its protected sockets.
        guard let interface = path.availableInterfaces.first(where: {
            $0.type == .wifi || $0.type == .cellular || $0.type == .wiredEthernet
        }) else { return nil }
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return nil }
        defer { freeifaddrs(head) }
        var addresses: [String] = []
        var current = head
        while let item = current {
            defer { current = item.pointee.ifa_next }
            guard String(cString: item.pointee.ifa_name) == interface.name,
                  let address = item.pointee.ifa_addr,
                  address.pointee.sa_family == AF_INET || address.pointee.sa_family == AF_INET6
            else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(address, socklen_t(address.pointee.sa_len), &host,
                           socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                addresses.append(String(cString: host))
            }
        }
        return Self(interfaceName: interface.name, interfaceIndex: interface.index, addresses: addresses)
    }
}

struct XrayPacketTunnelCarrierTracker {
    private var previous: XrayPacketTunnelCarrierSignature?

    mutating func update(_ signature: XrayPacketTunnelCarrierSignature?) -> Bool {
        guard let signature else {
            previous = nil
            return false
        }
        guard signature != previous else { return false }
        previous = signature
        return true
    }
}

final class XrayPacketTunnelNetworkObserver: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let scheduler: XrayPacketTunnelRebindScheduler
    // Confined to the monitor's serial queue; stop() does not access these.
    private var tracker = XrayPacketTunnelCarrierTracker()
    private var previousFallback: NWPath?
#if DEBUG
    private let diagnosticLock = NSLock()
    private var events: [[String: String]] = []

    var diagnosticEvents: [[String: String]] {
        diagnosticLock.lock()
        defer { diagnosticLock.unlock() }
        return events
    }
    func recordApplied() { record("applied") }

    private func record(_ kind: String, interface: String = "") {
        diagnosticLock.lock()
        defer { diagnosticLock.unlock() }
        events.append(["kind": kind, "interface": interface,
                       "uptime": String(ProcessInfo.processInfo.systemUptime)])
        if events.count > 64 { events.removeFirst(events.count - 64) }
    }
#endif

    init(action: @escaping @Sendable () -> Void) {
        let queue = DispatchQueue(label: "org.xrayrust.apple.packet-tunnel.network")
        scheduler = XrayPacketTunnelRebindScheduler(queue: queue, action: action)
        monitor.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            guard path.status == .satisfied else {
                _ = tracker.update(nil)
                previousFallback = nil
                scheduler.cancelPending()
#if DEBUG
                record("offline")
#endif
                return
            }
            let signature = XrayPacketTunnelCarrierSignature.capture(path)
            let changed: Bool
            if let signature {
                previousFallback = nil
                changed = tracker.update(signature)
            } else {
                // Unknown/other interface or address enumeration failure:
                // retain raw-path behavior instead of missing a real outage.
                _ = tracker.update(nil)
                changed = path != previousFallback
                previousFallback = path
            }
#if DEBUG
            record(changed ? "scheduled" : "unchanged", interface: signature?.interfaceName ?? "fallback")
#endif
            if changed { scheduler.schedule() }
        }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
        scheduler.stop()
    }

    deinit { stop() }
}
#endif
