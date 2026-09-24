#if DEBUG && os(iOS)
import Foundation
import Network
import UIKit

/// Records physical interface availability separately from reachability of the
/// excluded carrier destination. The UDP connection sends no payload.
@MainActor
final class XrayDeviceProbeSignals {
    private(set) var carrier = "unavailable"
    private(set) var carrierChangedAt = ProcessInfo.processInfo.systemUptime
    private(set) var carrierRoute = "unavailable"
    private(set) var carrierRouteChangedAt = ProcessInfo.processInfo.systemUptime
    private(set) var lockedAt: TimeInterval?
    private(set) var unlockedAt: TimeInterval?
    private(set) var active = UIApplication.shared.applicationState == .active
    private var connection: NWConnection?
    private var tokens: [NSObjectProtocol] = []
    private var timer: Task<Void, Never>?
    private var generation = 0
    private var lastPathDescription = ""
    private let defaultPathMonitor = NWPathMonitor()
    private let wifiMonitor = NWPathMonitor(requiredInterfaceType: .wifi)
    private let cellularMonitor = NWPathMonitor(requiredInterfaceType: .cellular)
    private var wifiAvailable = false
    private var cellularAvailable = false
    private let emit: ([String: Any]) -> Void

    init(emit: @escaping ([String: Any]) -> Void) { self.emit = emit }

    func start(host: String, port: UInt16) {
        for (monitor, wifi) in [(wifiMonitor, true), (cellularMonitor, false)] {
            monitor.pathUpdateHandler = { [weak self] path in
                let available = path.status == .satisfied
                Task { @MainActor [weak self] in
                    guard let self else { return }
                    if wifi { wifiAvailable = available } else { cellularAvailable = available }
                    let value = wifiAvailable ? "wifi" : (cellularAvailable ? "cellular" : "unavailable")
                    if carrier != value {
                        carrier = value
                        carrierChangedAt = ProcessInfo.processInfo.systemUptime
                        emit(["event": "access-network", "interface": value])
                    }
                }
            }
            monitor.start(queue: DispatchQueue(label: "org.xrayrust.v07-access-network"))
        }
        defaultPathMonitor.pathUpdateHandler = { [weak self] path in
            let interfaces = path.availableInterfaces.map { String(describing: $0.type) }.sorted()
            let status = String(describing: path.status)
            let reason = String(describing: path.unsatisfiedReason)
            let ipv4 = path.supportsIPv4
            let ipv6 = path.supportsIPv6
            Task { @MainActor [weak self] in
                self?.emit(["event": "system-path", "status": status, "unsatisfiedReason": reason,
                            "availableInterfaces": interfaces, "supportsIPv4": ipv4, "supportsIPv6": ipv6])
            }
        }
        defaultPathMonitor.start(queue: DispatchQueue(label: "org.xrayrust.v07-system-path"))
        observe(UIApplication.didEnterBackgroundNotification) { [weak self] in
            self?.active = false
            self?.emit(["event": "app-background"])
        }
        observe(UIApplication.didBecomeActiveNotification) { [weak self] in
            self?.active = true
            self?.emit(["event": "app-active"])
        }
        observe(UIApplication.protectedDataWillBecomeUnavailableNotification) { [weak self] in
            self?.lockedAt = ProcessInfo.processInfo.systemUptime
            self?.unlockedAt = nil
            self?.emit(["event": "protected-data-unavailable"])
        }
        observe(UIApplication.protectedDataDidBecomeAvailableNotification) { [weak self] in
            self?.unlockedAt = ProcessInfo.processInfo.systemUptime
            self?.emit(["event": "protected-data-available"])
        }
        timer = Task { [weak self] in
            while !Task.isCancelled {
                self?.observeCarrier(host: host, port: port)
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    func resetLockObservation() { lockedAt = nil; unlockedAt = nil }

    func stop() {
        timer?.cancel()
        timer = nil
        generation += 1
        defaultPathMonitor.cancel()
        wifiMonitor.cancel()
        cellularMonitor.cancel()
        connection?.cancel()
        connection = nil
        for token in tokens { NotificationCenter.default.removeObserver(token) }
        tokens.removeAll()
    }

    private func observe(_ name: Notification.Name, action: @escaping @MainActor () -> Void) {
        tokens.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { _ in
            Task { @MainActor in action() }
        })
    }

    private func observeCarrier(host: String, port: UInt16) {
        connection?.cancel()
        generation += 1
        let currentGeneration = generation
        let connection = NWConnection(host: .init(host), port: .init(rawValue: port)!, using: .udp)
        connection.pathUpdateHandler = { [weak self] path in
            let value: String
            if path.status != .satisfied { value = "unavailable" }
            else if path.usesInterfaceType(.wifi) { value = "wifi" }
            else if path.usesInterfaceType(.cellular) { value = "cellular" }
            else { value = "other" }
            let reason = String(describing: path.unsatisfiedReason)
            let available = path.availableInterfaces.map { String(describing: $0.type) }.sorted()
            let description = "\(value):\(reason):\(available.joined(separator: ","))"
            Task { @MainActor [weak self] in
                guard let self, generation == currentGeneration else { return }
                if carrierRoute != value {
                    carrierRoute = value
                    carrierRouteChangedAt = ProcessInfo.processInfo.systemUptime
                }
                if lastPathDescription != description {
                    lastPathDescription = description
                    emit(["event": "carrier-path-detail", "interface": value,
                          "unsatisfiedReason": reason, "availableInterfaces": available])
                }
            }
        }
        self.connection = connection
        connection.start(queue: DispatchQueue(label: "org.xrayrust.v07-carrier-path"))
    }
}
#endif
