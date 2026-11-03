import XrayAppleTunnel
#if DEBUG
import Darwin
import Foundation
#endif

@available(iOSApplicationExtension 15.0, tvOSApplicationExtension 17.0, *)
final class PacketTunnelProvider: XrayPacketTunnelProvider {
#if DEBUG
    // Reference-app instrumentation only. CPU belongs to this extension,
    // including all live and terminated threads; no SDK or FFI ABI change.
    override func handleAppMessage(_ data: Data, completionHandler: ((Data?) -> Void)?) {
        guard data == Data("v08-process-cpu".utf8) else {
            super.handleAppMessage(data, completionHandler: completionHandler)
            return
        }
        var usage = rusage()
        guard getrusage(RUSAGE_SELF, &usage) == 0 else { completionHandler?(nil); return }
        let user = Double(usage.ru_utime.tv_sec) + Double(usage.ru_utime.tv_usec) / 1_000_000
        let system = Double(usage.ru_stime.tv_sec) + Double(usage.ru_stime.tv_usec) / 1_000_000
        completionHandler?(try? JSONSerialization.data(withJSONObject: [
            "userSeconds": user, "systemSeconds": system,
            "uptime": ProcessInfo.processInfo.systemUptime, "pid": Double(getpid())
        ]))
    }
#endif
}
