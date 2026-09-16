import SwiftUI
import XrayAppleClient

@main
struct XrayClientApp: App {
    var body: some Scene {
        WindowGroup {
            if #available(iOS 15.0, tvOS 17.0, *) {
                #if DEBUG
                if ProcessInfo.processInfo.environment["XRAY_V07_DEVICE_PROBE"] == "1" {
                    XrayProtocolDeviceProbeView()
                } else {
                    XrayClientRootView()
                }
                #else
                XrayClientRootView()
                #endif
            } else {
                Text("Unsupported OS")
            }
        }
    }
}
