import SwiftUI
import XrayAppleClient

@main
struct XrayClientApp: App {
    var body: some Scene {
        WindowGroup {
            if #available(iOS 15.0, tvOS 17.0, *) {
                XrayClientRootView()
            } else {
                Text("Unsupported OS")
            }
        }
    }
}
