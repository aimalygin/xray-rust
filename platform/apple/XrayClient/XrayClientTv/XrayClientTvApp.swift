import SwiftUI
import XrayAppleClient

@main
struct XrayClientTVApp: App {
    var body: some Scene {
        WindowGroup {
            if #available(tvOS 17.0, *) {
                XrayClientRootView()
            } else {
                Text("Unsupported OS")
            }
        }
    }
}
