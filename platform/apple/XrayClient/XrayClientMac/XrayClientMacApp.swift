import SwiftUI
import XrayAppleClient

@main
struct XrayClientMacApp: App {
    @StateObject private var viewModel = XrayClientViewModel()

    var body: some Scene {
        WindowGroup("Xray", id: XrayMacWindowID.main) {
            XrayMacRootView(viewModel: viewModel)
                .frame(minWidth: 720, minHeight: 480)
        }
        .defaultSize(width: 980, height: 640)
        .windowResizability(.contentMinSize)
        .windowToolbarStyle(.unified)

        MenuBarExtra {
            XrayMacMenuBarView(viewModel: viewModel)
        } label: {
            XrayMacMenuBarLabel(viewModel: viewModel)
        }
        .menuBarExtraStyle(.menu)

        Settings {
            XrayMacSettingsView()
        }
    }
}
