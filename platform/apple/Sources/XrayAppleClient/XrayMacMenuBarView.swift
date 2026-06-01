#if os(macOS)
import AppKit
import SwiftUI

@available(macOS 13.0, *)
public struct XrayMacMenuBarLabel: View {
    @ObservedObject private var viewModel: XrayClientViewModel

    public init(viewModel: XrayClientViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        Label(
            "Xray",
            systemImage: XrayMacPresentation.menuBarSystemImage(
                status: viewModel.connectionStatus,
                isBusy: viewModel.isBusy,
                lastErrorMessage: viewModel.lastErrorMessage
            )
        )
    }
}

@available(macOS 13.0, *)
public struct XrayMacMenuBarView: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject private var viewModel: XrayClientViewModel

    public init(viewModel: XrayClientViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        Text("Status: \(viewModel.connectionStatus.displayName)")

        if let runtimeStats = viewModel.runtimeStats {
            Divider()
            Text("Inbound: \(runtimeStats.inboundPackets.formatted())")
            Text("Outbound: \(runtimeStats.outboundPackets.formatted())")
            Text("Dropped: \(runtimeStats.droppedPackets.formatted())")
        }

        if let lastErrorMessage = viewModel.lastErrorMessage {
            Divider()
            Label(lastErrorMessage, systemImage: "exclamationmark.triangle")
        }

        Divider()

        Button {
            Task { await viewModel.connectOrDisconnect() }
        } label: {
            Label(
                XrayMacPresentation.primaryTunnelActionTitle(for: viewModel.connectionStatus),
                systemImage: XrayMacPresentation.primaryTunnelActionSystemImage(
                    for: viewModel.connectionStatus
                )
            )
        }
        .disabled(viewModel.isBusy)

        Button {
            Task { await viewModel.refresh() }
        } label: {
            Label("Refresh", systemImage: "arrow.clockwise")
        }

        Divider()

        Button {
            openWindow(id: XrayMacWindowID.main)
            NSApplication.shared.activate(ignoringOtherApps: true)
        } label: {
            Label("Open Xray", systemImage: "macwindow")
        }

        Button {
            NSApplication.shared.sendAction(
                Selector(("showSettingsWindow:")),
                to: nil,
                from: nil
            )
            NSApplication.shared.activate(ignoringOtherApps: true)
        } label: {
            Label("Settings", systemImage: "gear")
        }

        Divider()

        Button {
            NSApplication.shared.terminate(nil)
        } label: {
            Label("Quit", systemImage: "power")
        }
    }
}
#endif
