import SwiftUI
import XrayAppleShared

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
public struct XrayClientRootView: View {
    @StateObject private var viewModel: XrayClientViewModel

    public init(
        store: XrayClientProfileStore = XrayClientProfileStore(),
        tunnelController: (any XrayClientTunnelControlling)? = nil
    ) {
        _viewModel = StateObject(
            wrappedValue: XrayClientViewModel(
                store: store,
                tunnelController: tunnelController
            )
        )
    }

    public var body: some View {
        NavigationStack {
            Form {
                connectionSection
                profileSection
                configurationSection
                issueSection
            }
            .navigationTitle("Xray")
            .toolbar {
                ToolbarItemGroup(placement: .primaryAction) {
                    Button {
                        viewModel.saveProfile()
                    } label: {
                        Label("Save", systemImage: "square.and.arrow.down")
                    }

                    Button {
                        Task { await viewModel.refresh() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
            }
        }
        .task {
            await viewModel.refresh()
        }
    }

    private var connectionSection: some View {
        Section("Connection") {
            HStack {
                Label(
                    viewModel.connectionStatus.displayName,
                    systemImage: statusSystemImage
                )
                Spacer()
                if viewModel.isBusy {
                    ProgressView()
                }
            }

            if let runtimeStats = viewModel.runtimeStats {
                statsRow("Inbound", value: runtimeStats.inboundPackets)
                statsRow("Outbound", value: runtimeStats.outboundPackets)
                statsRow("Dropped", value: runtimeStats.droppedPackets)
            }

            Button {
                Task { await viewModel.connectOrDisconnect() }
            } label: {
                Label(
                    viewModel.connectionStatus.isActive ? "Disconnect" : "Connect",
                    systemImage: viewModel.connectionStatus.isActive ? "stop.circle" : "power"
                )
            }
            .disabled(viewModel.isBusy)
        }
    }

    private var profileSection: some View {
        Section("Profile") {
            TextField("Name", text: $viewModel.profile.name)
            TextField("Provider Bundle ID", text: $viewModel.profile.providerBundleIdentifier)
            TextField("Server Address", text: $viewModel.profile.serverAddress)
        }
    }

    private var configurationSection: some View {
        Section("Configuration") {
            #if os(iOS) || os(macOS)
            PasteButton(payloadType: String.self) { strings in
                guard let vlessURL = strings.first else {
                    return
                }
                viewModel.importVlessURL(vlessURL)
            }
            .accessibilityLabel("Paste VLESS URL")
            #endif

            TextEditor(text: $viewModel.profile.configJSON)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 260)
                .accessibilityLabel("Xray JSON configuration")
        }
    }

    @ViewBuilder
    private var issueSection: some View {
        if let lastErrorMessage = viewModel.lastErrorMessage {
            Section("Issue") {
                Label(lastErrorMessage, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
            }
        }
    }

    private var statusSystemImage: String {
        switch viewModel.connectionStatus {
        case .connected:
            return "checkmark.circle"
        case .connecting, .reasserting:
            return "bolt.horizontal.circle"
        case .disconnecting:
            return "pause.circle"
        case .invalid:
            return "xmark.octagon"
        case .disconnected:
            return "circle"
        case .unknown:
            return "questionmark.circle"
        }
    }

    private func statsRow(_ title: String, value: UInt64) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value, format: .number)
                .monospacedDigit()
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}
