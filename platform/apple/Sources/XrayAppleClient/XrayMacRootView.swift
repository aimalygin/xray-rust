#if os(macOS)
import SwiftUI
import XrayAppleShared

@available(macOS 13.0, *)
public struct XrayMacRootView: View {
    @ObservedObject private var viewModel: XrayClientViewModel
    @State private var vlessURLInput = ""

    public init(viewModel: XrayClientViewModel) {
        self.viewModel = viewModel
    }

    public var body: some View {
        NavigationSplitView {
            List {
                connectionSection
                profileSection
            }
            .navigationSplitViewColumnWidth(min: 240, ideal: 280, max: 360)
        } detail: {
            configurationDetail
        }
        .navigationTitle("Xray")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    Task { await viewModel.connectOrDisconnect() }
                } label: {
                    Label(
                        XrayMacPresentation.primaryTunnelActionTitle(
                            for: viewModel.connectionStatus
                        ),
                        systemImage: XrayMacPresentation.primaryTunnelActionSystemImage(
                            for: viewModel.connectionStatus
                        )
                    )
                }
                .disabled(viewModel.isBusy)

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
        .task {
            await viewModel.refresh()
        }
    }

    private var connectionSection: some View {
        Section("Connection") {
            Label(
                viewModel.connectionStatus.displayName,
                systemImage: XrayMacPresentation.menuBarSystemImage(
                    status: viewModel.connectionStatus,
                    isBusy: viewModel.isBusy,
                    lastErrorMessage: viewModel.lastErrorMessage
                )
            )

            if viewModel.isBusy {
                HStack {
                    ProgressView()
                    Text("Working")
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
                    XrayMacPresentation.primaryTunnelActionTitle(
                        for: viewModel.connectionStatus
                    ),
                    systemImage: XrayMacPresentation.primaryTunnelActionSystemImage(
                        for: viewModel.connectionStatus
                    )
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
            Toggle("Debug Logging", isOn: $viewModel.profile.debugLoggingEnabled)
            Toggle("TUN File Descriptor", isOn: $viewModel.profile.useTunFileDescriptor)
            Picker("TUN Profile", selection: $viewModel.profile.tunRuntimeProfile) {
                ForEach(XrayTunRuntimeProfileSetting.allCases) { profile in
                    Text(profile.displayName).tag(profile)
                }
            }
        }
    }

    private var configurationDetail: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("VLESS URL", text: $vlessURLInput)

                Button {
                    importPendingVlessURL()
                } label: {
                    Label("Import", systemImage: "square.and.arrow.down")
                }
                .disabled(vlessURLInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

                PasteButton(payloadType: String.self) { strings in
                    guard let vlessURL = strings.first else {
                        return
                    }
                    viewModel.importVlessURL(vlessURL)
                }
                .accessibilityLabel("Paste VLESS URL")
            }

            TextEditor(text: $viewModel.profile.configJSON)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 320)
                .accessibilityLabel("Xray JSON configuration")

            if let lastErrorMessage = viewModel.lastErrorMessage {
                Label(lastErrorMessage, systemImage: "exclamationmark.triangle")
                    .foregroundStyle(.red)
                    .accessibilityLabel("Issue: \(lastErrorMessage)")
            }
        }
        .padding()
    }

    private func importPendingVlessURL() {
        let trimmedURL = vlessURLInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedURL.isEmpty else {
            return
        }
        guard viewModel.importVlessURLIfPresent(trimmedURL) else {
            return
        }
        vlessURLInput = ""
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
#endif
