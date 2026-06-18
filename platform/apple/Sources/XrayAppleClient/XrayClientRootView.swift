import SwiftUI
import XrayAppleShared

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
public struct XrayClientRootView: View {
    @StateObject private var viewModel: XrayClientViewModel
    @State private var vlessURLInput = ""

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
                regionalRoutingSection
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
                Task {
                    #if os(tvOS)
                    let acceptedPendingInput = await viewModel.connectOrDisconnect(
                        importingVlessURLIfPresent: vlessURLInput
                    )
                    if acceptedPendingInput {
                        vlessURLInput = ""
                    }
                    #else
                    await viewModel.connectOrDisconnect()
                    #endif
                }
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
            XrayRealityVisionFlowPicker(viewModel: viewModel)
            XrayRealityFingerprintPicker(viewModel: viewModel)
            Toggle("Debug Logging", isOn: $viewModel.profile.debugLoggingEnabled)
            Toggle("TUN File Descriptor", isOn: $viewModel.profile.useTunFileDescriptor)
            Picker("TUN Profile", selection: $viewModel.profile.tunRuntimeProfile) {
                ForEach(XrayTunRuntimeProfileSetting.allCases) { profile in
                    Text(profile.displayName).tag(profile)
                }
            }
        }
    }

    private var regionalRoutingSection: some View {
        Section("Regional Routing") {
            Picker("Mode", selection: $viewModel.profile.regionalRoutingMode) {
                ForEach(XrayRegionalRoutingMode.allCases) { mode in
                    Text(mode.displayName).tag(mode)
                }
            }

            if viewModel.profile.regionalRoutingMode != .off {
                ForEach(XrayRegionalRoutingRegion.allCases) { region in
                    Toggle(region.displayName, isOn: regionalRoutingRegionBinding(region))
                }
            }
        }
    }

    private var configurationSection: some View {
        Section("Configuration") {
            #if os(tvOS)
            VStack(alignment: .leading) {
                Text("VLESS URL")
                TextField("VLESS URL", text: $vlessURLInput, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .frame(minHeight: 140)
                    .accessibilityLabel("VLESS URL")
            }

            Button {
                _ = importPendingVlessURL()
            } label: {
                Label("Import VLESS URL", systemImage: "square.and.arrow.down")
            }
            .disabled(vlessURLInput.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)

            ScrollView {
                Text(viewModel.profile.configJSON)
                    .font(.system(.body, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 260)
            .accessibilityLabel("Xray JSON configuration")
            #else
            PasteButton(payloadType: String.self) { strings in
                guard let vlessURL = strings.first else {
                    return
                }
                viewModel.importVlessURL(vlessURL)
            }
            .accessibilityLabel("Paste VLESS URL")

            TextEditor(text: $viewModel.profile.configJSON)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 260)
                .accessibilityLabel("Xray JSON configuration")
            #endif
        }
    }

    private func importPendingVlessURL() -> Bool {
        #if os(tvOS)
        let trimmedURL = vlessURLInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedURL.isEmpty else {
            return true
        }
        guard viewModel.importVlessURLIfPresent(trimmedURL) else {
            return false
        }
        vlessURLInput = ""
        return true
        #else
        return true
        #endif
    }

    private func regionalRoutingRegionBinding(
        _ region: XrayRegionalRoutingRegion
    ) -> Binding<Bool> {
        Binding {
            viewModel.profile.regionalRoutingRegions.contains(region)
        } set: { isSelected in
            var selected = Set(viewModel.profile.regionalRoutingRegions)
            if isSelected {
                selected.insert(region)
            } else {
                selected.remove(region)
            }
            viewModel.profile.regionalRoutingRegions = XrayRegionalRoutingRegion.allCases
                .filter { selected.contains($0) }
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
