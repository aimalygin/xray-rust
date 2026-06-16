import SwiftUI
import XrayAppleShared

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
struct XrayRealityVisionFlowPicker: View {
    @ObservedObject var viewModel: XrayClientViewModel

    var body: some View {
        if viewModel.realityVisionFlowMode != nil {
            flowPicker
        }
    }

    @ViewBuilder
    private var flowPicker: some View {
        #if os(tvOS)
        Picker("Vision UDP/443", selection: flowModeBinding) {
            flowModeOptions
        }
        #else
        Picker("Vision UDP/443", selection: flowModeBinding) {
            flowModeOptions
        }
        .pickerStyle(.menu)
        #endif
    }

    private var flowModeOptions: some View {
        ForEach(XrayRealityVisionFlowMode.allCases) { mode in
            Text(mode.displayName).tag(mode)
        }
    }

    private var flowModeBinding: Binding<XrayRealityVisionFlowMode> {
        Binding {
            viewModel.realityVisionFlowMode ?? .blockUDP443
        } set: { mode in
            viewModel.setRealityVisionFlowMode(mode)
        }
    }
}
