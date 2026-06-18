import SwiftUI
import XrayAppleShared

@available(iOS 16.0, tvOS 17.0, macOS 13.0, *)
struct XrayRealityFingerprintPicker: View {
    @ObservedObject var viewModel: XrayClientViewModel

    var body: some View {
        if viewModel.realityFingerprintMode != nil {
            fingerprintPicker
        }
    }

    @ViewBuilder
    private var fingerprintPicker: some View {
        #if os(tvOS)
        Picker("Fingerprint", selection: fingerprintModeBinding) {
            fingerprintModeOptions
        }
        #else
        Picker("Fingerprint", selection: fingerprintModeBinding) {
            fingerprintModeOptions
        }
        .pickerStyle(.menu)
        #endif
    }

    private var fingerprintModeOptions: some View {
        ForEach(XrayRealityFingerprintMode.allCases) { mode in
            Text(mode.displayName).tag(mode)
        }
    }

    private var fingerprintModeBinding: Binding<XrayRealityFingerprintMode> {
        Binding {
            viewModel.realityFingerprintMode ?? .chrome
        } set: { mode in
            viewModel.setRealityFingerprintMode(mode)
        }
    }
}
