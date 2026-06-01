#if os(macOS)
import SwiftUI

@available(macOS 13.0, *)
public struct XrayMacSettingsView: View {
    public init() {}

    public var body: some View {
        Form {
            Section("Network Extension") {
                LabeledContent("Provider") {
                    Text("Packet Tunnel")
                }
                LabeledContent("Profile Storage") {
                    Text("User Defaults")
                }
            }
        }
        .padding()
        .frame(width: 380)
    }
}
#endif
