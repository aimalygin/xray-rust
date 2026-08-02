import SwiftUI
import XrayAppleShared

@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
struct XrayDNSTestSettingsView: View {
    @Binding var mode: XrayClientDNSTestMode
    @Binding var transport: XrayClientDNSTestTransport
    @Binding var upstream: String

    var body: some View {
        Section("DNS Testing") {
            modePicker

            if mode == .defaultDNS {
                Text(
                    "FakeDNS with \(XrayClientDNSTestMode.defaultDNSUpstream) over routed TCP."
                )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .accessibilityLabel(
                        "Default DNS uses FakeDNS with \(XrayClientDNSTestMode.defaultDNSUpstream) over routed TCP."
                    )
            } else if mode != .configuration {
                transportPicker
                upstreamField

                if mode == .fakeIP {
                    Text(
                        "A FakeDNS upstream is optional only when restored domains cannot select Freedom."
                    )
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                }

                if transport == .localTCP {
                    Label(
                        "Local TCP bypasses Xray routing.",
                        systemImage: "exclamationmark.triangle"
                    )
                    .font(.footnote)
                    .foregroundStyle(.orange)
                    .accessibilityLabel("Warning: Local TCP bypasses Xray routing.")
                }
            }

            Text("Applied on the next connection. The source JSON remains unchanged.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private var modePicker: some View {
        #if os(tvOS)
        Picker("DNS Test Mode", selection: $mode) {
            modeOptions
        }
        .accessibilityIdentifier("dns-test-mode-picker")
        #else
        Picker("DNS Test Mode", selection: $mode) {
            modeOptions
        }
        .pickerStyle(.menu)
        .accessibilityIdentifier("dns-test-mode-picker")
        #endif
    }

    private var modeOptions: some View {
        ForEach(XrayClientDNSTestMode.allCases) { option in
            Text(option.displayName).tag(option)
        }
    }

    @ViewBuilder
    private var transportPicker: some View {
        #if os(tvOS)
        Picker("DNS Transport", selection: $transport) {
            transportOptions
        }
        .accessibilityIdentifier("dns-test-transport-picker")
        #else
        Picker("DNS Transport", selection: $transport) {
            transportOptions
        }
        .pickerStyle(.menu)
        .accessibilityIdentifier("dns-test-transport-picker")
        #endif
    }

    private var transportOptions: some View {
        ForEach(XrayClientDNSTestTransport.allCases) { option in
            Text(option.displayName).tag(option)
        }
    }

    @ViewBuilder
    private var upstreamField: some View {
        #if os(iOS)
        TextField(upstreamFieldLabel, text: $upstream)
            .textInputAutocapitalization(.never)
            .disableAutocorrection(true)
            .keyboardType(.URL)
            .dnsUpstreamAccessibility(label: upstreamFieldLabel)
        #elseif os(tvOS)
        TextField(upstreamFieldLabel, text: $upstream)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
            .dnsUpstreamAccessibility(label: upstreamFieldLabel)
        #else
        TextField(upstreamFieldLabel, text: $upstream)
            .dnsUpstreamAccessibility(label: upstreamFieldLabel)
        #endif
    }

    private var upstreamFieldLabel: String {
        mode.requiresUpstream ? "DNS Upstream (Required)" : "DNS Upstream (Optional)"
    }
}

@available(iOS 15.0, tvOS 17.0, macOS 13.0, *)
private extension View {
    func dnsUpstreamAccessibility(label: String) -> some View {
        accessibilityLabel(label)
            .accessibilityHint(
                "Enter a host or IP address with an optional port. Use brackets around IPv6 when adding a port. The selected transport determines the scheme."
            )
            .accessibilityIdentifier("dns-upstream-field")
    }
}
