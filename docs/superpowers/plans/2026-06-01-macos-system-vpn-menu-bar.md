# macOS System VPN Menu Bar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a native macOS system VPN app target with a Packet Tunnel extension and a menu bar extra.

**Architecture:** Reuse the existing Apple Swift package for runtime, profile storage, NetworkExtension control, and tunnel provider code. Add macOS-specific SwiftUI views inside `XrayAppleClient`, then add thin macOS app and extension targets under the existing Xcode project. The app owns one shared `XrayClientViewModel` and passes it to both the main window and menu bar extra.

**Tech Stack:** Swift 5, SwiftUI, AppKit for macOS app lifecycle actions, NetworkExtension, Xcode project targets, existing Rust `XrayRust.xcframework`.

---

## File Structure

- Create `platform/apple/Sources/XrayAppleClient/XrayMacPresentation.swift`
  - Pure presentation helpers for menu symbols, action labels, and the main window id.
- Create `platform/apple/Tests/XrayAppleClientTests/XrayMacPresentationTests.swift`
  - Unit coverage for macOS presentation state mapping.
- Create `platform/apple/Sources/XrayAppleClient/XrayMacRootView.swift`
  - Native macOS main window using `NavigationSplitView`.
- Create `platform/apple/Sources/XrayAppleClient/XrayMacMenuBarView.swift`
  - `MenuBarExtra` label and menu content using the shared view model.
- Create `platform/apple/Sources/XrayAppleClient/XrayMacSettingsView.swift`
  - Minimal native `Settings` scene content.
- Create `platform/apple/XrayClient/XrayClientMac/XrayClientMacApp.swift`
  - Thin macOS `@main` app target entry point.
- Create `platform/apple/XrayClient/XrayClientMac/XrayClientMac.entitlements`
  - macOS app NetworkExtension entitlement.
- Create `platform/apple/XrayClient/XrayClientMacTunnel/PacketTunnelProvider.swift`
  - Thin macOS Packet Tunnel extension provider.
- Create `platform/apple/XrayClient/XrayClientMacTunnel/Info.plist`
  - Packet Tunnel extension point declaration.
- Create `platform/apple/XrayClient/XrayClientMacTunnel/XrayClientMacTunnel.entitlements`
  - macOS extension NetworkExtension entitlement.
- Modify `platform/apple/XrayClient/XrayClient.xcodeproj/project.pbxproj`
  - Add macOS app and Packet Tunnel extension targets, build phases, file refs, product refs, dependencies, package product dependencies, and build settings.
- Modify `platform/apple/README.md`
  - Document the new macOS host targets and signing expectations.

Keep existing dirty `xcuserdata` files unstaged unless the user explicitly asks to include them.

---

### Task 1: Add Test-Covered macOS Presentation Helpers

**Files:**
- Create: `platform/apple/Tests/XrayAppleClientTests/XrayMacPresentationTests.swift`
- Create: `platform/apple/Sources/XrayAppleClient/XrayMacPresentation.swift`

- [ ] **Step 1: Write the failing tests**

Create `platform/apple/Tests/XrayAppleClientTests/XrayMacPresentationTests.swift`:

```swift
#if os(macOS)
import XCTest
import XrayAppleShared
@testable import XrayAppleClient

@available(macOS 13.0, *)
final class XrayMacPresentationTests: XCTestCase {
    func testMenuBarSystemImagePrioritizesIssueThenBusyThenConnectionStatus() {
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .connected,
                isBusy: false,
                lastErrorMessage: "failed"
            ),
            "exclamationmark.triangle"
        )
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .connected,
                isBusy: true,
                lastErrorMessage: nil
            ),
            "arrow.triangle.2.circlepath"
        )
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .connected,
                isBusy: false,
                lastErrorMessage: nil
            ),
            "network"
        )
        XCTAssertEqual(
            XrayMacPresentation.menuBarSystemImage(
                status: .disconnected,
                isBusy: false,
                lastErrorMessage: nil
            ),
            "network.slash"
        )
    }

    func testPrimaryTunnelActionReflectsConnectionStatus() {
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionTitle(for: .connected),
            "Disconnect"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionSystemImage(for: .connected),
            "stop.circle"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionTitle(for: .connecting),
            "Disconnect"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionTitle(for: .disconnected),
            "Connect"
        )
        XCTAssertEqual(
            XrayMacPresentation.primaryTunnelActionSystemImage(for: .disconnected),
            "power"
        )
    }
}
#endif
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
HOME=target/mobile/apple-swiftpm-home CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache swift test --disable-sandbox --package-path platform/apple --filter XrayMacPresentationTests
```

Expected: FAIL because `XrayMacPresentation` does not exist.

- [ ] **Step 3: Add the minimal presentation helper implementation**

Create `platform/apple/Sources/XrayAppleClient/XrayMacPresentation.swift`:

```swift
#if os(macOS)
import Foundation
import XrayAppleShared

@available(macOS 13.0, *)
public enum XrayMacWindowID {
    public static let main = "xray-main"
}

@available(macOS 13.0, *)
public enum XrayMacPresentation {
    public static func menuBarSystemImage(
        status: XrayClientConnectionStatus,
        isBusy: Bool,
        lastErrorMessage: String?
    ) -> String {
        if lastErrorMessage != nil {
            return "exclamationmark.triangle"
        }
        if isBusy {
            return "arrow.triangle.2.circlepath"
        }
        return status.isActive ? "network" : "network.slash"
    }

    public static func primaryTunnelActionTitle(
        for status: XrayClientConnectionStatus
    ) -> String {
        status.isActive ? "Disconnect" : "Connect"
    }

    public static func primaryTunnelActionSystemImage(
        for status: XrayClientConnectionStatus
    ) -> String {
        status.isActive ? "stop.circle" : "power"
    }
}
#endif
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
HOME=target/mobile/apple-swiftpm-home CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache swift test --disable-sandbox --package-path platform/apple --filter XrayMacPresentationTests
```

Expected: PASS for `XrayMacPresentationTests`.

- [ ] **Step 5: Commit**

Run:

```bash
git add platform/apple/Sources/XrayAppleClient/XrayMacPresentation.swift platform/apple/Tests/XrayAppleClientTests/XrayMacPresentationTests.swift
git commit -m "feat(apple): add macOS presentation helpers"
```

---

### Task 2: Add macOS SwiftUI Views To The Shared Client Package

**Files:**
- Create: `platform/apple/Sources/XrayAppleClient/XrayMacRootView.swift`
- Create: `platform/apple/Sources/XrayAppleClient/XrayMacMenuBarView.swift`
- Create: `platform/apple/Sources/XrayAppleClient/XrayMacSettingsView.swift`

- [ ] **Step 1: Run package build before adding views**

Run:

```bash
HOME=target/mobile/apple-swiftpm-home CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache swift build --disable-sandbox --package-path platform/apple
```

Expected: PASS before the view changes.

- [ ] **Step 2: Add the native macOS root view**

Create `platform/apple/Sources/XrayAppleClient/XrayMacRootView.swift`:

```swift
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
            Toggle("Block QUIC", isOn: $viewModel.profile.blockQUIC)
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
```

- [ ] **Step 3: Add the menu bar label and menu content**

Create `platform/apple/Sources/XrayAppleClient/XrayMacMenuBarView.swift`:

```swift
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
```

- [ ] **Step 4: Add the settings scene view**

Create `platform/apple/Sources/XrayAppleClient/XrayMacSettingsView.swift`:

```swift
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
```

- [ ] **Step 5: Run package build**

Run:

```bash
HOME=target/mobile/apple-swiftpm-home CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache swift build --disable-sandbox --package-path platform/apple
```

Expected: PASS.

- [ ] **Step 6: Run package tests**

Run:

```bash
HOME=target/mobile/apple-swiftpm-home CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache swift test --disable-sandbox --package-path platform/apple
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add platform/apple/Sources/XrayAppleClient/XrayMacRootView.swift platform/apple/Sources/XrayAppleClient/XrayMacMenuBarView.swift platform/apple/Sources/XrayAppleClient/XrayMacSettingsView.swift
git commit -m "feat(apple): add native macOS client views"
```

---

### Task 3: Add macOS Host App And Packet Tunnel Source Files

**Files:**
- Create: `platform/apple/XrayClient/XrayClientMac/XrayClientMacApp.swift`
- Create: `platform/apple/XrayClient/XrayClientMac/XrayClientMac.entitlements`
- Create: `platform/apple/XrayClient/XrayClientMacTunnel/PacketTunnelProvider.swift`
- Create: `platform/apple/XrayClient/XrayClientMacTunnel/Info.plist`
- Create: `platform/apple/XrayClient/XrayClientMacTunnel/XrayClientMacTunnel.entitlements`

- [ ] **Step 1: Add the macOS app entry point**

Create `platform/apple/XrayClient/XrayClientMac/XrayClientMacApp.swift`:

```swift
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
```

- [ ] **Step 2: Add the macOS app entitlements**

Create `platform/apple/XrayClient/XrayClientMac/XrayClientMac.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.developer.networking.networkextension</key>
	<array>
		<string>packet-tunnel-provider</string>
	</array>
</dict>
</plist>
```

- [ ] **Step 3: Add the macOS Packet Tunnel provider**

Create `platform/apple/XrayClient/XrayClientMacTunnel/PacketTunnelProvider.swift`:

```swift
import XrayAppleTunnel

@available(macOSApplicationExtension 13.0, *)
final class PacketTunnelProvider: XrayPacketTunnelProvider {}
```

- [ ] **Step 4: Add the macOS Packet Tunnel extension plist**

Create `platform/apple/XrayClient/XrayClientMacTunnel/Info.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSExtension</key>
	<dict>
		<key>NSExtensionPointIdentifier</key>
		<string>com.apple.networkextension.packet-tunnel</string>
		<key>NSExtensionPrincipalClass</key>
		<string>$(PRODUCT_MODULE_NAME).PacketTunnelProvider</string>
	</dict>
</dict>
</plist>
```

- [ ] **Step 5: Add the macOS Packet Tunnel entitlements**

Create `platform/apple/XrayClient/XrayClientMacTunnel/XrayClientMacTunnel.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.developer.networking.networkextension</key>
	<array>
		<string>packet-tunnel-provider</string>
	</array>
</dict>
</plist>
```

- [ ] **Step 6: Lint new plist files**

Run:

```bash
plutil -lint platform/apple/XrayClient/XrayClientMac/XrayClientMac.entitlements platform/apple/XrayClient/XrayClientMacTunnel/Info.plist platform/apple/XrayClient/XrayClientMacTunnel/XrayClientMacTunnel.entitlements
```

Expected: each file reports `OK`.

- [ ] **Step 7: Commit**

Run:

```bash
git add platform/apple/XrayClient/XrayClientMac platform/apple/XrayClient/XrayClientMacTunnel
git commit -m "feat(apple): add macOS host and tunnel files"
```

---

### Task 4: Wire macOS Targets Into The Xcode Project

**Files:**
- Modify: `platform/apple/XrayClient/XrayClient.xcodeproj/project.pbxproj`

Use these deterministic IDs for the new project objects:

```text
04A1B2C3D4E5F60000000001 XrayClientMac target
04A1B2C3D4E5F60000000002 XrayClientMac.app product reference
04A1B2C3D4E5F60000000003 XrayClientMac sources phase
04A1B2C3D4E5F60000000004 XrayClientMac frameworks phase
04A1B2C3D4E5F60000000005 XrayClientMac resources phase
04A1B2C3D4E5F60000000006 XrayClientMac embed extensions phase
04A1B2C3D4E5F60000000007 XrayClientMac configuration list
04A1B2C3D4E5F60000000008 XrayClientMac Debug configuration
04A1B2C3D4E5F60000000009 XrayClientMac Release configuration
04A1B2C3D4E5F6000000000A XrayClientMac group
04A1B2C3D4E5F6000000000B XrayClientMacApp.swift file reference
04A1B2C3D4E5F6000000000C XrayClientMac.entitlements file reference
04A1B2C3D4E5F6000000000D XrayClientMacApp.swift build file
04A1B2C3D4E5F6000000000E XrayAppleClient package product dependency
04A1B2C3D4E5F6000000000F XrayAppleClient framework build file
04A1B2C3D4E5F60000000010 XrayClientMacTunnel target
04A1B2C3D4E5F60000000011 XrayClientMacTunnel.appex product reference
04A1B2C3D4E5F60000000012 XrayClientMacTunnel sources phase
04A1B2C3D4E5F60000000013 XrayClientMacTunnel frameworks phase
04A1B2C3D4E5F60000000014 XrayClientMacTunnel resources phase
04A1B2C3D4E5F60000000015 XrayClientMacTunnel configuration list
04A1B2C3D4E5F60000000016 XrayClientMacTunnel Debug configuration
04A1B2C3D4E5F60000000017 XrayClientMacTunnel Release configuration
04A1B2C3D4E5F60000000018 XrayClientMacTunnel group
04A1B2C3D4E5F60000000019 XrayClientMacTunnel Info.plist file reference
04A1B2C3D4E5F6000000001A XrayClientMacTunnel PacketTunnelProvider.swift file reference
04A1B2C3D4E5F6000000001B XrayClientMacTunnel entitlements file reference
04A1B2C3D4E5F6000000001C XrayClientMacTunnel PacketTunnelProvider.swift build file
04A1B2C3D4E5F6000000001D NetworkExtension.framework build file for macOS tunnel
04A1B2C3D4E5F6000000001E XrayAppleTunnel package product dependency
04A1B2C3D4E5F6000000001F XrayAppleTunnel framework build file
04A1B2C3D4E5F60000000020 XrayClientMac dependency on XrayClientMacTunnel
04A1B2C3D4E5F60000000021 XrayClientMac dependency proxy for XrayClientMacTunnel
04A1B2C3D4E5F60000000022 XrayClientMacTunnel.appex embed build file
```

- [ ] **Step 1: Add build files**

In the `PBXBuildFile section`, add:

```pbxproj
		04A1B2C3D4E5F6000000000D /* XrayClientMacApp.swift in Sources */ = {isa = PBXBuildFile; fileRef = 04A1B2C3D4E5F6000000000B /* XrayClientMacApp.swift */; };
		04A1B2C3D4E5F6000000000F /* XrayAppleClient in Frameworks */ = {isa = PBXBuildFile; productRef = 04A1B2C3D4E5F6000000000E /* XrayAppleClient */; };
		04A1B2C3D4E5F6000000001C /* PacketTunnelProvider.swift in Sources */ = {isa = PBXBuildFile; fileRef = 04A1B2C3D4E5F6000000001A /* PacketTunnelProvider.swift */; };
		04A1B2C3D4E5F6000000001D /* NetworkExtension.framework in Frameworks */ = {isa = PBXBuildFile; fileRef = 044523D22FCA253F00EB1099 /* NetworkExtension.framework */; };
		04A1B2C3D4E5F6000000001F /* XrayAppleTunnel in Frameworks */ = {isa = PBXBuildFile; productRef = 04A1B2C3D4E5F6000000001E /* XrayAppleTunnel */; };
		04A1B2C3D4E5F60000000022 /* XrayClientMacTunnel.appex in Embed Foundation Extensions */ = {isa = PBXBuildFile; fileRef = 04A1B2C3D4E5F60000000011 /* XrayClientMacTunnel.appex */; settings = {ATTRIBUTES = (RemoveHeadersOnCopy, ); }; };
```

- [ ] **Step 2: Add the dependency proxy**

In the `PBXContainerItemProxy section`, add:

```pbxproj
		04A1B2C3D4E5F60000000021 /* PBXContainerItemProxy */ = {
			isa = PBXContainerItemProxy;
			containerPortal = 044523912FCA23E800EB1099 /* Project object */;
			proxyType = 1;
			remoteGlobalIDString = 04A1B2C3D4E5F60000000010;
			remoteInfo = XrayClientMacTunnel;
		};
```

- [ ] **Step 3: Add the macOS embed extension build phase**

In the `PBXCopyFilesBuildPhase section`, add:

```pbxproj
		04A1B2C3D4E5F60000000006 /* Embed Foundation Extensions */ = {
			isa = PBXCopyFilesBuildPhase;
			buildActionMask = 2147483647;
			dstPath = "";
			dstSubfolderSpec = 13;
			files = (
				04A1B2C3D4E5F60000000022 /* XrayClientMacTunnel.appex in Embed Foundation Extensions */,
			);
			name = "Embed Foundation Extensions";
			runOnlyForDeploymentPostprocessing = 0;
		};
```

- [ ] **Step 4: Add file references**

In the `PBXFileReference section`, add:

```pbxproj
		04A1B2C3D4E5F60000000002 /* XrayClientMac.app */ = {isa = PBXFileReference; explicitFileType = wrapper.application; includeInIndex = 0; path = XrayClientMac.app; sourceTree = BUILT_PRODUCTS_DIR; };
		04A1B2C3D4E5F6000000000B /* XrayClientMacApp.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = XrayClientMacApp.swift; sourceTree = "<group>"; };
		04A1B2C3D4E5F6000000000C /* XrayClientMac.entitlements */ = {isa = PBXFileReference; lastKnownFileType = text.plist.entitlements; path = XrayClientMac.entitlements; sourceTree = "<group>"; };
		04A1B2C3D4E5F60000000011 /* XrayClientMacTunnel.appex */ = {isa = PBXFileReference; explicitFileType = "wrapper.app-extension"; includeInIndex = 0; path = XrayClientMacTunnel.appex; sourceTree = BUILT_PRODUCTS_DIR; };
		04A1B2C3D4E5F60000000019 /* Info.plist */ = {isa = PBXFileReference; lastKnownFileType = text.plist.xml; path = Info.plist; sourceTree = "<group>"; };
		04A1B2C3D4E5F6000000001A /* PacketTunnelProvider.swift */ = {isa = PBXFileReference; lastKnownFileType = sourcecode.swift; path = PacketTunnelProvider.swift; sourceTree = "<group>"; };
		04A1B2C3D4E5F6000000001B /* XrayClientMacTunnel.entitlements */ = {isa = PBXFileReference; lastKnownFileType = text.plist.entitlements; path = XrayClientMacTunnel.entitlements; sourceTree = "<group>"; };
```

- [ ] **Step 5: Add framework build phases**

In the `PBXFrameworksBuildPhase section`, add:

```pbxproj
		04A1B2C3D4E5F60000000004 /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
				04A1B2C3D4E5F6000000000F /* XrayAppleClient in Frameworks */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
		04A1B2C3D4E5F60000000013 /* Frameworks */ = {
			isa = PBXFrameworksBuildPhase;
			buildActionMask = 2147483647;
			files = (
				04A1B2C3D4E5F6000000001D /* NetworkExtension.framework in Frameworks */,
				04A1B2C3D4E5F6000000001F /* XrayAppleTunnel in Frameworks */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
```

- [ ] **Step 6: Add groups and product references**

In the `PBXGroup section`, add:

```pbxproj
		04A1B2C3D4E5F6000000000A /* XrayClientMac */ = {
			isa = PBXGroup;
			children = (
				04A1B2C3D4E5F6000000000B /* XrayClientMacApp.swift */,
				04A1B2C3D4E5F6000000000C /* XrayClientMac.entitlements */,
			);
			path = XrayClientMac;
			sourceTree = "<group>";
		};
		04A1B2C3D4E5F60000000018 /* XrayClientMacTunnel */ = {
			isa = PBXGroup;
			children = (
				04A1B2C3D4E5F60000000019 /* Info.plist */,
				04A1B2C3D4E5F6000000001A /* PacketTunnelProvider.swift */,
				04A1B2C3D4E5F6000000001B /* XrayClientMacTunnel.entitlements */,
			);
			path = XrayClientMacTunnel;
			sourceTree = "<group>";
		};
```

Also insert `04A1B2C3D4E5F6000000000A /* XrayClientMac */` and `04A1B2C3D4E5F60000000018 /* XrayClientMacTunnel */` into the main group children after `TunnelTv`. Insert `04A1B2C3D4E5F60000000002 /* XrayClientMac.app */` and `04A1B2C3D4E5F60000000011 /* XrayClientMacTunnel.appex */` into the `Products` group.

- [ ] **Step 7: Add native targets**

In the `PBXNativeTarget section`, add:

```pbxproj
		04A1B2C3D4E5F60000000001 /* XrayClientMac */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 04A1B2C3D4E5F60000000007 /* Build configuration list for PBXNativeTarget "XrayClientMac" */;
			buildPhases = (
				04A1B2C3D4E5F60000000003 /* Sources */,
				04A1B2C3D4E5F60000000004 /* Frameworks */,
				04A1B2C3D4E5F60000000005 /* Resources */,
				04A1B2C3D4E5F60000000006 /* Embed Foundation Extensions */,
			);
			buildRules = (
			);
			dependencies = (
				04A1B2C3D4E5F60000000020 /* PBXTargetDependency */,
			);
			name = XrayClientMac;
			packageProductDependencies = (
				04A1B2C3D4E5F6000000000E /* XrayAppleClient */,
			);
			productName = XrayClientMac;
			productReference = 04A1B2C3D4E5F60000000002 /* XrayClientMac.app */;
			productType = "com.apple.product-type.application";
		};
		04A1B2C3D4E5F60000000010 /* XrayClientMacTunnel */ = {
			isa = PBXNativeTarget;
			buildConfigurationList = 04A1B2C3D4E5F60000000015 /* Build configuration list for PBXNativeTarget "XrayClientMacTunnel" */;
			buildPhases = (
				04A1B2C3D4E5F60000000012 /* Sources */,
				04A1B2C3D4E5F60000000013 /* Frameworks */,
				04A1B2C3D4E5F60000000014 /* Resources */,
			);
			buildRules = (
			);
			dependencies = (
			);
			name = XrayClientMacTunnel;
			packageProductDependencies = (
				04A1B2C3D4E5F6000000001E /* XrayAppleTunnel */,
			);
			productName = XrayClientMacTunnel;
			productReference = 04A1B2C3D4E5F60000000011 /* XrayClientMacTunnel.appex */;
			productType = "com.apple.product-type.app-extension";
		};
```

- [ ] **Step 8: Update project target attributes and target list**

In `PBXProject.TargetAttributes`, add:

```pbxproj
					04A1B2C3D4E5F60000000001 = {
						CreatedOnToolsVersion = 26.5;
					};
					04A1B2C3D4E5F60000000010 = {
						CreatedOnToolsVersion = 26.5;
					};
```

In `PBXProject.targets`, add:

```pbxproj
				04A1B2C3D4E5F60000000001 /* XrayClientMac */,
				04A1B2C3D4E5F60000000010 /* XrayClientMacTunnel */,
```

- [ ] **Step 9: Add resource and source build phases**

In the `PBXResourcesBuildPhase section`, add:

```pbxproj
		04A1B2C3D4E5F60000000005 /* Resources */ = {
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
		04A1B2C3D4E5F60000000014 /* Resources */ = {
			isa = PBXResourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
```

In the `PBXSourcesBuildPhase section`, add:

```pbxproj
		04A1B2C3D4E5F60000000003 /* Sources */ = {
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
				04A1B2C3D4E5F6000000000D /* XrayClientMacApp.swift in Sources */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
		04A1B2C3D4E5F60000000012 /* Sources */ = {
			isa = PBXSourcesBuildPhase;
			buildActionMask = 2147483647;
			files = (
				04A1B2C3D4E5F6000000001C /* PacketTunnelProvider.swift in Sources */,
			);
			runOnlyForDeploymentPostprocessing = 0;
		};
```

- [ ] **Step 10: Add target dependency**

In the `PBXTargetDependency section`, add:

```pbxproj
		04A1B2C3D4E5F60000000020 /* PBXTargetDependency */ = {
			isa = PBXTargetDependency;
			target = 04A1B2C3D4E5F60000000010 /* XrayClientMacTunnel */;
			targetProxy = 04A1B2C3D4E5F60000000021 /* PBXContainerItemProxy */;
		};
```

- [ ] **Step 11: Add macOS target build configurations**

In the `XCBuildConfiguration section`, add:

```pbxproj
		04A1B2C3D4E5F60000000008 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				CODE_SIGN_ENTITLEMENTS = XrayClientMac/XrayClientMac.entitlements;
				CODE_SIGN_STYLE = Automatic;
				COMBINE_HIDPI_IMAGES = YES;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = 9QF29ADW72;
				ENABLE_HARDENED_RUNTIME = YES;
				ENABLE_PREVIEWS = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_KEY_NSApplicationCategoryType = "public.app-category.utilities";
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/../Frameworks",
				);
				MACOSX_DEPLOYMENT_TARGET = 13.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = org.texforge.XrayClientMac;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SDKROOT = macosx;
				STRING_CATALOG_GENERATE_SYMBOLS = YES;
				SWIFT_APPROACHABLE_CONCURRENCY = YES;
				SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor;
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_UPCOMING_FEATURE_MEMBER_IMPORT_VISIBILITY = YES;
				SWIFT_VERSION = 5.0;
			};
			name = Debug;
		};
		04A1B2C3D4E5F60000000009 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				CODE_SIGN_ENTITLEMENTS = XrayClientMac/XrayClientMac.entitlements;
				CODE_SIGN_STYLE = Automatic;
				COMBINE_HIDPI_IMAGES = YES;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = 9QF29ADW72;
				ENABLE_HARDENED_RUNTIME = YES;
				ENABLE_PREVIEWS = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_KEY_NSApplicationCategoryType = "public.app-category.utilities";
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/../Frameworks",
				);
				MACOSX_DEPLOYMENT_TARGET = 13.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = org.texforge.XrayClientMac;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SDKROOT = macosx;
				STRING_CATALOG_GENERATE_SYMBOLS = YES;
				SWIFT_APPROACHABLE_CONCURRENCY = YES;
				SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor;
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_UPCOMING_FEATURE_MEMBER_IMPORT_VISIBILITY = YES;
				SWIFT_VERSION = 5.0;
			};
			name = Release;
		};
		04A1B2C3D4E5F60000000016 /* Debug */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				CODE_SIGN_ENTITLEMENTS = XrayClientMacTunnel/XrayClientMacTunnel.entitlements;
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = 9QF29ADW72;
				ENABLE_HARDENED_RUNTIME = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_FILE = XrayClientMacTunnel/Info.plist;
				INFOPLIST_KEY_CFBundleDisplayName = XrayClientMacTunnel;
				INFOPLIST_KEY_NSHumanReadableCopyright = "";
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/../Frameworks",
					"@executable_path/../../../../Frameworks",
				);
				MACOSX_DEPLOYMENT_TARGET = 13.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = org.texforge.XrayClientMac.Tunnel;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SDKROOT = macosx;
				SKIP_INSTALL = YES;
				STRING_CATALOG_GENERATE_SYMBOLS = YES;
				SWIFT_APPROACHABLE_CONCURRENCY = YES;
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_UPCOMING_FEATURE_MEMBER_IMPORT_VISIBILITY = YES;
				SWIFT_VERSION = 5.0;
			};
			name = Debug;
		};
		04A1B2C3D4E5F60000000017 /* Release */ = {
			isa = XCBuildConfiguration;
			buildSettings = {
				CODE_SIGN_ENTITLEMENTS = XrayClientMacTunnel/XrayClientMacTunnel.entitlements;
				CODE_SIGN_STYLE = Automatic;
				CURRENT_PROJECT_VERSION = 1;
				DEVELOPMENT_TEAM = 9QF29ADW72;
				ENABLE_HARDENED_RUNTIME = YES;
				GENERATE_INFOPLIST_FILE = YES;
				INFOPLIST_FILE = XrayClientMacTunnel/Info.plist;
				INFOPLIST_KEY_CFBundleDisplayName = XrayClientMacTunnel;
				INFOPLIST_KEY_NSHumanReadableCopyright = "";
				LD_RUNPATH_SEARCH_PATHS = (
					"$(inherited)",
					"@executable_path/../Frameworks",
					"@executable_path/../../../../Frameworks",
				);
				MACOSX_DEPLOYMENT_TARGET = 13.0;
				MARKETING_VERSION = 1.0;
				PRODUCT_BUNDLE_IDENTIFIER = org.texforge.XrayClientMac.Tunnel;
				PRODUCT_NAME = "$(TARGET_NAME)";
				SDKROOT = macosx;
				SKIP_INSTALL = YES;
				STRING_CATALOG_GENERATE_SYMBOLS = YES;
				SWIFT_APPROACHABLE_CONCURRENCY = YES;
				SWIFT_EMIT_LOC_STRINGS = YES;
				SWIFT_UPCOMING_FEATURE_MEMBER_IMPORT_VISIBILITY = YES;
				SWIFT_VERSION = 5.0;
			};
			name = Release;
		};
```

- [ ] **Step 12: Add configuration lists**

In the `XCConfigurationList section`, add:

```pbxproj
		04A1B2C3D4E5F60000000007 /* Build configuration list for PBXNativeTarget "XrayClientMac" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				04A1B2C3D4E5F60000000008 /* Debug */,
				04A1B2C3D4E5F60000000009 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
		04A1B2C3D4E5F60000000015 /* Build configuration list for PBXNativeTarget "XrayClientMacTunnel" */ = {
			isa = XCConfigurationList;
			buildConfigurations = (
				04A1B2C3D4E5F60000000016 /* Debug */,
				04A1B2C3D4E5F60000000017 /* Release */,
			);
			defaultConfigurationIsVisible = 0;
			defaultConfigurationName = Release;
		};
```

- [ ] **Step 13: Add package product dependencies**

In the `XCSwiftPackageProductDependency section`, add:

```pbxproj
		04A1B2C3D4E5F6000000000E /* XrayAppleClient */ = {
			isa = XCSwiftPackageProductDependency;
			package = 044523C32FCA246000EB1099 /* XCLocalSwiftPackageReference "../../apple" */;
			productName = XrayAppleClient;
		};
		04A1B2C3D4E5F6000000001E /* XrayAppleTunnel */ = {
			isa = XCSwiftPackageProductDependency;
			package = 044523C32FCA246000EB1099 /* XCLocalSwiftPackageReference "../../apple" */;
			productName = XrayAppleTunnel;
		};
```

- [ ] **Step 14: Validate the project file**

Run:

```bash
plutil -lint platform/apple/XrayClient/XrayClient.xcodeproj/project.pbxproj
xcodebuild -list -project platform/apple/XrayClient/XrayClient.xcodeproj
```

Expected: `plutil` reports OK, and `xcodebuild -list` includes `XrayClientMac` and `XrayClientMacTunnel` in schemes or targets.

- [ ] **Step 15: Commit**

Run:

```bash
git add platform/apple/XrayClient/XrayClient.xcodeproj/project.pbxproj
git commit -m "feat(apple): wire macOS Xcode targets"
```

---

### Task 5: Document macOS Target Usage

**Files:**
- Modify: `platform/apple/README.md`

- [ ] **Step 1: Add macOS target documentation**

Append this section to `platform/apple/README.md`:

````markdown
## macOS System VPN Target

The Xcode project also contains native macOS targets:

```text
XrayClientMac
XrayClientMacTunnel
```

`XrayClientMac` is a normal macOS app with a main window and a SwiftUI
`MenuBarExtra`. `XrayClientMacTunnel` is the macOS Packet Tunnel extension and
depends on the shared `XrayAppleTunnel` package product.

The default macOS provider bundle identifier follows the same convention as the
iOS and tvOS hosts:

```text
org.texforge.XrayClientMac.Tunnel
```

Build locally without signing checks:

```sh
xcodebuild -project platform/apple/XrayClient/XrayClient.xcodeproj \
  -scheme XrayClientMac \
  -sdk macosx \
  -configuration Debug \
  CODE_SIGNING_ALLOWED=NO \
  build
```

Starting the system VPN requires a signed build with the Packet Tunnel
NetworkExtension entitlement and local user approval in macOS System Settings.
````

- [ ] **Step 2: Commit**

Run:

```bash
git add platform/apple/README.md
git commit -m "docs(apple): document macOS VPN target"
```

---

### Task 6: Verify The macOS App And Existing Apple Targets

**Files:**
- No source edits expected.

- [ ] **Step 1: Run Swift package tests**

Run:

```bash
HOME=target/mobile/apple-swiftpm-home CLANG_MODULE_CACHE_PATH=target/mobile/apple-clang-module-cache swift test --disable-sandbox --package-path platform/apple
```

Expected: PASS.

- [ ] **Step 2: Build the macOS app scheme**

Run:

```bash
xcodebuild -project platform/apple/XrayClient/XrayClient.xcodeproj -scheme XrayClientMac -sdk macosx -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

Expected: BUILD SUCCEEDED.

- [ ] **Step 3: Build the macOS tunnel extension scheme**

Run:

```bash
xcodebuild -project platform/apple/XrayClient/XrayClient.xcodeproj -scheme XrayClientMacTunnel -sdk macosx -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

Expected: BUILD SUCCEEDED.

- [ ] **Step 4: Build the existing iOS app scheme**

Run:

```bash
xcodebuild -project platform/apple/XrayClient/XrayClient.xcodeproj -scheme XrayClient -sdk iphonesimulator -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

Expected: BUILD SUCCEEDED.

- [ ] **Step 5: Build the existing tvOS app scheme**

Run:

```bash
xcodebuild -project platform/apple/XrayClient/XrayClient.xcodeproj -scheme XrayClientTv -sdk appletvsimulator -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

Expected: BUILD SUCCEEDED.

- [ ] **Step 6: Inspect git status**

Run:

```bash
git status --short
```

Expected: only intended source, project, README, and plan files are changed. `xcuserdata` files may remain modified from the user's local Xcode session and should stay unstaged.
