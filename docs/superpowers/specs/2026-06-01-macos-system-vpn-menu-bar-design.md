# macOS System VPN With Menu Bar Design

## Goal

Add a native macOS client to the existing Apple project that runs Xray as a system VPN through NetworkExtension and exposes a persistent menu bar control for day-to-day connect, disconnect, status, and window access.

## Current Context

The repository already has a Swift package under `platform/apple` with reusable Apple components:

- `XrayMobileAdapter` wraps the Rust `xray-ffi` XCFramework.
- `XrayAppleShared` owns shared profile, status, stats, and host-to-extension message types.
- `XrayAppleClient` owns profile persistence, config validation, `NETunnelProviderManager` control-plane wiring, and the current SwiftUI root view.
- `XrayAppleTunnel` owns the reusable `NEPacketTunnelProvider` implementation.

The package already declares macOS support and the XCFramework build script already includes an `aarch64-apple-darwin` slice. The missing piece is a macOS app target and a macOS Packet Tunnel extension target in the Xcode project.

## Requirements

- Add a native macOS app target named `XrayClientMac`.
- Add a macOS Packet Tunnel extension target named `XrayClientMacTunnel`.
- Use system VPN behavior through `NETunnelProviderManager` and `NEPacketTunnelProvider`, not a local-only proxy.
- Add a menu bar icon using SwiftUI `MenuBarExtra`.
- Keep a regular app window for profile editing, JSON config editing, diagnostics, and manual control.
- Reuse the existing Swift package products instead of duplicating tunnel or Rust FFI code.
- Keep iOS and tvOS targets working unchanged.

## Recommended Approach

Create a macOS-specific app shell around the existing shared client/tunnel libraries:

- `XrayClientMac.app` depends on `XrayAppleClient`.
- `XrayClientMacTunnel.appex` depends on `XrayAppleTunnel`.
- The app remains a normal Dock app in the first version and also inserts a menu bar extra.
- The menu bar extra provides fast controls; the main window provides full editing and diagnostics.

This is preferable to making the app menu-bar-only because the project is still in active development and a visible main app is easier to debug, provision, and test. A later preference can hide the Dock icon if that becomes desirable.

## Targets And Bundle IDs

Use dedicated macOS bundle identifiers:

- App: `org.texforge.XrayClientMac`
- Packet Tunnel extension: `org.texforge.XrayClientMac.Tunnel`

The existing profile default-provider logic derives the tunnel provider identifier as `<host bundle id>.Tunnel`, so the macOS app can reuse that convention without special casing.

## App Scene Design

The macOS app should define:

- `WindowGroup` for the main app window.
- `MenuBarExtra` for the persistent menu bar icon and menu.
- `Settings` for macOS preferences.

The main window should set a sensible minimum and default size:

- minimum: approximately `720 x 480`
- default: approximately `980 x 640`
- `windowResizability(.contentMinSize)`
- unified toolbar styling

The minimum platform for the macOS app should be macOS 13.0, matching the existing shared root view availability and `MenuBarExtra`.

## Main Window UI

The macOS-specific root view should use `NavigationSplitView`:

- Sidebar: connection status, active profile summary, and basic profile fields.
- Detail: JSON config editor, runtime stats, and validation or tunnel errors.
- Toolbar: Connect/Disconnect, Save, and Refresh.

The existing `XrayClientRootView` remains for iOS/tvOS compatibility. macOS gets a new `XrayMacRootView` that reuses `XrayClientViewModel` but presents it with Mac-specific layout. This keeps the current mobile UI stable while making the Mac app feel native.

## Menu Bar Extra

The menu bar extra should use SwiftUI `MenuBarExtra` with a status-oriented SF Symbol:

- connected: `network`
- disconnected: `network.slash`
- busy: `arrow.triangle.2.circlepath`
- issue: `exclamationmark.triangle`

The menu should include:

- current status text
- Connect or Disconnect
- Refresh
- runtime stats when connected
- Open Xray
- Settings
- Quit

The menu bar controls should talk to the same shared `XrayClientViewModel` as the main window so status changes stay consistent.

## State And Data Flow

Use one main actor state owner for the macOS app session:

- `XrayClientMacApp` owns one `@StateObject` `XrayClientViewModel`.
- The main window receives the model through initializer injection into `XrayMacRootView`.
- The menu bar extra receives the same model through initializer injection into `XrayMacMenuBarView`.
- Connect, disconnect, save, refresh, VLESS import, and stats retrieval continue to flow through `XrayClientViewModel`.
- The model continues to use `NetworkExtensionTunnelController`, which persists a `NETunnelProviderManager` and starts the provider with the current profile.
- The tunnel extension receives the profile config via start options and provider configuration, then starts `XrayCore` through `XrayAppleTunnel`.

This keeps NetworkExtension wiring in one place and prevents the menu bar extra from inventing a second control path.

## Entitlements And Provisioning

The macOS app and extension need packet tunnel NetworkExtension entitlements:

- `com.apple.developer.networking.networkextension = packet-tunnel-provider`

The first macOS implementation does not add an app group because the current start options and provider configuration already pass the needed tunnel config. App-group storage can be added later only if the host and extension need shared persisted state.

Apple Developer provisioning and signing remain local setup requirements. The repository can add target files, entitlements, and project configuration, but it cannot create developer-account provisioning profiles.

## Error Handling

Errors should surface in both places:

- The main window shows detailed validation, save, and tunnel errors in the diagnostics/detail area.
- The menu bar extra shows a compact issue row and keeps the app icon in an issue state.

Connect/Disconnect actions should be disabled while the shared model is busy. Refresh failures should not clear the existing profile.

## Testing And Verification

Implementation should verify:

- `swift test --disable-sandbox --package-path platform/apple` for shared package behavior.
- Xcode build for the new `XrayClientMac` scheme.
- Xcode build for the new `XrayClientMacTunnel` extension target.
- Existing iOS/tvOS schemes still build.
- The macOS app launches, inserts the menu bar extra, opens the main window, and can save/refresh profile state.

Full VPN activation requires valid local macOS NetworkExtension signing and user approval in System Settings. Automated verification should cover build and non-privileged UI behavior; live VPN start can be a manual signed-build check.

## Out Of Scope

- Hiding the Dock icon by making the app menu-bar-only.
- Reworking the Rust runtime or TUN packet pump.
- Adding multi-profile management beyond the existing single stored profile.
- Shipping App Store-ready provisioning or notarization automation.
- Replacing the existing iOS/tvOS UI.

## Acceptance Criteria

- A macOS app target and macOS Packet Tunnel extension target exist in the Apple Xcode project.
- The macOS app links the existing shared Apple package products.
- The macOS app has a visible main window and a menu bar icon.
- The menu bar menu can trigger connect/disconnect, refresh, open window, settings, and quit.
- The macOS tunnel provider uses the existing `XrayPacketTunnelProvider`.
- Existing iOS/tvOS targets remain intact.
