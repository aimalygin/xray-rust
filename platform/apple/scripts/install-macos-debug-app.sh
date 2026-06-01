#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APPLE_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
PROJECT_PATH="$APPLE_DIR/XrayClient/XrayClient.xcodeproj"

SCHEME="${XRAY_MACOS_SCHEME:-XrayClientMac}"
CONFIGURATION="${XRAY_MACOS_CONFIGURATION:-Debug}"
SDK="${XRAY_MACOS_SDK:-macosx}"
DERIVED_DATA_PATH="${XRAY_MACOS_DERIVED_DATA_PATH:-${TMPDIR:-/tmp}/xray-rust-macos-debug-derived-data}"
INSTALL_DIR="${XRAY_MACOS_INSTALL_DIR:-/Applications}"
APP_NAME="XrayClientMac.app"
TUNNEL_NAME="XrayClientMacTunnel.appex"
BUILT_APP="$DERIVED_DATA_PATH/Build/Products/$CONFIGURATION/$APP_NAME"
INSTALL_APP="$INSTALL_DIR/$APP_NAME"
BUILT_TUNNEL="$BUILT_APP/Contents/PlugIns/$TUNNEL_NAME"
INSTALL_TUNNEL="$INSTALL_APP/Contents/PlugIns/$TUNNEL_NAME"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister"
CODE_SIGN_IDENTITY="${XRAY_MACOS_CODE_SIGN_IDENTITY:-Apple Development}"

echo "Building $SCHEME ($CONFIGURATION) with signing enabled..."
xcodebuild \
  -project "$PROJECT_PATH" \
  -scheme "$SCHEME" \
  -sdk "$SDK" \
  -configuration "$CONFIGURATION" \
  -derivedDataPath "$DERIVED_DATA_PATH" \
  CODE_SIGNING_ALLOWED=YES \
  CODE_SIGN_IDENTITY="$CODE_SIGN_IDENTITY" \
  ENABLE_DEBUG_DYLIB=NO \
  "$@" \
  build

if [[ ! -d "$BUILT_APP" ]]; then
  echo "error: expected app was not built at $BUILT_APP" >&2
  exit 1
fi

if [[ ! -d "$BUILT_TUNNEL" ]]; then
  echo "error: expected embedded tunnel was not built at $BUILT_TUNNEL" >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR"

if [[ -e "$INSTALL_APP" ]]; then
  case "$INSTALL_APP" in
    */XrayClientMac.app) rm -rf "$INSTALL_APP" ;;
    *)
      echo "error: refusing to replace unexpected install path: $INSTALL_APP" >&2
      exit 1
      ;;
  esac
fi

echo "Installing $APP_NAME to $INSTALL_APP..."
/usr/bin/ditto "$BUILT_APP" "$INSTALL_APP"

echo "Registering $APP_NAME with LaunchServices..."
"$LSREGISTER" -f -R -trusted "$INSTALL_APP"

PROVIDER_BUNDLE_ID="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$INSTALL_TUNNEL/Contents/Info.plist")"
PLUGIN_MATCHES="$(/usr/bin/pluginkit -m -A -p com.apple.networkextension.packet-tunnel -i "$PROVIDER_BUNDLE_ID" -v || true)"

if [[ "$PLUGIN_MATCHES" == *"$PROVIDER_BUNDLE_ID"* ]]; then
  echo "PlugInKit found packet tunnel provider: $PROVIDER_BUNDLE_ID"
else
  cat >&2 <<EOF
warning: PlugInKit did not find packet tunnel provider $PROVIDER_BUNDLE_ID.
Make sure both the app and the tunnel extension are sandboxed and signed with
the Packet Tunnel NetworkExtension entitlement.
EOF
fi

cat <<EOF

Installed:
  $INSTALL_APP

Next:
  1. Quit any XrayClientMac copy launched from Xcode DerivedData.
  2. Open $INSTALL_APP.
  3. In Xcode, use Debug > Attach to Process by PID or Name... and enter XrayClientMacTunnel.
  4. Press Connect in the installed app.

If macOS still reports that the VPN app is not installed, delete the old
"Xray Rust" VPN entry in System Settings > VPN, then press Connect again.
EOF
