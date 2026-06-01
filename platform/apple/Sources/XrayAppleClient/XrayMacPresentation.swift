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
