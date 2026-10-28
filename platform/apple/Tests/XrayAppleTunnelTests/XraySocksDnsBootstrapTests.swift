import XCTest
import XrayAppleShared
import XrayMobileAdapter
@testable import XrayAppleTunnel

@available(macOS 13.0, *)
final class XraySocksDnsBootstrapTests: XCTestCase {
    func testPinsBothFormsWithoutResolvingDestinationsOrChangingCredentialsAndTLS() throws {
        for legacy in [false, true] {
            let json = config(address: " Socks.Example. ", legacy: legacy)
            var queries: [String] = []
            let prepared = try prepare(json) { domain in
                queries.append(domain)
                return ["2001:db8::8", "192.0.2.8"]
            }
            XCTAssertEqual(queries, ["socks.example"])
            let original = try object(json)
            let root = try object(prepared.json)
            XCTAssertEqual(root["outbounds"] as? NSArray, original["outbounds"] as? NSArray)
            XCTAssertEqual(root["routing"] as? NSDictionary, original["routing"] as? NSDictionary)
            let hosts = try XCTUnwrap((root["dns"] as? NSDictionary)?["hosts"] as? NSDictionary)
            XCTAssertEqual(hosts["full:socks.example"] as? [String], ["2001:db8::8", "192.0.2.8"])
            XCTAssertEqual(prepared.excludedServerAddresses, ["2001:db8::8", "192.0.2.8"])
            XCTAssertNoThrow(try XrayPacketTunnelProvider.validateConfigBeforeApplyingNetworkSettings(
                prepared.json, geodataSelection: .init(directory: nil, policy: .fallbackToDefaults)
            ))
        }
    }

    func testExistingStaticHostsAndAliasesSkipSystemLookup() throws {
        for legacy in [false, true] {
            for target: Any in [["2001:db8::8", "192.0.2.8"], "Alias.Example."] {
                let json = try withHosts(config(address: "Socks.Example.", legacy: legacy), hosts: [
                    "Socks.Example.": target, "alias.example": ["2001:db8::8", "192.0.2.8"],
                ])
                let prepared = try prepare(json)
                XCTAssertEqual(prepared.excludedServerAddresses, ["2001:db8::8", "192.0.2.8"])
            }
        }
    }

    func testLiteralsIncludingBracketedIPv6SkipLookupAndExcludeCarrierRoutes() throws {
        for legacy in [false, true] {
            for (address, expected) in [
                ("192.0.2.8", "192.0.2.8"), (" 192.0.2.8 ", "192.0.2.8"),
                ("[192.0.2.8]", "192.0.2.8"), ("2001:db8::8", "2001:db8::8"),
                ("[2001:db8::8]", "2001:db8::8"), ("::ffff:192.0.2.8", "192.0.2.8"),
            ] {
                let prepared = try prepare(config(address: address, legacy: legacy))
                XCTAssertEqual(prepared.excludedServerAddresses, [expected], address)
            }
        }
    }

    func testRejectsTunnelOwnedLiteralResolvedAndAliasedCarriers() throws {
        for legacy in [false, true] {
            for address in ["198.18.0.1", "198.18.0.2", "fd00:7872::2", "::ffff:198.18.0.1"] {
                XCTAssertThrowsError(try prepare(config(address: address, legacy: legacy)))
                XCTAssertThrowsError(try prepare(config(address: "socks.example", legacy: legacy)) { _ in [address] })
                let json = try withHosts(config(address: "socks.example", legacy: legacy), hosts: [
                    "socks.example": "alias.example", "alias.example": address,
                ])
                XCTAssertThrowsError(try prepare(json))
            }
            XCTAssertThrowsError(try prepare(config(address: "[fd00:7872::2]", legacy: legacy)))
        }
    }

    func testLookupFailureFailsPreparation() throws {
        for legacy in [false, true] {
            XCTAssertThrowsError(try prepare(config(address: "socks.example", legacy: legacy)) { _ in nil })
        }
    }

    private func config(address: String, legacy: Bool) -> String {
        let settings = legacy
            ? #"{"servers":[{"address":"\#(address)","port":1080,"users":[{"user":"synthetic-user","pass":"synthetic-secret"}]}]}"#
            : #"{"address":"\#(address)","port":1080,"user":"synthetic-user","pass":"synthetic-secret"}"#
        return #"""
            {"inbounds":[{"tag":"tun-in","protocol":"tun","settings":{}}],"dns":{"servers":["192.0.2.53"]},
             "outbounds":[{"tag":"proxy","protocol":"socks","settings":\#(settings),
               "streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"tls.example"}}}],
             "routing":{"rules":[{"type":"field","domain":["full:destination.example"],"outboundTag":"proxy"}]}}
            """#
    }

    private func object(_ json: String) throws -> NSDictionary {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? NSDictionary)
    }

    private func withHosts(_ json: String, hosts: [String: Any]) throws -> String {
        var root = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        root["dns"] = ["servers": ["192.0.2.53"], "hosts": hosts]
        return String(decoding: try JSONSerialization.data(withJSONObject: root), as: UTF8.self)
    }

    private func prepare(
        _ json: String,
        resolveAddress: (String) -> [String]? = { _ in XCTFail("unexpected system DNS lookup"); return nil }
    ) throws -> XrayPacketTunnelProvider.ResolvedConfig {
        try XrayPacketTunnelProvider.configPinningOutboundServerAddresses(
            .init(
                json: json, source: "test", serverAddress: nil, debugLoggingEnabled: false,
                useTunFileDescriptor: true, tunRuntimeProfile: .default,
                startupProbeConfiguration: .disabled, dnsConfiguration: .system,
                geodataSelection: .init(directory: nil, policy: .fallbackToDefaults)
            ),
            resolveAddress: resolveAddress
        )
    }
}
