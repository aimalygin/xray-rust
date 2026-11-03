"""Apply the 0.8.1 ios-projection-harness/provider patches to the v0.9 worktree."""
import pathlib, sys
W = pathlib.Path(sys.argv[1])
probe = W / "platform/apple/Sources/XrayAppleClient/Debug/XrayProtocolDeviceProbe.swift"
provider = W / "platform/apple/XrayClient/Tunnel/PacketTunnelProvider.swift"
s = probe.read_text()
old = "debugLoggingEnabled: false, useTunFileDescriptor: true, tunRuntimeProfile: .mobile)"
assert s.count(old) == 1
s = s.replace(old, 'debugLoggingEnabled: false, useTunFileDescriptor: ProcessInfo.processInfo.environment["XRAY_PROJECTION_PACKET_PUMP"] != "1", tunRuntimeProfile: .mobile)')
old = "    private func sample(cycle: Int, stage: String) async throws {\n"
assert s.count(old) == 1
s = s.replace(old, old + '''        if ProcessInfo.processInfo.environment["XRAY_ADAPTER_PROJECTION_DEVICE_CHECK"] == "1" {
            guard let counts = try await controller.protocolProbeCPU(),
                  let tcp = counts["admissionTCP"], let udp = counts["admissionUDP"], tcp > 0, udp > 0,
                  counts["invalidTuples"] == 0 else { throw Failure.configuration }
            emit(["event": "host-adapter-projection", "result": "passed", "tcpCallbacks": tcp,
                  "udpCallbacks": udp, "stage": stage,
                  "backend": ProcessInfo.processInfo.environment["XRAY_PROJECTION_PACKET_PUMP"] == "1" ? "packet-pump" : "file-descriptor"])
        }
''')
probe.write_text(s)
p = provider.read_text()
def rep(old, new):
    global p
    assert p.count(old) == 1, old
    p = p.replace(old, new)
rep("import XrayAppleTunnel\n", "import XrayAppleTunnel\nimport XrayMobileAdapter\n")
rep("final class PacketTunnelProvider: XrayPacketTunnelProvider {\n#if DEBUG\n",
    "final class PacketTunnelProvider: XrayPacketTunnelProvider {\n#if DEBUG\n    private let projection = ProjectionCounters()\n"
    "    override func tunAdmissionOptions() throws -> XrayTunAdmissionOptions? {\n        let counters = projection\n"
    "        return try XrayTunAdmissionOptions { flow in counters.record(flow); return true }\n    }\n")
rep('''        completionHandler?(try? JSONSerialization.data(withJSONObject: [
            "userSeconds": user, "systemSeconds": system,
            "uptime": ProcessInfo.processInfo.systemUptime, "pid": Double(getpid())
        ]))
''', '''        var values = projection.snapshot()
        values["userSeconds"] = user; values["systemSeconds"] = system
        values["uptime"] = ProcessInfo.processInfo.systemUptime; values["pid"] = Double(getpid())
        completionHandler?(try? JSONSerialization.data(withJSONObject: values))
''')
p += '''
#if DEBUG
private final class ProjectionCounters: @unchecked Sendable {
    private let lock = NSLock()
    private var tcp = 0, udp = 0, invalid = 0
    func record(_ flow: XrayTunFlow) {
        lock.lock(); defer { lock.unlock() }
        if flow.protocolNumber == 6 { tcp += 1 }
        if flow.protocolNumber == 17 { udp += 1 }
        let length = flow.addressFamily == 4 ? 4 : (flow.addressFamily == 6 ? 16 : 0)
        if length == 0 || flow.sourceAddress.count != length || flow.destinationAddress.count != length
            || flow.sourcePort == 0 || flow.destinationPort == 0 { invalid += 1 }
    }
    func snapshot() -> [String: Double] {
        lock.lock(); defer { lock.unlock() }
        return ["admissionTCP": Double(tcp), "admissionUDP": Double(udp), "invalidTuples": Double(invalid)]
    }
}
#endif
'''
provider.write_text(p)
print("applied")
