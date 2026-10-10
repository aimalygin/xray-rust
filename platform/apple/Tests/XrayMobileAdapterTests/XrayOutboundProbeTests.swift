import Network
import XCTest
import XrayRust
@testable import XrayMobileAdapter

final class XrayOutboundProbeTests: XCTestCase {
    private let config = #"{"inbounds":[{"protocol":"socks","listen":"127.0.0.1","port":0,"settings":{"udp":false}}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}"#

    func testEmbeddedNULIsRejectedBeforeTheCBridge() throws {
        let core = try XrayCore(configJSON: config)
        try core.start()
        defer { try? core.stop() }
        for (url, tag) in [
            ("http://127.0.0.1:9/\u{0}secret", "direct"),
            ("http://127.0.0.1:9/", "direct\u{0}missing"),
        ] {
            XCTAssertThrowsError(try core.probeOutboundURL(url, outboundTag: tag)) { error in
                guard case let XrayCoreError.status(code, message) = error else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertEqual(code, XRAY_STATUS_INVALID_ARGUMENT)
                XCTAssertFalse(message.contains("secret"))
                XCTAssertFalse(message.contains("missing"))
            }
        }
    }

    func testStopCancelsStalledSixtySecondProbe() throws {
        let server = try StalledProbeServer()
        defer { server.close() }
        wait(for: [server.ready], timeout: 5)
        let port = try XCTUnwrap(server.listener.port)
        let core = try XrayCore(configJSON: config)
        try core.start()
        let finished = expectation(description: "probe cancelled")
        DispatchQueue.global().async {
            defer { finished.fulfill() }
            do {
                _ = try core.probeOutboundURL("http://127.0.0.1:\(port.rawValue)/", timeoutMs: 60_000)
                XCTFail("stalled probe must be cancelled")
            } catch {
                guard case let XrayCoreError.status(code, _) = error else {
                    return XCTFail("unexpected error: \(error)")
                }
                XCTAssertEqual(code, XRAY_STATUS_RUNTIME_ERROR)
            }
        }
        wait(for: [server.accepted], timeout: 5)
        let started = Date()
        try core.stop()
        XCTAssertLessThan(Date().timeIntervalSince(started), 2)
        wait(for: [finished], timeout: 2)
    }
}

private final class StalledProbeServer {
    let ready = XCTestExpectation(description: "server listening")
    let accepted = XCTestExpectation(description: "probe connected")
    let listener: NWListener
    private let queue = DispatchQueue(label: "xray.test.stalled-probe")
    private var connection: NWConnection?

    init() throws {
        listener = try NWListener(using: .tcp, on: .any)
        listener.stateUpdateHandler = { [weak self] state in
            if case .ready = state { self?.ready.fulfill() }
        }
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { return }
            self.connection = connection
            connection.start(queue: self.queue)
            self.accepted.fulfill()
        }
        listener.start(queue: queue)
    }

    func close() {
        queue.sync {
            connection?.cancel()
            listener.cancel()
        }
    }
}
