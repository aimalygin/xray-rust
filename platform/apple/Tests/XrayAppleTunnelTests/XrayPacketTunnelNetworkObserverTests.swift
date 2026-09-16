import XCTest
@testable import XrayAppleTunnel

final class XrayPacketTunnelNetworkObserverTests: XCTestCase {
    func testBurstCoalescesWithoutLosingLaterChange() {
        let first = expectation(description: "coalesced first burst")
        let later = expectation(description: "later network change")
        let count = Count()
        let scheduler = XrayPacketTunnelRebindScheduler(
            queue: DispatchQueue(label: "test.path.burst"), delay: .milliseconds(20)
        ) {
            switch count.increment() {
            case 1: first.fulfill()
            case 2: later.fulfill()
            default: XCTFail("unexpected repeated rebind")
            }
        }
        for _ in 0..<100 { scheduler.schedule() }
        wait(for: [first], timeout: 2)
        scheduler.schedule()
        wait(for: [later], timeout: 2)
        scheduler.stop()
    }

    func testSameCarrierIgnoresAddressOrderingButKeepsRealChanges() {
        var tracker = XrayPacketTunnelCarrierTracker()
        func path(_ name: String = "en0", _ index: Int = 4,
                  _ addresses: [String] = ["192.0.2.1", "2001:db8::1"]) -> XrayPacketTunnelCarrierSignature {
            .init(interfaceName: name, interfaceIndex: index, addresses: addresses)
        }
        XCTAssertTrue(tracker.update(path()))
        for _ in 0..<100 {
            XCTAssertFalse(tracker.update(path("en0", 4, ["2001:db8::1", "192.0.2.1", "192.0.2.1"])))
        }
        XCTAssertTrue(tracker.update(path("pdp_ip0", 5, ["192.0.2.2"])))
        XCTAssertTrue(tracker.update(path()))
        XCTAssertTrue(tracker.update(path("en0", 4, ["192.0.2.3", "2001:db8::1"])))
        XCTAssertTrue(tracker.update(path("en0", 4, ["192.0.2.3", "2001:db8::2"])))
        XCTAssertTrue(tracker.update(path("en0", 8, ["192.0.2.3", "2001:db8::2"])))
    }

    func testOfflineThenSameCarrierStillRebinds() {
        var tracker = XrayPacketTunnelCarrierTracker()
        let path = XrayPacketTunnelCarrierSignature(interfaceName: "en0", interfaceIndex: 4, addresses: ["192.0.2.1"])
        XCTAssertTrue(tracker.update(path))
        XCTAssertFalse(tracker.update(nil))
        XCTAssertFalse(tracker.update(nil))
        XCTAssertTrue(tracker.update(path))
        XCTAssertFalse(tracker.update(path))
    }

    func testOfflineCancelsPendingRebindAndAllowsRecovery() {
        let queue = DispatchQueue(label: "test.path.offline")
        let count = Count()
        let recovered = expectation(description: "same interface is available again")
        let scheduler = XrayPacketTunnelRebindScheduler(queue: queue, delay: .milliseconds(20)) {
            XCTAssertEqual(count.increment(), 1)
            recovered.fulfill()
        }
        queue.suspend()
        scheduler.schedule()
        scheduler.cancelPending()
        queue.resume()
        let offlineDrained = expectation(description: "cancelled callback deadline passed")
        queue.asyncAfter(deadline: .now() + .milliseconds(60)) { offlineDrained.fulfill() }
        wait(for: [offlineDrained], timeout: 2)
        XCTAssertEqual(count.current, 0)
        scheduler.schedule()
        wait(for: [recovered], timeout: 2)
        scheduler.stop()
    }

    func testStopFencesPendingAndFutureCallbacks() {
        let queue = DispatchQueue(label: "test.path.stop")
        let unexpected = expectation(description: "stopped observer must not rebind")
        unexpected.isInverted = true
        let scheduler = XrayPacketTunnelRebindScheduler(queue: queue, delay: .milliseconds(20)) {
            unexpected.fulfill()
        }
        scheduler.schedule()
        scheduler.stop()
        scheduler.schedule()
        wait(for: [unexpected], timeout: 0.1)
    }
}

private final class Count: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    var current: Int {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        value += 1
        return value
    }
}
