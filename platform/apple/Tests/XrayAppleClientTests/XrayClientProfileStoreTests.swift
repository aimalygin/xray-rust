import Foundation
import XCTest
import XrayAppleShared
@testable import XrayAppleClient

#if canImport(NetworkExtension)
import NetworkExtension
#endif

final class XrayClientProfileStoreTests: XCTestCase {
    func testSavePersistsOnlyOpaqueReferenceInUserDefaults() throws {
        let defaults = try makeDefaults()
        let secureStore = RecordingSecureConfigStore()
        let profile = makeProfile()
        let store = XrayClientProfileStore(
            defaults: defaults,
            key: "profile",
            secureConfigStore: secureStore
        )

        try store.save(profile)

        let persisted = try XCTUnwrap(defaults.data(forKey: "profile"))
        let persistedText = try XCTUnwrap(String(data: persisted, encoding: .utf8))
        XCTAssertFalse(persistedText.contains(Self.vlessUserID))
        XCTAssertFalse(persistedText.contains(profile.configJSON))
        XCTAssertTrue(persistedText.contains("profile."))
        XCTAssertEqual(store.load(), profile)
    }

    func testLoadMigratesLegacyProfileOutOfUserDefaults() throws {
        let defaults = try makeDefaults()
        let secureStore = RecordingSecureConfigStore()
        let profile = makeProfile()
        defaults.set(try JSONEncoder().encode(profile), forKey: "profile")
        let store = XrayClientProfileStore(
            defaults: defaults,
            key: "profile",
            secureConfigStore: secureStore
        )

        XCTAssertEqual(store.load(), profile)

        let migrated = try XCTUnwrap(defaults.data(forKey: "profile"))
        let migratedText = try XCTUnwrap(String(data: migrated, encoding: .utf8))
        XCTAssertFalse(migratedText.contains(Self.vlessUserID))
        XCTAssertEqual(
            try secureStore.configJSON(
                reference: XraySecureConfigReference.profile(profile.id)
            ),
            profile.configJSON
        )
    }

    func testFailedLegacyMigrationRemovesCredentialBearingPreference() throws {
        let defaults = try makeDefaults()
        let profile = makeProfile()
        defaults.set(try JSONEncoder().encode(profile), forKey: "profile")
        let store = XrayClientProfileStore(
            defaults: defaults,
            key: "profile",
            secureConfigStore: FailingSecureConfigStore()
        )

        XCTAssertEqual(store.load(), profile)
        XCTAssertNil(defaults.data(forKey: "profile"))
    }

    func testSavingNewProfileIdentityRemovesPreviousSecureConfiguration() throws {
        let defaults = try makeDefaults()
        let secureStore = RecordingSecureConfigStore()
        let first = makeProfile()
        var second = makeProfile()
        second.id = UUID()
        second.configJSON = #"{"outbounds":[{"protocol":"freedom"}]}"#
        let store = XrayClientProfileStore(
            defaults: defaults,
            key: "profile",
            secureConfigStore: secureStore
        )

        try store.save(first)
        try store.save(second)

        let firstReference = XraySecureConfigReference.profile(first.id)
        let secondReference = XraySecureConfigReference.profile(second.id)
        XCTAssertNil(try secureStore.configJSON(reference: firstReference))
        XCTAssertEqual(
            try secureStore.configJSON(reference: secondReference),
            second.configJSON
        )
        XCTAssertEqual(secureStore.removedReferences, [firstReference])
        XCTAssertEqual(store.load(), second)
    }

    func testObsoleteConfigurationCleanupFailureDoesNotFailCommittedSave() throws {
        let defaults = try makeDefaults()
        let secureStore = FailingRemovalSecureConfigStore()
        let first = makeProfile()
        var second = makeProfile()
        second.id = UUID()
        second.configJSON = #"{"outbounds":[{"protocol":"freedom"}]}"#
        let store = XrayClientProfileStore(
            defaults: defaults,
            key: "profile",
            secureConfigStore: secureStore
        )
        try store.save(first)
        secureStore.failRemovals = true

        XCTAssertNoThrow(try store.save(second))

        let firstReference = XraySecureConfigReference.profile(first.id)
        let secondReference = XraySecureConfigReference.profile(second.id)
        XCTAssertEqual(secureStore.removalAttempts, [firstReference])
        XCTAssertEqual(
            try secureStore.configJSON(reference: firstReference),
            first.configJSON
        )
        XCTAssertEqual(
            try secureStore.configJSON(reference: secondReference),
            second.configJSON
        )
        XCTAssertEqual(store.load(), second)
    }

    @available(macOS 13.0, *)
    func testTunnelSecureTransactionRollbackRemovesNewReference() throws {
        let secureStore = RecordingSecureConfigStore()
        let reference = "tunnel.new"
        let transaction = try XrayTunnelSecureConfigTransaction(
            secureConfigStore: secureStore,
            configJSON: "new-config",
            reference: reference
        )

        transaction.rollback()

        XCTAssertNil(try secureStore.configJSON(reference: reference))
        XCTAssertEqual(secureStore.removedReferences, [reference])
    }

    @available(macOS 13.0, *)
    func testTunnelSecureTransactionRollbackRestoresReplacedConfiguration() throws {
        let secureStore = RecordingSecureConfigStore()
        let reference = "tunnel.existing"
        try secureStore.store(configJSON: "old-config", reference: reference)
        let transaction = try XrayTunnelSecureConfigTransaction(
            secureConfigStore: secureStore,
            configJSON: "new-config",
            reference: reference
        )

        transaction.rollback()

        XCTAssertEqual(
            try secureStore.configJSON(reference: reference),
            "old-config"
        )
        XCTAssertTrue(secureStore.removedReferences.isEmpty)
    }

    @available(macOS 13.0, *)
    func testTunnelSecureTransactionCommitRemovesObsoleteReference() throws {
        let secureStore = RecordingSecureConfigStore()
        try secureStore.store(configJSON: "old-config", reference: "tunnel.old")
        let transaction = try XrayTunnelSecureConfigTransaction(
            secureConfigStore: secureStore,
            configJSON: "new-config",
            reference: "tunnel.new"
        )

        transaction.commit(removingObsoleteReference: "tunnel.old")

        XCTAssertNil(try secureStore.configJSON(reference: "tunnel.old"))
        XCTAssertEqual(
            try secureStore.configJSON(reference: "tunnel.new"),
            "new-config"
        )
        XCTAssertEqual(secureStore.removedReferences, ["tunnel.old"])
    }

    @available(macOS 13.0, *)
    @MainActor
    func testFailedStartRestoresPersistedManagerBeforeSecureRollback() async throws {
        let state = ManagerRollbackState(persistedReference: "tunnel.old")
        let manager = NETunnelProviderManager()
        manager.localizedDescription = "Old manager"
        manager.protocolConfiguration = makeTunnelProtocol(reference: "tunnel.old")
        manager.isEnabled = false
        manager.isOnDemandEnabled = true
        manager.onDemandRules = [NEOnDemandRuleConnect()]

        let preferencesTransaction = XrayTunnelManagerPreferencesTransaction(
            manager: manager,
            wasPersisted: true,
            persistManager: { restoredManager in
                state.events.append("preferences")
                state.persistedReference = Self.tunnelReference(from: restoredManager)
            },
            removeManager: { _ in
                throw ManagerRollbackTestError.unexpectedRemoval
            }
        )

        manager.localizedDescription = "New manager"
        manager.protocolConfiguration = makeTunnelProtocol(reference: "tunnel.new")
        manager.isEnabled = true
        manager.isOnDemandEnabled = false
        manager.onDemandRules = nil
        state.persistedReference = "tunnel.new"

        let secureStore = RecordingSecureConfigStore()
        try secureStore.store(configJSON: "old-config", reference: "tunnel.old")
        let secureTransaction = try XrayTunnelSecureConfigTransaction(
            secureConfigStore: secureStore,
            configJSON: "new-config",
            reference: "tunnel.new"
        )

        let rolledBack = await NetworkExtensionTunnelController.rollbackFailedStart(
            preferencesTransaction: preferencesTransaction,
            secureRollback: {
                state.events.append("secure-config")
                secureTransaction.rollback()
            }
        )

        XCTAssertTrue(rolledBack)
        XCTAssertEqual(preferencesTransaction.rollbackKind, .restoreExisting)
        XCTAssertEqual(state.events, ["preferences", "secure-config"])
        XCTAssertEqual(state.persistedReference, "tunnel.old")
        XCTAssertEqual(manager.localizedDescription, "Old manager")
        XCTAssertEqual(Self.tunnelReference(from: manager), "tunnel.old")
        XCTAssertFalse(manager.isEnabled)
        XCTAssertTrue(manager.isOnDemandEnabled)
        XCTAssertEqual(manager.onDemandRules?.count, 1)
        XCTAssertEqual(
            try secureStore.configJSON(reference: "tunnel.old"),
            "old-config"
        )
        XCTAssertNil(try secureStore.configJSON(reference: "tunnel.new"))
    }

    @available(macOS 13.0, *)
    @MainActor
    func testFailedStartRemovesNewManagerBeforeSecureRollback() async throws {
        let state = ManagerRollbackState(persistedReference: nil)
        let manager = NETunnelProviderManager()
        let preferencesTransaction = XrayTunnelManagerPreferencesTransaction(
            manager: manager,
            wasPersisted: false,
            persistManager: { _ in
                throw ManagerRollbackTestError.unexpectedPersistence
            },
            removeManager: { _ in
                state.events.append("preferences")
                state.persistedReference = nil
            }
        )

        manager.localizedDescription = "New manager"
        manager.protocolConfiguration = makeTunnelProtocol(reference: "tunnel.new")
        manager.isEnabled = true
        state.persistedReference = "tunnel.new"

        let secureStore = RecordingSecureConfigStore()
        let secureTransaction = try XrayTunnelSecureConfigTransaction(
            secureConfigStore: secureStore,
            configJSON: "new-config",
            reference: "tunnel.new"
        )

        let rolledBack = await NetworkExtensionTunnelController.rollbackFailedStart(
            preferencesTransaction: preferencesTransaction,
            secureRollback: {
                state.events.append("secure-config")
                secureTransaction.rollback()
            }
        )

        XCTAssertTrue(rolledBack)
        XCTAssertEqual(preferencesTransaction.rollbackKind, .removeNew)
        XCTAssertEqual(state.events, ["preferences", "secure-config"])
        XCTAssertNil(state.persistedReference)
        XCTAssertNil(try secureStore.configJSON(reference: "tunnel.new"))
    }

    @available(macOS 13.0, *)
    @MainActor
    func testFailedPreferenceRollbackRetainsReferencedSecureConfiguration() async throws {
        let state = ManagerRollbackState(persistedReference: "tunnel.new")
        let manager = NETunnelProviderManager()
        manager.protocolConfiguration = makeTunnelProtocol(reference: "tunnel.old")
        let preferencesTransaction = XrayTunnelManagerPreferencesTransaction(
            manager: manager,
            wasPersisted: true,
            persistManager: { _ in
                state.events.append("preferences")
                throw ManagerRollbackTestError.persistenceFailed
            },
            removeManager: { _ in
                throw ManagerRollbackTestError.unexpectedRemoval
            }
        )
        manager.protocolConfiguration = makeTunnelProtocol(reference: "tunnel.new")

        let secureStore = RecordingSecureConfigStore()
        let secureTransaction = try XrayTunnelSecureConfigTransaction(
            secureConfigStore: secureStore,
            configJSON: "new-config",
            reference: "tunnel.new"
        )

        let rolledBack = await NetworkExtensionTunnelController.rollbackFailedStart(
            preferencesTransaction: preferencesTransaction,
            secureRollback: {
                state.events.append("secure-config")
                secureTransaction.rollback()
            }
        )

        XCTAssertFalse(rolledBack)
        XCTAssertEqual(state.events, ["preferences"])
        XCTAssertEqual(
            try secureStore.configJSON(reference: "tunnel.new"),
            "new-config"
        )
    }

    @available(macOS 13.0, *)
    @MainActor
    func testTunnelStartOptionsContainReferenceInsteadOfConfiguration() {
        let profile = makeProfile()
        let options = NetworkExtensionTunnelController.startTunnelOptions(
            for: profile,
            configReference: "opaque-reference"
        )

        XCTAssertEqual(
            options[XrayTunnelProviderMessage.configReferenceOptionKey] as? String,
            "opaque-reference"
        )
        XCTAssertFalse(options.values.contains { "\($0)".contains(Self.vlessUserID) })
    }

    private func makeDefaults() throws -> UserDefaults {
        let suiteName = "org.xrayrust.profile-store-tests.\(UUID().uuidString)"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }

    private func makeProfile() -> XrayClientProfile {
        XrayClientProfile(
            name: "Secure",
            providerBundleIdentifier: "org.example.Tunnel",
            serverAddress: "203.0.113.10",
            configJSON: """
            {"outbounds":[{"protocol":"vless","settings":{"vnext":[{"users":[{"id":"\(Self.vlessUserID)"}]}]}}]}
            """
        )
    }

    @available(macOS 13.0, *)
    @MainActor
    private func makeTunnelProtocol(reference: String) -> NETunnelProviderProtocol {
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = "org.example.Tunnel"
        tunnelProtocol.serverAddress = "203.0.113.10"
        tunnelProtocol.providerConfiguration = [
            XrayTunnelProviderMessage.providerConfigReferenceKey: reference,
        ]
        return tunnelProtocol
    }

    @available(macOS 13.0, *)
    @MainActor
    private static func tunnelReference(
        from manager: NETunnelProviderManager
    ) -> String? {
        let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol
        return tunnelProtocol?.providerConfiguration?[
            XrayTunnelProviderMessage.providerConfigReferenceKey
        ] as? String
    }

    private static let vlessUserID = "11111111-1111-4111-8111-111111111111"
}

@available(macOS 13.0, *)
@MainActor
private final class ManagerRollbackState {
    var persistedReference: String?
    var events: [String] = []

    init(persistedReference: String?) {
        self.persistedReference = persistedReference
    }
}

private enum ManagerRollbackTestError: Error {
    case persistenceFailed
    case unexpectedPersistence
    case unexpectedRemoval
}

private final class FailingRemovalSecureConfigStore: XraySecureConfigStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]
    private var attempts: [String] = []
    private var shouldFailRemovals = false

    var failRemovals: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return shouldFailRemovals
        }
        set {
            lock.lock()
            shouldFailRemovals = newValue
            lock.unlock()
        }
    }

    var removalAttempts: [String] {
        lock.lock()
        defer { lock.unlock() }
        return attempts
    }

    func store(configJSON: String, reference: String) throws {
        lock.lock()
        values[reference] = configJSON
        lock.unlock()
    }

    func configJSON(reference: String) throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        return values[reference]
    }

    func remove(reference: String) throws {
        lock.lock()
        defer { lock.unlock() }
        attempts.append(reference)
        if shouldFailRemovals {
            throw CocoaError(.fileWriteUnknown)
        }
        values.removeValue(forKey: reference)
    }
}

private final class FailingSecureConfigStore: XraySecureConfigStoring, @unchecked Sendable {
    func store(configJSON: String, reference: String) throws {
        throw CocoaError(.fileWriteNoPermission)
    }

    func configJSON(reference: String) throws -> String? {
        nil
    }

    func remove(reference: String) throws {}
}

private final class RecordingSecureConfigStore: XraySecureConfigStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [String: String] = [:]
    private var removals: [String] = []

    var removedReferences: [String] {
        lock.lock()
        defer { lock.unlock() }
        return removals
    }

    func store(configJSON: String, reference: String) throws {
        lock.lock()
        values[reference] = configJSON
        lock.unlock()
    }

    func configJSON(reference: String) throws -> String? {
        lock.lock()
        defer { lock.unlock() }
        return values[reference]
    }

    func remove(reference: String) throws {
        lock.lock()
        values.removeValue(forKey: reference)
        removals.append(reference)
        lock.unlock()
    }
}
