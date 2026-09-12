import Combine
import Foundation
import Security

// Senha de acesso — troque aqui para mudar
private let kAccessPassword = "tefvx"

@MainActor
final class LicenseManager: ObservableObject {

    @Published private(set) var isActive = false
    @Published private(set) var isBusy = false
    @Published private(set) var message: String?
    @Published private(set) var contactOwner: String? = nil
    @Published var rememberKey = true

    private let service  = "com.tefvx.external-ios.activation"
    private let keyAccount = "license-key"

    init() {
        if let stored = string(for: keyAccount), stored == kAccessPassword {
            isActive = true
        }
    }

    var hasRememberedKey: Bool {
        if let stored = string(for: keyAccount), !stored.isEmpty { return true }
        return false
    }

    func beginLaunchSession() {
        if let saved = string(for: keyAccount), saved == kAccessPassword {
            isActive = true
            message  = nil
        } else {
            isActive = false
        }
    }

    func activate(key: String, isAutoLogin: Bool = false) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }

        if trimmed == kAccessPassword {
            isActive = true
            message  = nil
            if rememberKey { save(trimmed, for: keyAccount) }
        } else {
            isActive = false
            message  = "Invalid license key"
        }
    }

    func rememberedKey() -> String? { string(for: keyAccount) }
    func refresh() { beginLaunchSession() }

    func deactivate() {
        delete(keyAccount)
        isActive = false
        message  = nil
    }

    // MARK: - Keychain

    private func string(for account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String, for account: String) {
        let base: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String]      = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    private func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}
