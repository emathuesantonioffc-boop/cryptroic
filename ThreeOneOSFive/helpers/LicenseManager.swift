import Combine
import Foundation
import Security
import UIKit

// Senha de acesso — troca aqui para mudar
private let kAccessPassword = "MRC"

@MainActor
final class LicenseManager: ObservableObject {

    @Published private(set) var isActive     = false
    @Published private(set) var isBusy       = false
    @Published private(set) var message: String?
    @Published private(set) var expiresAt: String?
    @Published private(set) var daysRemaining: Int?
    @Published var rememberKey = true

    private let service     = "com.MRC.external-ios.activation"
    private let keyAccount  = "license-key"

    init() {
        if let saved = storedKey(), !saved.isEmpty {
            verifyPassword(key: saved, silent: true)
        }
    }

    var hasRememberedKey: Bool {
        if let k = storedKey(), !k.isEmpty { return true }
        return false
    }

    func beginLaunchSession() {
        guard let saved = storedKey(), !saved.isEmpty else {
            isActive = false; return
        }
        verifyPassword(key: saved, silent: true)
    }

    func activate(key: String, isAutoLogin: Bool = false) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        verifyPassword(key: trimmed, silent: false)
    }

    func rememberedKey() -> String? { storedKey() }

    func refresh() {
        guard let saved = storedKey(), !saved.isEmpty else { return }
        verifyPassword(key: saved, silent: false)
    }

    func deactivate() {
        deleteKey()
        isActive      = false
        message       = nil
        expiresAt     = nil
        daysRemaining = nil
    }

    // MARK: - Verificação local de senha

    private func verifyPassword(key: String, silent: Bool) {
        if !silent { isBusy = true }

        let valid = key == kAccessPassword

        isActive      = valid
        expiresAt     = nil
        daysRemaining = nil

        if valid {
            if rememberKey { saveKey(key) }
            if !silent { message = "Senha correta — bem-vindo!" }
        } else {
            if !silent { message = "Senha incorreta" }
            deleteKey()
        }

        if !silent { isBusy = false }
    }

    // MARK: - Keychain

    private func storedKey() -> String? {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyAccount,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func saveKey(_ value: String) {
        let base: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyAccount
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String]      = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    private func deleteKey() {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: keyAccount
        ]
        SecItemDelete(query as CFDictionary)
    }
}
