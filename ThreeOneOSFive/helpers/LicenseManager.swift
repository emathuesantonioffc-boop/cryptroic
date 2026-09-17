import Combine
import Foundation
import Security

// URL da sua API — atualiza se mudar
private let kAPIBaseURL = "https://tefvx-api.onrender.com"

@MainActor
final class LicenseManager: ObservableObject {

    @Published private(set) var isActive     = false
    @Published private(set) var isBusy       = false
    @Published private(set) var message: String?
    @Published private(set) var expiresAt: String?
    @Published private(set) var daysRemaining: Int?
    @Published var rememberKey = true

    private let service     = "com.tefvx.external-ios.activation"
    private let keyAccount  = "license-key"

    init() {
        if let saved = storedKey(), !saved.isEmpty {
            Task { await verifyOnline(key: saved, silent: true) }
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
        Task { await verifyOnline(key: saved, silent: true) }
    }

    func activate(key: String, isAutoLogin: Bool = false) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !trimmed.isEmpty else { return }
        Task { await verifyOnline(key: trimmed, silent: false) }
    }

    func rememberedKey() -> String? { storedKey() }

    func refresh() {
        guard let saved = storedKey(), !saved.isEmpty else { return }
        Task { await verifyOnline(key: saved, silent: false) }
    }

    func deactivate() {
        deleteKey()
        isActive      = false
        message       = nil
        expiresAt     = nil
        daysRemaining = nil
    }

    // MARK: - API

    private func verifyOnline(key: String, silent: Bool) async {
        if !silent { isBusy = true }

        let deviceID = UIDevice.current.identifierForVendor?.uuidString ?? "unknown"
        let body: [String: String] = ["key": key, "device_id": deviceID]

        guard let url = URL(string: "\(kAPIBaseURL)/api/verify"),
              let bodyData = try? JSONSerialization.data(withJSONObject: body) else {
            if !silent { message = "Erro ao conectar" }
            if !silent { isBusy = false }
            return
        }

        var req = URLRequest(url: url, timeoutInterval: 15)
        req.httpMethod = "POST"
        req.httpBody   = bodyData
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        do {
            let (data, _) = try await URLSession.shared.data(for: req)
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            let valid = json?["valid"] as? Bool ?? false
            let msg   = json?["message"] as? String ?? ""
            let exp   = json?["expires_at"] as? String
            let days  = json?["days_remaining"] as? Int

            isActive      = valid
            expiresAt     = exp
            daysRemaining = days

            if valid {
                if rememberKey { saveKey(key) }
                message = days != nil ? "Key válida — \(days!) dia(s) restante(s)" : "Key válida"
            } else {
                if !silent { message = msg }
                deleteKey()
            }
        } catch {
            if !silent { message = "Sem conexão — tente novamente" }
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
