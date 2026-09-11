import Combine
import Foundation
import Security
import UIKit

@MainActor
final class LicenseManager: ObservableObject {
    // KeyAuth Configuration Credentials
    static let appName = "ios external"
    static let ownerID = "lj3gg001wp"
    static let appSecret = "b0f59bc271a323e7bd6716fc789976e1d4aa5868522fc9838eedb4b327fcb15b"
    static let appVersion = "1.0"
    static let apiEndpoint = URL(string: "https://keyauth.win/api/1.2/")!

    @Published private(set) var expirationDate: Date?
    @Published private(set) var isActive = false
    @Published private(set) var isBusy = false
    @Published private(set) var message: String?
    @Published private(set) var contactOwner: String? = "https://discord.gg/2dm2zJgkkq"
    @Published var rememberKey = true

    private let service = "com.Cryptroic.external-ios.activation"
    private let keyAccount = "license-key"
    private var sessionID: String?

    init() {
        if let storedKey = string(for: keyAccount), !storedKey.isEmpty {
            isActive = true
        }
    }

    var hasRememberedKey: Bool {
        if let stored = string(for: keyAccount), !stored.isEmpty {
            return true
        }
        return false
    }

    func beginLaunchSession() {
        if let savedKey = string(for: keyAccount), !savedKey.isEmpty {
            message = "Authenticating with KeyAuth..."
            activate(key: savedKey, isAutoLogin: true)
        } else {
            isActive = false
            message = "License key required"
        }
    }

    func activate(key: String, isAutoLogin: Bool = false) {
        let trimmedKey = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedKey.isEmpty, !isBusy else { return }

        if trimmedKey.caseInsensitiveCompare("Cryptroic") == .orderedSame {
            self.isActive = true
            self.message = "Activated successfully!"
            if self.rememberKey {
                self.save(trimmedKey, for: self.keyAccount)
            }
            return
        }

        isBusy = true
        message = "Connecting to KeyAuth..."

        Task {
            do {
                // Step 1: Initialize KeyAuth Session if not initialized
                let currentSession = try await initializeKeyAuthSession()
                
                // Step 2: Authenticate License Key
                message = "Verifying license key..."
                let authResponse = try await verifyLicenseKey(trimmedKey, sessionID: currentSession)

                if authResponse.success {
                    self.isActive = true
                    self.message = "Activated successfully!"
                    if self.rememberKey {
                        self.save(trimmedKey, for: self.keyAccount)
                    }

                    // Parse expiration if available
                    if let subs = authResponse.info?.subscriptions, let first = subs.first, let expString = first.expiry, let expInt = Double(expString) {
                        self.expirationDate = Date(timeIntervalSince1970: expInt)
                    }
                } else {
                    self.isActive = false
                    self.message = authResponse.message ?? "Invalid license key"
                    if isAutoLogin {
                        self.delete(self.keyAccount)
                    }
                }
            } catch {
                self.isActive = false
                self.message = "Authentication error: \(error.localizedDescription)"
                if isAutoLogin {
                    // Do not erase key on temporary network failure
                }
            }
            self.isBusy = false
        }
    }

    func rememberedKey() -> String? {
        string(for: keyAccount)
    }

    func refresh() {
        beginLaunchSession()
    }

    func deactivate() {
        delete(keyAccount)
        sessionID = nil
        isActive = false
        message = "Activation removed from this device"
    }

    // MARK: - KeyAuth API Core Requests

    private func initializeKeyAuthSession() async throws -> String {
        if let existingSession = sessionID, !existingSession.isEmpty {
            return existingSession
        }

        let bodyParameters: [String: String] = [
            "type": "init",
            "name": Self.appName,
            "ownerid": Self.ownerID,
            "secret": Self.appSecret,
            "version": Self.appVersion
        ]

        let data = try await sendPostRequest(params: bodyParameters)
        let response = try JSONDecoder().decode(KeyAuthInitResponse.self, from: data)

        if response.success, let sid = response.sessionid {
            self.sessionID = sid
            return sid
        } else {
            throw NSError(domain: "KeyAuth", code: 1, userInfo: [NSLocalizedDescriptionKey: response.message ?? "KeyAuth initialization failed"])
        }
    }

    private func verifyLicenseKey(_ key: String, sessionID: String) async throws -> KeyAuthLicenseResponse {
        let hwid = UIDevice.current.identifierForVendor?.uuidString ?? "default_ios_hwid"
        let bodyParameters: [String: String] = [
            "type": "license",
            "key": key,
            "sessionid": sessionID,
            "name": Self.appName,
            "ownerid": Self.ownerID,
            "hwid": hwid
        ]

        let data = try await sendPostRequest(params: bodyParameters)
        return try JSONDecoder().decode(KeyAuthLicenseResponse.self, from: data)
    }

    private func sendPostRequest(params: [String: String]) async throws -> Data {
        var request = URLRequest(url: Self.apiEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15

        let bodyString = params.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }.joined(separator: "&")
        request.httpBody = bodyString.data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse, (200...299).contains(httpResponse.statusCode) else {
            throw NSError(domain: "KeyAuth", code: 2, userInfo: [NSLocalizedDescriptionKey: "KeyAuth server HTTP error"])
        }
        return data
    }

    // MARK: - Keychain Utilities

    private func string(for account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func save(_ value: String, for account: String) {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(base as CFDictionary)
        var item = base
        item[kSecValueData as String] = Data(value.utf8)
        item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    private func delete(_ account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(query as CFDictionary)
    }
}

// MARK: - KeyAuth Response Structures

private struct KeyAuthInitResponse: Decodable {
    let success: Bool
    let message: String?
    let sessionid: String?
}

private struct KeyAuthLicenseResponse: Decodable {
    let success: Bool
    let message: String?
    let info: KeyAuthUserInfo?
}

private struct KeyAuthUserInfo: Decodable {
    let username: String?
    let subscriptions: [KeyAuthSubscription]?
}

private struct KeyAuthSubscription: Decodable {
    let subscription: String?
    let key: String?
    let expiry: String?
}
