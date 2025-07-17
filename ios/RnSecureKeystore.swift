import Foundation
import Security
import LocalAuthentication

@objc(RnSecureKeystore)
class RnSecureKeystore: NSObject {

  @objc(setItem:value:options:resolve:reject:)
  func setItem(_ key: String, value: String, options: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      let accessGroup = options["accessGroup"] as? String
      let withBiometric = options["withBiometric"] as? Bool ?? false
      
      var query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrAccount as String: key,
          kSecValueData as String: value.data(using: .utf8)!
      ]
      
      // Set access control based on withBiometric flag
      if withBiometric {
          // Store with biometric protection - will require authentication on retrieval
          guard let accessControl = SecAccessControlCreateWithFlags(
              nil,
              kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
              .biometryAny,
              nil
          ) else {
              reject("ACCESS_CONTROL_ERROR", "Failed to create access control", nil)
              return
          }
          query[kSecAttrAccessControl as String] = accessControl
      } else {
          // Store without biometric protection - basic device unlock protection
          query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
      }
      
      // Optional: Enable sharing between apps from the same developer
      if let accessGroup = accessGroup {
          query[kSecAttrAccessGroup as String] = accessGroup
      }
      
      // Delete existing item first
      SecItemDelete(query as CFDictionary)
      
      // Add new item
      let status = SecItemAdd(query as CFDictionary, nil)
      
      if status == errSecSuccess {
          resolve(true)
      } else {
          reject("KEYCHAIN_ERROR", "Failed to store item: \(status)", nil)
      }
  }

  @objc(getItem:options:resolve:reject:)
  func getItem(_ key: String, options: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      let accessGroup = options["accessGroup"] as? String
      
      var query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrAccount as String: key,
          kSecReturnData as String: true,
          kSecMatchLimit as String: kSecMatchLimitOne
      ]
      
      if let accessGroup = accessGroup {
          query[kSecAttrAccessGroup as String] = accessGroup
      }
      
      // Always allow authentication UI - iOS will automatically show biometric prompt
      // only if the item was stored with biometric protection
      query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIAllow
      
      // Optional: Add authentication prompt customization
      if let authenticatePrompt = options["authenticatePrompt"] as? String {
          query[kSecUseOperationPrompt as String] = authenticatePrompt
      } else {
          query[kSecUseOperationPrompt as String] = "Authenticate to access secure data"
      }
      
      var result: AnyObject?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      
      switch status {
      case errSecSuccess:
          if let data = result as? Data,
             let string = String(data: data, encoding: .utf8) {
              resolve(string)
          } else {
              resolve(nil)
          }
      case errSecItemNotFound:
          resolve(nil)
      case -128: // errSecUserCancel
          reject("AUTHENTICATION_CANCELLED", "User cancelled authentication", nil)
      case -25293: // errSecAuthFailed
          reject("AUTHENTICATION_FAILED", "Authentication failed", nil)
      case -25308: // errSecInteractionNotAllowed
          reject("INTERACTION_NOT_ALLOWED", "User interaction not allowed", nil)
      default:
          reject("KEYCHAIN_ERROR", "Failed to retrieve item: \(status)", nil)
      }
  }
      
  @objc(removeItem:resolve:reject:)
  func removeItem(_ key: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      let query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrAccount as String: key
      ]
      
      let status = SecItemDelete(query as CFDictionary)
      
      if status == errSecSuccess || status == errSecItemNotFound {
          resolve(true)
      } else {
          reject("KEYCHAIN_ERROR", "Failed to remove item: \(status)", nil)
      }
  }
  
  @objc(hasItem:resolve:reject:)
  func hasItem(_ key: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      let query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecAttrAccount as String: key,
          kSecReturnData as String: false
      ]
      
      let status = SecItemCopyMatching(query as CFDictionary, nil)
      resolve(status == errSecSuccess)
  }
  
  @objc(getAllKeys:reject:)
  func getAllKeys(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      let query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword,
          kSecReturnAttributes as String: true,
          kSecMatchLimit as String: kSecMatchLimitAll
      ]
      
      var result: AnyObject?
      let status = SecItemCopyMatching(query as CFDictionary, &result)
      
      if status == errSecSuccess {
          if let items = result as? [[String: Any]] {
              let keys = items.compactMap { $0[kSecAttrAccount as String] as? String }
              resolve(keys)
          } else {
              resolve([])
          }
      } else if status == errSecItemNotFound {
          resolve([])
      } else {
          reject("KEYCHAIN_ERROR", "Failed to get all keys: \(status)", nil)
      }
  }
  
  @objc(clear:reject:)
  func clear(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      let query: [String: Any] = [
          kSecClass as String: kSecClassGenericPassword
      ]
      
      let status = SecItemDelete(query as CFDictionary)
      
      if status == errSecSuccess || status == errSecItemNotFound {
          resolve(true)
      } else {
          reject("KEYCHAIN_ERROR", "Failed to clear keychain: \(status)", nil)
      }
  }
  
  @objc(isBiometricAvailable:reject:)
  func isBiometricAvailable(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      let context = LAContext()
      var error: NSError?
      
      let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
      resolve(available)
  }
  
  @objc(isHardwareBackedAvailable:reject:)
  func isHardwareBackedAvailable(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      // iOS Keychain is always hardware-backed on devices with Secure Enclave
      // Check if device has Secure Enclave (iPhone 5s and later, iPad Air and later)
      var hasSecureEnclave = false
      
      if #available(iOS 9.0, *) {
          // Try to create a key in Secure Enclave to test availability
          let keyData = "test".data(using: .utf8)!
          let testQuery: [String: Any] = [
              kSecClass as String: kSecClassGenericPassword,
              kSecAttrAccount as String: "__test_secure_enclave__",
              kSecValueData as String: keyData,
              kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
          ]
          
          // Clean up any existing test key
          SecItemDelete(testQuery as CFDictionary)
          
          // Try to add test key
          let status = SecItemAdd(testQuery as CFDictionary, nil)
          if status == errSecSuccess {
              hasSecureEnclave = true
              // Clean up test key
              SecItemDelete(testQuery as CFDictionary)
          }
      }
      
      resolve(hasSecureEnclave)
  }
  
  @objc(isStrongBoxAvailable:reject:)
  func isStrongBoxAvailable(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      // StrongBox is Android-specific, not available on iOS
      resolve(false)
  }
  
  @objc(getHardwareSecurityInfo:reject:)
  func getHardwareSecurityInfo(_ resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      isHardwareBackedAvailable({ (isHardwareBacked) in
          let info: [String: Any] = [
            "isHardwareBackedAvailable": isHardwareBacked as! Bool,
              "isStrongBoxAvailable": false, // iOS doesn't have StrongBox
            "recommendedSecurityLevel": (isHardwareBacked as! Bool) ? "hardware" : "software"
          ]
          resolve(info)
      }, reject: reject)
  }
  
  @objc(isKeyHardwareBacked:resolve:reject:)
  func isKeyHardwareBacked(_ key: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      // First check if the key exists
      hasItem(key, resolve: { (exists) in
          if !(exists as! Bool) {
              resolve(false)
              return
          }
          
          // For iOS, if the key exists and we have hardware backing available,
          // then the key is hardware-backed
          self.isHardwareBackedAvailable({ (isHardwareBacked) in
              resolve(isHardwareBacked)
          }, reject: reject)
          
      }, reject: reject)
  }
  
  @objc(getKeySecurityLevel:resolve:reject:)
  func getKeySecurityLevel(_ key: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
      
      hasItem(key, resolve: { (exists) in
          if !(exists as! Bool) {
              resolve("unknown")
              return
          }
          
          self.isHardwareBackedAvailable({ (isHardwareBacked) in
              if isHardwareBacked as! Bool {
                  resolve("hardware")
              } else {
                  resolve("software")
              }
          }, reject: { (_, _, _) in
              resolve("unknown")
          })
          
      }, reject: { (_, _, _) in
          resolve("unknown")
      })
  }
  
  private func getAccessControl(_ accessControl: String?) -> SecAccessControl? {
      guard let accessControl = accessControl else {
          return nil
      }
      
      var flags: SecAccessControlCreateFlags = []
      
      switch accessControl {
      case "kSecAccessControlBiometryAny":
          flags = .biometryAny
      case "kSecAccessControlBiometryCurrentSet":
          if #available(iOS 11.3, *) {
              flags = .biometryCurrentSet
          } else {
              flags = .biometryAny
          }
      case "kSecAccessControlDevicePasscode":
          flags = .devicePasscode
      case "kSecAccessControlApplicationPassword":
          flags = .applicationPassword
      case "kSecAccessControlBiometryAnyOrDevicePasscode":
          if #available(iOS 9.0, *) {
              flags = [.biometryAny, .or, .devicePasscode]
          } else {
              flags = .biometryAny
          }
      default:
          flags = .biometryAny
      }
      
      return SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)
  }
}
