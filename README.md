# rn-secure-keystore

A comprehensive, cross-platform React Native wrapper for secure key-value storage using native security features of Android and iOS. It supports **biometric authentication**, **hardware-backed encryption**, and deep platform integrations such as **Android StrongBox**, **EncryptedSharedPreferences**, and iOS Secure Enclave via the Keychain.

This library enables storing data securely with biometric protection, ensuring that sensitive information can only be accessed after successful biometric verification (e.g., fingerprint or face recognition). This adds an additional layer of security by requiring user authentication to retrieve or modify protected data, making it ideal for handling highly sensitive data.

## Features

- **Hardware-backed security** – Utilizes device secure elements when available
- **Biometric authentication** – Store and retrieve data with biometric protection
- **Cross-platform** – Works on both iOS and Android with platform-specific optimizations
- **StrongBox support** _(Android only)_ – Enhanced protection using dedicated security chips
- **iOS Keychain integration** – Access to iOS Keychain access controls
- **Secure storage** – Store sensitive data like tokens, passwords, and user credentials
- **Error handling** – Comprehensive error codes and recovery mechanisms
- **Security introspection** – Check security levels and platform capabilities
- **Fallback mechanisms** – Graceful degradation when advanced features aren't available

## 📦 Installation

```bash
npm install rn-secure-keystore
```

### iOS Setup

```bash
cd ios && pod install
```

Add the following to your `Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Use Face ID to authenticate and access secure data</string>
```

### Android Setup

Ensure your `android/app/build.gradle` has minimum SDK version 23:

```gradle
android {
    compileSdkVersion 34
    defaultConfig {
        minSdkVersion 23
        // ...
    }
}
```

Add biometric permissions to `android/app/src/main/AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
```

> **Note**: This library requires native modules and will not work with **Expo Go**.

## Platform-Level Security Features

### iOS – Secure Enclave & Keychain

On iOS, all data is securely stored using the native **Keychain**. For devices with **Secure Enclave** (iPhone 5s and later), encryption is **hardware-backed**, meaning your secrets are tied to the physical chip and are secure.

**Key benefits:**

- Secure Enclave for hardware-backed storage
- Support for **access groups** and **keychain sharing** between apps
- Advanced access control options
- Hardware backing when available

### Android – EncryptedSharedPreferences & StrongBox

#### EncryptedSharedPreferences

This library uses Android Jetpack's `EncryptedSharedPreferences` with fallback to regular SharedPreferences, which combines:

- A **master key** stored in Android's **Keystore**
- AES encryption for your key-value pairs
- Automatic key generation and rotation
- Graceful fallback for compatibility

#### StrongBox

On supported devices (API 28+), you can optionally store encryption keys in **StrongBox**, a **hardware security module (HSM)** separate from the main CPU. This provides maximum protection, especially against physical tampering.

- Resistant to rooting and debugging
- Keys stored in StrongBox are **non-exportable**
- Enforced user authentication (e.g., biometrics) via hardware-backed checks
- **Fallback to TEE (Trusted Execution Environment)** if StrongBox is unavailable

> StrongBox is only available on select newer Android devices with a dedicated secure element (Pixel 3+, Samsung S9+, etc.).

## 🔐 Security Levels

### Android Security Tiers

| Level       | Description                                              | Use Case             |
| ----------- | -------------------------------------------------------- | -------------------- |
| `strongbox` | Stored in StrongBox HSM; maximum protection if available | Ultra-sensitive data |
| `hardware`  | Backed by Trusted Execution Environment (TEE)            | Sensitive data       |
| `software`  | Software-encrypted; fallback for older devices           | Basic protection     |
| `auto`      | Automatically chooses the strongest supported level      | Recommended default  |

### iOS Security

- iOS Keychain automatically uses **hardware-backed encryption** when the device supports **Secure Enclave**
- Hardware backing is **transparent and automatic** on supported iOS devices

## Quick Start

### Basic Usage

```typescript
import SecureStorage from 'rn-secure-keystore';

// Store a value
await SecureStorage.setItem('userToken', 'abc123');

// Retrieve a value
const token = await SecureStorage.getItem('userToken');

// Check if a key exists
const exists = await SecureStorage.hasItem('userToken');

// Remove a value
await SecureStorage.removeItem('userToken');

// Get all keys
const keys = await SecureStorage.getAllKeys();

// Clear all data
await SecureStorage.clear();
```

### Biometric Authentication

```typescript
// Store with biometric protection
await SecureStorage.setItem('sensitiveData', 'secret', {
  withBiometric: true,
  authenticatePrompt: 'Authenticate to store sensitive data',
  authenticatePromptSubtitle:
    'Use your fingerprint or face to secure this data',
});

// Retrieve with biometric authentication
const data = await SecureStorage.getItem('sensitiveData', {
  authenticatePrompt: 'Authenticate to access sensitive data',
  authenticatePromptSubtitle: 'Use your biometric to continue',
});
```

## Platform-Specific Features

### Android – Advanced Security Options

```typescript
// Check device capabilities
const capabilities = await SecureStorage.getPlatformCapabilities();
console.log('StrongBox available:', capabilities.hasStrongBox);

// Store with specific security level
await SecureStorage.setItem('data', 'value', {
  securityLevel: 'strongbox', // 'strongbox' | 'hardware' | 'software' | 'auto'
  allowFallback: true, // Allow fallback if StrongBox not available
});

// Use convenience method for StrongBox
await SecureStorage.setStrongBoxItem('ultraSecure', 'data', true);

// Get recommended security level
const recommendedLevel = await SecureStorage.getRecommendedSecurityLevel();
```

### iOS – Keychain Access Control

```typescript
import SecureStorage, { ACCESS_CONTROL } from 'rn-secure-keystore';

// Store with specific access control (no biometric required for basic storage)
await SecureStorage.setItem('basicData', 'value');

// Store with biometric requirement
await SecureStorage.setItem('biometricData', 'secret', {
  accessControl: ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
  authenticatePrompt: 'Authenticate to store data',
});

// Use convenience method
await SecureStorage.setKeychainItem(
  'keychainData',
  'secret',
  ACCESS_CONTROL.BIOMETRY_CURRENT_SET,
  'com.yourapp.shared' // access group (optional)
);
```

## Security Introspection

```typescript
// Check individual key security
const isHardwareBacked = await SecureStorage.isKeyHardwareBacked('myKey');
const securityLevel = await SecureStorage.getKeySecurityLevel('myKey');

// Get security status for all keys
const securityStatus = await SecureStorage.getSecurityStatus();
console.log('All keys security:', securityStatus);

// Check if device meets requirements
const requirements = {
  requireBiometric: true,
  requireHardwareBacking: true,
  requireStrongBox: false,
};
const { meets, missing } =
  await SecureStorage.meetsSecurityRequirements(requirements);
```

## Complete API Reference

### Core Storage Methods

#### `setItem(key: string, value: string, options?: StorageOptions): Promise<boolean>`

Stores a key-value pair securely with optional biometric protection and security level specification.

**Parameters:**

- `key`: Unique identifier for the stored value
- `value`: Data to store securely
- `options`: Optional configuration object

**Example:**

```typescript
await SecureStorage.setItem('apiKey', 'sk-123456', {
  withBiometric: true,
  securityLevel: 'hardware', // Android only
  accessControl: ACCESS_CONTROL.BIOMETRY_ANY, // iOS only
});
```

#### `getItem(key: string, options?: GetItemOptions): Promise<string | null>`

Retrieves a stored value, prompting for authentication if required.

#### `removeItem(key: string): Promise<boolean>`

Removes a stored key-value pair from secure storage.

#### `hasItem(key: string): Promise<boolean>`

Checks if a key exists in storage without retrieving the value.

#### `getAllKeys(): Promise<string[]>`

Returns an array of all stored keys.

#### `clear(): Promise<boolean>`

Clears all secure storage and removes all encryption keys.

### Security & Capability Methods

#### `isBiometricAvailable(): Promise<boolean>`

Checks if biometric authentication is available and enrolled on the device.

#### `isHardwareBackedAvailable(): Promise<boolean>`

Checks if hardware-backed keystore is available on the current device.

#### `isStrongBoxAvailable(): Promise<boolean>`

Checks if StrongBox hardware security module is available (Android only).

#### `getHardwareSecurityInfo(): Promise<HardwareSecurityInfo>`

Returns comprehensive information about device security capabilities.

```typescript
const info = await SecureStorage.getHardwareSecurityInfo();
// {
//   isHardwareBackedAvailable: true,
//   isStrongBoxAvailable: true,
//   recommendedSecurityLevel: 'strongbox'
// }
```

#### `getPlatformCapabilities(): Promise<PlatformCapabilities>`

Returns detailed platform-specific feature availability.

#### `isKeyHardwareBacked(key: string): Promise<boolean>`

Checks if a specific stored key uses hardware-backed security.

#### `getKeySecurityLevel(key: string): Promise<string>`

Returns the security level of a specific key ('strongbox', 'hardware', 'software', 'unknown').

#### `getRecommendedSecurityLevel(): Promise<'strongbox' | 'hardware' | 'software'>`

Returns the recommended security level for the current device.

#### `getSecurityStatus(): Promise<SecurityStatus>`

Returns security information for all stored keys.

#### `meetsSecurityRequirements(requirements): Promise<{meets: boolean, missing: string[]}>`

Checks if the current device meets specified security requirements.

### Platform-Specific Methods

#### Android Only

##### `setStrongBoxItem(key: string, value: string, allowFallback?: boolean): Promise<boolean>`

Convenience method to store data with StrongBox security.

#### iOS Only

##### `setKeychainItem(key: string, value: string, accessControl?: string, accessGroup?: string): Promise<boolean>`

Convenience method for iOS Keychain with custom access control.

### Utility Methods

#### `migrateToSecureStorage(key: string, plainValue: string, options?: StorageOptions): Promise<boolean>`

Migrates plain text data to secure storage.

#### `isSecurityLevelAvailable(level: 'strongbox' | 'hardware'): Promise<boolean>`

Checks if a specific security level is available on the current device.

## Type Definitions

### StorageOptions

```typescript
interface StorageOptions {
  withBiometric?: boolean;
  // Android-specific options
  requireStrongBox?: boolean;
  requireHardware?: boolean;
  securityLevel?: 'auto' | 'strongbox' | 'hardware' | 'software';
  allowFallback?: boolean;
  // iOS-specific options
  accessGroup?: string | null;
  accessControl?: string | null;
  // Authentication prompts
  authenticatePrompt?: string;
  authenticatePromptSubtitle?: string;
}
```

### GetItemOptions

```typescript
interface GetItemOptions {
  // iOS-specific
  accessGroup?: string | null;
  kLocalizedFallbackTitle?: string;
  // Android-specific
  showModal?: boolean;
  // Common
  authenticatePrompt?: string;
  authenticatePromptSubtitle?: string;
}
```

### HardwareSecurityInfo

```typescript
interface HardwareSecurityInfo {
  isHardwareBackedAvailable: boolean;
  isStrongBoxAvailable: boolean;
  recommendedSecurityLevel: 'strongbox' | 'hardware' | 'software';
}
```

### PlatformCapabilities

```typescript
interface PlatformCapabilities {
  platform: string;
  hasStrongBox: boolean;
  hasHardwareBackedKeystore: boolean;
  hasBiometrics: boolean;
  hasKeychainAccessControl: boolean;
}
```

## Constants

### iOS Access Control

```typescript
import { ACCESS_CONTROL } from 'rn-secure-keystore';

const ACCESS_CONTROL = {
  BIOMETRY_ANY: 'kSecAccessControlBiometryAny',
  BIOMETRY_CURRENT_SET: 'kSecAccessControlBiometryCurrentSet',
  DEVICE_PASSCODE: 'kSecAccessControlDevicePasscode',
  APPLICATION_PASSWORD: 'kSecAccessControlApplicationPassword',
  BIOMETRY_ANY_OR_DEVICE_PASSCODE:
    'kSecAccessControlBiometryAnyOrDevicePasscode',
};
```

### Error Codes

```typescript
import { ERROR_CODES } from 'rn-secure-keystore';

// Authentication errors
ERROR_CODES.AUTHENTICATION_CANCELLED;
ERROR_CODES.AUTHENTICATION_FAILED;
ERROR_CODES.BIOMETRIC_NOT_AVAILABLE;

// Platform errors
ERROR_CODES.PLATFORM_NOT_SUPPORTED;
ERROR_CODES.STRONGBOX_NOT_AVAILABLE;

// Storage errors
ERROR_CODES.STORAGE_ERROR;
ERROR_CODES.RETRIEVAL_ERROR;
// ... and more
```

## Error Handling

The library provides comprehensive error handling with detailed error codes:

```typescript
import { SecureStorageError, ERROR_CODES } from 'rn-secure-keystore';

try {
  await SecureStorage.getItem('protectedKey');
} catch (error) {
  if (error instanceof SecureStorageError) {
    switch (error.code) {
      case ERROR_CODES.AUTHENTICATION_CANCELLED:
        console.log('User cancelled authentication');
        break;
      case ERROR_CODES.BIOMETRIC_NOT_AVAILABLE:
        console.log('Biometric authentication not available');
        break;
      case ERROR_CODES.STRONGBOX_NOT_AVAILABLE:
        console.log('StrongBox not supported on this device');
        break;
      default:
        console.error('Storage error:', error.message);
    }
  }
}
```

## Best Practices

### 1. Check Capabilities First

```typescript
const capabilities = await SecureStorage.getPlatformCapabilities();
if (capabilities.hasStrongBox) {
  // Use StrongBox for maximum security
  await SecureStorage.setStrongBoxItem('ultraSecret', 'value');
} else if (capabilities.hasHardwareBackedKeystore) {
  // Fallback to hardware backing
  await SecureStorage.setItem('secret', 'value', { securityLevel: 'hardware' });
}
```

### 2. Handle Biometric Availability

```typescript
const biometricAvailable = await SecureStorage.isBiometricAvailable();
if (biometricAvailable) {
  await SecureStorage.setItem('biometricData', 'secret', {
    withBiometric: true,
  });
} else {
  // Fallback to device passcode or other authentication
  await SecureStorage.setItem('data', 'secret');
}
```

### 3. Use Appropriate Security Levels

```typescript
// For highly sensitive data (credit cards, private keys)
await SecureStorage.setItem('creditCard', cardNumber, {
  securityLevel: 'strongbox',
  withBiometric: true,
  allowFallback: true,
});

// For moderately sensitive data (API tokens)
await SecureStorage.setItem('apiToken', token, {
  securityLevel: 'hardware',
  allowFallback: true,
});

// For less sensitive data (user preferences)
await SecureStorage.setItem('userPrefs', preferences);
```

### 4. Implement Proper Error Handling

```typescript
try {
  const secret = await SecureStorage.getItem('protectedData', {
    authenticatePrompt: 'Access your secure data',
  });
} catch (error) {
  if (error instanceof SecureStorageError) {
    switch (error.code) {
      case ERROR_CODES.AUTHENTICATION_CANCELLED:
        // Don't show error, user intentionally cancelled
        break;
      case ERROR_CODES.AUTHENTICATION_FAILED:
        showRetryDialog();
        break;
      default:
        showGenericErrorDialog(error.message);
    }
  }
}
```

### 5. Audit Security Status

```typescript
const securityStatus = await SecureStorage.getSecurityStatus();
for (const [key, info] of Object.entries(securityStatus)) {
  console.log(
    `${key}: Hardware=${info.isHardwareBacked}, Level=${info.securityLevel}`
  );
}
```

## Platform Differences

### Storage Options

| Feature           | iOS                      | Android                  | Notes                                            |
| ----------------- | ------------------------ | ------------------------ | ------------------------------------------------ |
| Basic Storage     | Hardware-backed keychain | Default Android Keystore | iOS automatically hardware-backed when available |
| Hardware Storage  | Same as basic            | Explicit TEE backing     | iOS: automatic, Android: explicit                |
| StrongBox         | Not available            | Dedicated security chip  | Android-only feature                             |
| Biometric Storage | Face ID/Touch ID         | Fingerprint              | Platform-native biometric APIs                   |

### Key Differences

**iOS:**

- Basic storage = Hardware storage (automatically hardware-backed)
- Access control determines authentication requirements
- All keychain items are secure when Secure Enclave is available

**Android:**

- Hardware ≠ StrongBox (explicit security levels)
- Manual security level control
- StrongBox provides highest security when available

## Troubleshooting

### Common Issues

#### "The package doesn't seem to be linked"

- Run `npx pod-install` (iOS)
- Rebuild your app after installation
- Avoid Expo Go (use development build)

#### Multiple biometric prompts

- Use single `setItem()` call with `withBiometric: true`
- Don't call `getItem()` immediately after `setItem()` for biometric-protected data

#### "bad base-64" error (Android)

- Corrupted EncryptedSharedPreferences data
- Use `clear()` method to clean up corrupted storage
- Library automatically handles fallback to regular SharedPreferences

#### StrongBox not available

- StrongBox requires newer Android devices (API 28+)
- Use `allowFallback: true` for broader compatibility
- Check `isStrongBoxAvailable()` before using

#### Authentication errors

- Ensure biometrics are enrolled on device
- Use clear `authenticatePrompt` messages
- Handle user cancellations gracefully

### Debug Information

Enable logging to see detailed storage operations:

```typescript
// Check device capabilities
const info = await SecureStorage.getHardwareSecurityInfo();
console.log('Security capabilities:', info);

// Check individual key security
const keyInfo = await SecureStorage.isKeyHardwareBacked('myKey');
console.log('Key hardware-backed:', keyInfo);
```

## Requirements

- **React Native**: 0.60+
- **iOS**: 11.0+
- **Android**: API level 23+ (Android 6.0+)

## Advanced Features

### Security Requirements Validation

```typescript
const requirements = {
  requireBiometric: true,
  requireHardwareBacking: true,
  requireStrongBox: false,
};

const { meets, missing } =
  await SecureStorage.meetsSecurityRequirements(requirements);
if (!meets) {
  console.log('Missing security features:', missing);
}
```

### Migration from Plain Storage

```typescript
// Migrate existing plain text data to secure storage
await SecureStorage.migrateToSecureStorage('oldKey', plainTextValue, {
  securityLevel: 'hardware',
  withBiometric: true,
});
```

## 📄 License

MIT

## Contributing

Contributions are welcome! Please open issues and pull requests with clear descriptions.

## Support

For issues and questions:

- GitHub Issues: Report bugs and feature requests
- Documentation: Check this README for comprehensive API documentation
- Examples: See the `/example` folder for complete usage examples

---

**Made with ❤️ for React Native developers who care about security.**
