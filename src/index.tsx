import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'rn-secure-keystore' doesn't seem to be linked. Make sure:\n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const NativeSecureKeystore = NativeModules.RnSecureKeystore
  ? NativeModules.RnSecureKeystore
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

// Type definitions for hardware security info
export interface HardwareSecurityInfo {
  isHardwareBackedAvailable: boolean;
  isStrongBoxAvailable: boolean;
  recommendedSecurityLevel: 'strongbox' | 'hardware' | 'software';
}

// Type definitions for storage options (for setItem)
export interface StorageOptions {
  withBiometric?: boolean;
  requireStrongBox?: boolean; // Android only
  requireHardware?: boolean; // Android only
  securityLevel?: 'auto' | 'strongbox' | 'hardware' | 'software'; // Android only
  allowFallback?: boolean; // Android only - allow fallback to lower security levels
  accessGroup?: string | null; // iOS only
  accessControl?: string | null; // iOS only
  // Authentication prompts for setItem (when withBiometric is true)
  authenticatePrompt?: string;
  authenticatePromptSubtitle?: string;
}

// Type definitions for retrieval options (for getItem)
export interface GetItemOptions {
  accessGroup?: string | null; // iOS only
  authenticatePrompt?: string;
  authenticatePromptSubtitle?: string;
  showModal?: boolean;
  kLocalizedFallbackTitle?: string;
}

// Custom error types
export class SecureStorageError extends Error {
  constructor(
    message: string,
    public code: string,
    public originalError?: Error
  ) {
    super(message);
    this.name = 'SecureStorageError';
  }
}

/**
 * SecureStorage - React Native wrapper for secure key-value storage
 */
class SecureStorage {
  /**
   * Store a key-value pair securely
   * @param key The key to store
   * @param value The value to store
   * @param options Storage options including security level
   */
  static async setItem(
    key: string,
    value: string,
    options: StorageOptions = {}
  ): Promise<boolean> {
    if (!key || typeof key !== 'string') {
      throw new SecureStorageError(
        'Key must be a non-empty string',
        'INVALID_KEY'
      );
    }
    if (!value || typeof value !== 'string') {
      throw new SecureStorageError(
        'Value must be a non-empty string',
        'INVALID_VALUE'
      );
    }

    const defaultOptions: StorageOptions = {
      withBiometric: false,
      // Platform-specific defaults
      ...(Platform.OS === 'android' && {
        requireStrongBox: false,
        requireHardware: false,
        securityLevel: 'auto',
        allowFallback: true,
      }),
      ...(Platform.OS === 'ios' && {
        accessGroup: null,
        accessControl: null,
      }),
      // Default authentication prompts
      authenticatePrompt: 'Authenticate to store data',
      authenticatePromptSubtitle:
        'Use your biometric credential to secure this data',
    };

    const mergedOptions = { ...defaultOptions, ...options };

    // Filter out platform-specific options for the other platform
    if (Platform.OS === 'android') {
      // Remove iOS-specific options
      delete mergedOptions.accessGroup;
      delete mergedOptions.accessControl;
    } else if (Platform.OS === 'ios') {
      // Remove Android-specific options
      delete mergedOptions.requireStrongBox;
      delete mergedOptions.requireHardware;
      delete mergedOptions.securityLevel;
      delete mergedOptions.allowFallback;
    }

    try {
      return await NativeSecureKeystore.setItem(key, value, mergedOptions);
    } catch (error: any) {
      throw new SecureStorageError(
        error.message || 'Failed to store item',
        error.code || 'STORAGE_ERROR',
        error
      );
    }
  }

  /**
   * Retrieve a stored value by key
   * @param key The key to retrieve
   * @param options Retrieval options
   */
  static async getItem(
    key: string,
    options: GetItemOptions = {}
  ): Promise<string | null> {
    if (!key || typeof key !== 'string') {
      throw new SecureStorageError(
        'Key must be a non-empty string',
        'INVALID_KEY'
      );
    }

    const defaultOptions: GetItemOptions = {
      authenticatePrompt: 'Authenticate to access secure data',
      authenticatePromptSubtitle:
        'Use your biometric credential to access this data',
      showModal: false,
      kLocalizedFallbackTitle: 'Use Passcode',
    };

    const mergedOptions = { ...defaultOptions, ...options };

    // Filter platform-specific options
    if (Platform.OS === 'android') {
      // Remove iOS-specific options
      delete mergedOptions.accessGroup;
      delete mergedOptions.kLocalizedFallbackTitle;
    } else if (Platform.OS === 'ios') {
      // Remove Android-specific options
      delete mergedOptions.showModal;
    }

    try {
      return await NativeSecureKeystore.getItem(key, mergedOptions);
    } catch (error: any) {
      throw new SecureStorageError(
        error.message || 'Failed to retrieve item',
        error.code || 'RETRIEVAL_ERROR',
        error
      );
    }
  }

  /**
   * Remove a stored key-value pair
   * @param key The key to remove
   */
  static async removeItem(key: string): Promise<boolean> {
    if (!key || typeof key !== 'string') {
      throw new SecureStorageError(
        'Key must be a non-empty string',
        'INVALID_KEY'
      );
    }

    try {
      return await NativeSecureKeystore.removeItem(key);
    } catch (error: any) {
      throw new SecureStorageError(
        error.message || 'Failed to remove item',
        error.code || 'REMOVAL_ERROR',
        error
      );
    }
  }

  /**
   * Check if a key exists in storage
   * @param key The key to check
   */
  static async hasItem(key: string): Promise<boolean> {
    if (!key || typeof key !== 'string') {
      throw new SecureStorageError(
        'Key must be a non-empty string',
        'INVALID_KEY'
      );
    }

    try {
      return await NativeSecureKeystore.hasItem(key);
    } catch (error: any) {
      // hasItem should never throw, return false on error
      return false;
    }
  }

  /**
   * Get all stored keys
   */
  static async getAllKeys(): Promise<string[]> {
    try {
      return await NativeSecureKeystore.getAllKeys();
    } catch (error: any) {
      throw new SecureStorageError(
        error.message || 'Failed to get all keys',
        error.code || 'GET_KEYS_ERROR',
        error
      );
    }
  }

  /**
   * Clear all stored data
   */
  static async clear(): Promise<boolean> {
    try {
      return await NativeSecureKeystore.clear();
    } catch (error: any) {
      throw new SecureStorageError(
        error.message || 'Failed to clear storage',
        error.code || 'CLEAR_ERROR',
        error
      );
    }
  }

  /**
   * Check if biometric authentication is available
   */
  static async isBiometricAvailable(): Promise<boolean> {
    try {
      return await NativeSecureKeystore.isBiometricAvailable();
    } catch (error: any) {
      return false;
    }
  }

  /**
   * Check if hardware-backed keystore is available
   */
  static async isHardwareBackedAvailable(): Promise<boolean> {
    try {
      return await NativeSecureKeystore.isHardwareBackedAvailable();
    } catch (error: any) {
      return false;
    }
  }

  /**
   * Check if StrongBox security is available (Android only)
   * @returns Promise<boolean> - true if available on Android, false on iOS
   */
  static async isStrongBoxAvailable(): Promise<boolean> {
    if (Platform.OS === 'android') {
      try {
        return await NativeSecureKeystore.isStrongBoxAvailable();
      } catch (error: any) {
        return false;
      }
    }
    // StrongBox is Android-specific, return false for iOS
    return false;
  }

  /**
   * Get comprehensive hardware security information
   * @returns Object containing all available security features and recommendations
   */
  static async getHardwareSecurityInfo(): Promise<HardwareSecurityInfo> {
    if (Platform.OS === 'android') {
      try {
        return await NativeSecureKeystore.getHardwareSecurityInfo();
      } catch (error: any) {
        // Fallback for Android
        const isHardwareBacked = await this.isHardwareBackedAvailable();
        return {
          isHardwareBackedAvailable: isHardwareBacked,
          isStrongBoxAvailable: false,
          recommendedSecurityLevel: isHardwareBacked ? 'hardware' : 'software',
        };
      }
    }

    // For iOS, return equivalent information
    const isHardwareBacked = await this.isHardwareBackedAvailable();
    return {
      isHardwareBackedAvailable: isHardwareBacked,
      isStrongBoxAvailable: false, // iOS doesn't have StrongBox
      recommendedSecurityLevel: isHardwareBacked ? 'hardware' : 'software',
    };
  }

  /**
   * Check if a specific key is stored with hardware-backed security
   * @param key The key to check
   * @returns True if the key is hardware-backed, false otherwise
   */
  static async isKeyHardwareBacked(key: string): Promise<boolean> {
    if (!key || typeof key !== 'string') {
      throw new SecureStorageError(
        'Key must be a non-empty string',
        'INVALID_KEY'
      );
    }

    try {
      if (Platform.OS === 'android') {
        return await NativeSecureKeystore.isKeyHardwareBacked(key);
      }

      // For iOS, check if key exists and if hardware backing is available
      const hasItem = await this.hasItem(key);
      if (!hasItem) {
        return false;
      }

      return await this.isHardwareBackedAvailable();
    } catch (error: any) {
      return false;
    }
  }

  /**
   * Get security level for a specific key (Android only)
   * @param key The key to check
   * @returns Security level of the key
   */
  static async getKeySecurityLevel(key: string): Promise<string> {
    if (!key || typeof key !== 'string') {
      throw new SecureStorageError(
        'Key must be a non-empty string',
        'INVALID_KEY'
      );
    }

    try {
      if (Platform.OS === 'android') {
        return await NativeSecureKeystore.getKeySecurityLevel(key);
      } else {
        return await NativeSecureKeystore.getKeySecurityLevel(key);
      }
    } catch (error: any) {
      return 'unknown';
    }
  }

  /**
   * Utility method to get security level recommendation for the current device
   * @returns Recommended security level based on device capabilities
   */
  static async getRecommendedSecurityLevel(): Promise<
    'strongbox' | 'hardware' | 'software'
  > {
    const info = await this.getHardwareSecurityInfo();
    return info.recommendedSecurityLevel;
  }

  /**
   * Utility method to check if a security level is available on the current device
   * @param level The security level to check
   * @returns True if the security level is available
   */
  static async isSecurityLevelAvailable(
    level: 'strongbox' | 'hardware'
  ): Promise<boolean> {
    switch (level) {
      case 'strongbox':
        return Platform.OS === 'android'
          ? await this.isStrongBoxAvailable()
          : false;
      case 'hardware':
        return this.isHardwareBackedAvailable();
      default:
        return false;
    }
  }

  /**
   * Get security status for all stored keys
   * @returns Object mapping keys to their security status
   */
  static async getSecurityStatus(): Promise<
    Record<
      string,
      { exists: boolean; isHardwareBacked: boolean; securityLevel?: string }
    >
  > {
    const keys = await this.getAllKeys();
    const status: Record<
      string,
      { exists: boolean; isHardwareBacked: boolean; securityLevel?: string }
    > = {};

    for (const key of keys) {
      const exists = await this.hasItem(key);
      const isHardwareBacked = exists
        ? await this.isKeyHardwareBacked(key)
        : false;

      let securityLevel: string | undefined;
      if (exists) {
        try {
          securityLevel = await this.getKeySecurityLevel(key);
        } catch {
          securityLevel = undefined;
        }
      }

      status[key] = {
        exists,
        isHardwareBacked,
        ...(securityLevel && { securityLevel }),
      };
    }

    return status;
  }

  /**
   * Android-specific: Set item with StrongBox security (if available)
   * @param key The key to store
   * @param value The value to store
   * @param allowFallback Whether to allow fallback to hardware if StrongBox is not available
   */
  static async setStrongBoxItem(
    key: string,
    value: string,
    allowFallback: boolean = false
  ): Promise<boolean> {
    if (Platform.OS !== 'android') {
      throw new SecureStorageError(
        'StrongBox is only available on Android devices',
        'PLATFORM_NOT_SUPPORTED'
      );
    }

    const isAvailable = await this.isStrongBoxAvailable();
    if (!isAvailable && !allowFallback) {
      throw new SecureStorageError(
        'StrongBox is not available on this device',
        'STRONGBOX_NOT_AVAILABLE'
      );
    }

    return this.setItem(key, value, {
      securityLevel: 'strongbox',
      allowFallback,
    });
  }

  /**
   * iOS-specific: Set item with custom access control
   * @param key The key to store
   * @param value The value to store
   * @param accessControl iOS access control level
   * @param accessGroup iOS keychain access group
   */
  static async setKeychainItem(
    key: string,
    value: string,
    accessControl?: string,
    accessGroup?: string
  ): Promise<boolean> {
    if (Platform.OS !== 'ios') {
      throw new SecureStorageError(
        'Keychain access control is only available on iOS',
        'PLATFORM_NOT_SUPPORTED'
      );
    }

    return this.setItem(key, value, {
      accessControl,
      accessGroup,
    });
  }

  /**
   * Platform-specific capabilities check
   * @returns Object with platform-specific feature availability
   */
  static async getPlatformCapabilities(): Promise<{
    platform: string;
    hasStrongBox: boolean;
    hasHardwareBackedKeystore: boolean;
    hasBiometrics: boolean;
    hasKeychainAccessControl: boolean;
  }> {
    const [hasStrongBox, hasHardwareBacked, hasBiometrics] = await Promise.all([
      this.isStrongBoxAvailable(),
      this.isHardwareBackedAvailable(),
      this.isBiometricAvailable(),
    ]);

    return {
      platform: Platform.OS,
      hasStrongBox,
      hasHardwareBackedKeystore: hasHardwareBacked,
      hasBiometrics,
      hasKeychainAccessControl: Platform.OS === 'ios',
    };
  }

  /**
   * Utility method to migrate from plain storage to secure storage
   * @param key The key to migrate
   * @param plainValue The plain text value to secure
   * @param options Security options for the new secure storage
   */
  static async migrateToSecureStorage(
    key: string,
    plainValue: string,
    options: StorageOptions = {}
  ): Promise<boolean> {
    try {
      // Store securely
      await this.setItem(key, plainValue, options);
      return true;
    } catch (error) {
      throw new SecureStorageError(
        `Failed to migrate key "${key}" to secure storage: ${error instanceof Error ? error.message : 'Unknown error'}`,
        'MIGRATION_ERROR',
        error instanceof Error ? error : undefined
      );
    }
  }

  /**
   * Utility method to check if the current device meets minimum security requirements
   * @param requirements Security requirements to check
   */
  static async meetsSecurityRequirements(requirements: {
    requireBiometric?: boolean;
    requireHardwareBacking?: boolean;
    requireStrongBox?: boolean;
  }): Promise<{ meets: boolean; missing: string[] }> {
    const missing: string[] = [];

    if (requirements.requireBiometric) {
      const hasBiometric = await this.isBiometricAvailable();
      if (!hasBiometric) {
        missing.push('biometric authentication');
      }
    }

    if (requirements.requireHardwareBacking) {
      const hasHardware = await this.isHardwareBackedAvailable();
      if (!hasHardware) {
        missing.push('hardware-backed storage');
      }
    }

    if (requirements.requireStrongBox) {
      const hasStrongBox = await this.isStrongBoxAvailable();
      if (!hasStrongBox) {
        missing.push('StrongBox security');
      }
    }

    return {
      meets: missing.length === 0,
      missing,
    };
  }
}

export default SecureStorage;

// iOS access control constants
export const ACCESS_CONTROL = {
  BIOMETRY_ANY: 'kSecAccessControlBiometryAny',
  BIOMETRY_CURRENT_SET: 'kSecAccessControlBiometryCurrentSet',
  DEVICE_PASSCODE: 'kSecAccessControlDevicePasscode',
  APPLICATION_PASSWORD: 'kSecAccessControlApplicationPassword',
  BIOMETRY_ANY_OR_DEVICE_PASSCODE:
    'kSecAccessControlBiometryAnyOrDevicePasscode',
} as const;

// Common Error Codes - Added for better error handling
export const ERROR_CODES = {
  // Authentication errors
  AUTHENTICATION_CANCELLED: 'AUTHENTICATION_CANCELLED',
  AUTHENTICATION_FAILED: 'AUTHENTICATION_FAILED',
  BIOMETRIC_NOT_AVAILABLE: 'BIOMETRIC_NOT_AVAILABLE',
  INTERACTION_NOT_ALLOWED: 'INTERACTION_NOT_ALLOWED',

  // Platform errors
  PLATFORM_NOT_SUPPORTED: 'PLATFORM_NOT_SUPPORTED',
  STRONGBOX_NOT_AVAILABLE: 'STRONGBOX_NOT_AVAILABLE',

  // Input validation errors
  INVALID_KEY: 'INVALID_KEY',
  INVALID_VALUE: 'INVALID_VALUE',

  // Storage errors
  STORAGE_ERROR: 'STORAGE_ERROR',
  RETRIEVAL_ERROR: 'RETRIEVAL_ERROR',
  REMOVAL_ERROR: 'REMOVAL_ERROR',
  CLEAR_ERROR: 'CLEAR_ERROR',
  GET_KEYS_ERROR: 'GET_KEYS_ERROR',

  // Keychain/Keystore errors
  KEYCHAIN_ERROR: 'KEYCHAIN_ERROR',
  CIPHER_ERROR: 'CIPHER_ERROR',
  ACCESS_CONTROL_ERROR: 'ACCESS_CONTROL_ERROR',

  // Hardware errors
  SECURITY_INFO_ERROR: 'SECURITY_INFO_ERROR',
  NO_ACTIVITY: 'NO_ACTIVITY',
} as const;
