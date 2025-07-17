package com.rnsecurekeystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt as AndroidXBiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.facebook.react.bridge.*
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

class RnSecureKeystoreModule(private val reactContext: ReactApplicationContext) :
  ReactContextBaseJavaModule(reactContext) {

  private val KEYSTORE_PROVIDER = "AndroidKeyStore"
  private val TRANSFORMATION = "AES/GCM/NoPadding"
  private val SHARED_PREFS_NAME = "SecureKeystorePrefs"
  private val GCM_IV_LENGTH = 12
  private val GCM_TAG_LENGTH = 16

  private var keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
    load(null)
  }

  override fun getName(): String {
    return "RnSecureKeystore"
  }

  @ReactMethod
  fun setItem(key: String, value: String, options: ReadableMap, promise: Promise) {
    try {
      val keyAlias = "key_$key"
      val withBiometric = options.hasKey("withBiometric") && options.getBoolean("withBiometric")

      if (keyStore.containsAlias(keyAlias)) {
        keyStore.deleteEntry(keyAlias)
      }

      val generatedSecurityLevel = generateKey(keyAlias, options, withBiometric)

      // Store the actual security level achieved for later reference
      saveSecurityLevelInfo(key, generatedSecurityLevel)

      // Store whether this key requires biometric authentication
      saveBiometricRequirement(key, withBiometric)

      if (withBiometric) {
        authenticateAndEncrypt(keyAlias, value, key, promise, options)
      } else {
        val encryptedValue = encryptValue(keyAlias, value)
        saveToPreferences(key, encryptedValue)
        promise.resolve(true)
      }

    } catch (e: Exception) {
      promise.reject("ENCRYPTION_ERROR", "Failed to set item: ${e.message}", e)
    }
  }

  @ReactMethod
  fun getItem(key: String, options: ReadableMap, promise: Promise) {
    try {
      val keyAlias = "key_$key"
      val encryptedValue = loadFromPreferences(key)

      if (encryptedValue == null) {
        promise.resolve(null)
        return
      }

      // Check if this key was stored with biometric requirement
      val storedWithBiometric = getBiometricRequirement(key)
      val requiresAuth = storedWithBiometric || isKeyRequiresAuthentication(keyAlias)

      if (requiresAuth) {
        authenticateAndDecrypt(keyAlias, encryptedValue, promise, options)
      } else {
        val decryptedValue = decryptValue(keyAlias, encryptedValue)
        promise.resolve(decryptedValue)
      }

    } catch (e: Exception) {
      promise.reject("DECRYPTION_ERROR", "Failed to get item: ${e.message}", e)
    }
  }

  @ReactMethod
  fun removeItem(key: String, promise: Promise) {
    try {
      val keyAlias = "key_$key"

      // Remove from encrypted preferences
      try {
        val masterKey = MasterKey.Builder(reactContext)
          .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
          .build()

        val encryptedPrefs = EncryptedSharedPreferences.create(
          reactContext,
          SHARED_PREFS_NAME,
          masterKey,
          EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
          EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        encryptedPrefs.edit()
          .remove(key)
          .remove("${key}_security_level")
          .remove("${key}_biometric_required")
          .apply()
      } catch (e: Exception) {
        // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
        reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
          .edit()
          .remove(key)
          .remove("${key}_security_level")
          .remove("${key}_biometric_required")
          .apply()
      }

      if (keyStore.containsAlias(keyAlias)) {
        keyStore.deleteEntry(keyAlias)
      }

      promise.resolve(true)
    } catch (e: Exception) {
      promise.reject("REMOVAL_ERROR", "Failed to remove item: ${e.message}", e)
    }
  }

  @ReactMethod
  fun isBiometricAvailable(promise: Promise) {
    try {
      val biometricManager = BiometricManager.from(reactContext)
      val result = biometricManager.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
      )

      val available = when (result) {
        BiometricManager.BIOMETRIC_SUCCESS -> true
        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> false
        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> false
        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> false
        else -> false
      }

      promise.resolve(available)
    } catch (e: Exception) {
      promise.resolve(false)
    }
  }

  @ReactMethod
  fun hasItem(key: String, promise: Promise) {
    try {
      var exists = false

      try {
        val masterKey = MasterKey.Builder(reactContext)
          .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
          .build()

        val encryptedPrefs = EncryptedSharedPreferences.create(
          reactContext,
          SHARED_PREFS_NAME,
          masterKey,
          EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
          EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        exists = encryptedPrefs.contains(key)
      } catch (e: Exception) {
        // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
        exists = reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
          .contains(key)
      }

      promise.resolve(exists)
    } catch (e: Exception) {
      promise.resolve(false)
    }
  }

  @ReactMethod
  fun getAllKeys(promise: Promise) {
    try {
      val keys: WritableArray = Arguments.createArray()

      try {
        // Try EncryptedSharedPreferences first
        val masterKey = MasterKey.Builder(reactContext)
          .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
          .build()

        val encryptedPrefs = EncryptedSharedPreferences.create(
          reactContext,
          SHARED_PREFS_NAME,
          masterKey,
          EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
          EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        for (entry in encryptedPrefs.all.entries) {
          if (!entry.key.endsWith("_security_level") && !entry.key.endsWith("_biometric_required")) {
            keys.pushString(entry.key)
          }
        }
      } catch (e: Exception) {
        // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
        val regularPrefs = reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
        for (entry in regularPrefs.all.entries) {
          if (!entry.key.endsWith("_security_level") && !entry.key.endsWith("_biometric_required")) {
            keys.pushString(entry.key)
          }
        }
      }

      promise.resolve(keys)
    } catch (e: Exception) {
      promise.reject("GET_KEYS_ERROR", "Failed to get keys: ${e.message}", e)
    }
  }

  @ReactMethod
  fun clear(promise: Promise) {
    try {
      // Clear encrypted preferences
      try {
        val masterKey = MasterKey.Builder(reactContext)
          .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
          .build()

        val encryptedPrefs = EncryptedSharedPreferences.create(
          reactContext,
          SHARED_PREFS_NAME,
          masterKey,
          EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
          EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        encryptedPrefs.edit().clear().apply()
      } catch (e: Exception) {
        // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
        reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
          .edit()
          .clear()
          .apply()
      }

      // Clear Android Keystore keys
      val aliases = keyStore.aliases()
      while (aliases.hasMoreElements()) {
        val alias = aliases.nextElement()
        if (alias.startsWith("key_")) {
          keyStore.deleteEntry(alias)
        }
      }

      promise.resolve(true)
    } catch (e: Exception) {
      promise.reject("CLEAR_ERROR", "Failed to clear storage: ${e.message}", e)
    }
  }

  @ReactMethod
  fun isHardwareBackedAvailable(promise: Promise) {
    try {
      val available = keyStore.provider.name == KEYSTORE_PROVIDER
      promise.resolve(available)
    } catch (e: Exception) {
      promise.resolve(false)
    }
  }

  @ReactMethod
  fun isStrongBoxAvailable(promise: Promise) {
    try {
      val available = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        isStrongBoxAvailableSync()
      } else {
        false
      }
      promise.resolve(available)
    } catch (e: Exception) {
      promise.resolve(false)
    }
  }

  @ReactMethod
  fun getHardwareSecurityInfo(promise: Promise) {
    try {
      val info = Arguments.createMap()
      val isHardwareBacked = keyStore.provider.name == KEYSTORE_PROVIDER
      info.putBoolean("isHardwareBackedAvailable", isHardwareBacked)

      val isStrongBoxAvailable = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        isStrongBoxAvailableSync()
      } else {
        false
      }
      info.putBoolean("isStrongBoxAvailable", isStrongBoxAvailable)

      val securityLevel = when {
        isStrongBoxAvailable -> "strongbox"
        isHardwareBacked -> "hardware"
        else -> "software"
      }
      info.putString("recommendedSecurityLevel", securityLevel)

      promise.resolve(info)
    } catch (e: Exception) {
      promise.reject("SECURITY_INFO_ERROR", "Failed to get hardware security info: ${e.message}", e)
    }
  }

  @ReactMethod
  fun isKeyHardwareBacked(key: String, promise: Promise) {
    try {
      val keyAlias = "key_$key"

      if (!keyStore.containsAlias(keyAlias)) {
        promise.resolve(false)
        return
      }

      val securityLevel = getKeySecurityLevel(keyAlias)
      promise.resolve(securityLevel != "software")
    } catch (e: Exception) {
      promise.resolve(false)
    }
  }

  @ReactMethod
  fun getKeySecurityLevel(key: String, promise: Promise) {
    try {
      val keyAlias = "key_$key"
      val securityLevel = getKeySecurityLevel(keyAlias)
      promise.resolve(securityLevel)
    } catch (e: Exception) {
      promise.resolve("unknown")
    }
  }

  /**
   * Save biometric requirement for a key
   */
  private fun saveBiometricRequirement(key: String, requiresBiometric: Boolean) {
    try {
      val masterKey = MasterKey.Builder(reactContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

      val encryptedPrefs = EncryptedSharedPreferences.create(
        reactContext,
        SHARED_PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      )

      encryptedPrefs.edit()
        .putBoolean("${key}_biometric_required", requiresBiometric)
        .apply()
    } catch (e: Exception) {
      // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
      reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
        .edit()
        .putBoolean("${key}_biometric_required", requiresBiometric)
        .apply()
    }
  }

  /**
   * Get biometric requirement for a key
   */
  private fun getBiometricRequirement(key: String): Boolean {
    return try {
      val masterKey = MasterKey.Builder(reactContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

      val encryptedPrefs = EncryptedSharedPreferences.create(
        reactContext,
        SHARED_PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      )

      encryptedPrefs.getBoolean("${key}_biometric_required", false)
    } catch (e: Exception) {
      // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
      reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
        .getBoolean("${key}_biometric_required", false)
    }
  }

  /**
   * Generates a key with the specified security requirements
   * Returns the actual security level achieved
   */
  private fun generateKey(keyAlias: String, options: ReadableMap, withBiometric: Boolean): String {
    val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
    val requestedSecurityLevel = getRequestedSecurityLevel(options)
    val allowFallback = options.hasKey("allowFallback") && options.getBoolean("allowFallback")

    // Try to generate key with the requested security level
    val actualSecurityLevel = generateKeyWithSecurityLevel(
      keyGenerator,
      keyAlias,
      requestedSecurityLevel,
      withBiometric,
      allowFallback
    )

    return actualSecurityLevel
  }

  private fun generateKeyWithSecurityLevel(
    keyGenerator: KeyGenerator,
    keyAlias: String,
    requestedLevel: String,
    withBiometric: Boolean,
    allowFallback: Boolean
  ): String {
    val securityLevels = when (requestedLevel) {
      "strongbox" -> listOf("strongbox")
      "hardware" -> listOf("hardware")
      "software" -> listOf("software")
      else -> listOf("strongbox", "hardware", "software") // auto mode
    }

    for (level in securityLevels) {
      try {
        val builder = createKeyGenParameterSpec(keyAlias, level, withBiometric)
        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
        return level
      } catch (e: Exception) {
        if (!allowFallback && requestedLevel != "auto") {
          throw IllegalStateException("Failed to generate key with $level security level: ${e.message}", e)
        }
        // Continue to next security level
      }
    }

    throw IllegalStateException("Failed to generate key with any security level")
  }

  private fun createKeyGenParameterSpec(
    keyAlias: String,
    securityLevel: String,
    withBiometric: Boolean
  ): KeyGenParameterSpec.Builder {
    val builder = KeyGenParameterSpec.Builder(
      keyAlias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)

    // Configure biometric authentication
    if (withBiometric) {
      builder.setUserAuthenticationRequired(true)

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        builder.setUserAuthenticationParameters(
          0,
          KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        )
      } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
        builder.setUserAuthenticationValidityDurationSeconds(-1)
      } else {
        builder.setUserAuthenticationValidityDurationSeconds(30)
      }
    }

    // Configure security level specific settings
    when (securityLevel) {
      "strongbox" -> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
          builder.setIsStrongBoxBacked(true)
        } else {
          throw IllegalStateException("StrongBox requires API level 28 or higher")
        }
      }
      "hardware" -> {
        // Hardware-backed keys are the default for AndroidKeyStore
        // No additional configuration needed
      }
      "software" -> {
        // For software keys, we don't use AndroidKeyStore
        // This case should be handled differently if needed
        throw IllegalStateException("Software keys are not supported in AndroidKeyStore")
      }
    }

    return builder
  }

  private fun getRequestedSecurityLevel(options: ReadableMap): String {
    if (options.hasKey("securityLevel")) {
      return options.getString("securityLevel") ?: "auto"
    }

    if (options.hasKey("requireStrongBox") && options.getBoolean("requireStrongBox")) {
      return "strongbox"
    }

    if (options.hasKey("requireHardware") && options.getBoolean("requireHardware")) {
      return "hardware"
    }

    return "auto"
  }

  private fun isStrongBoxAvailableSync(): Boolean {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
      return false
    }

    return try {
      val testKeyAlias = "test_strongbox_sync_${System.currentTimeMillis()}"
      val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)

      val builder = KeyGenParameterSpec.Builder(
        testKeyAlias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
      )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(256)
        .setIsStrongBoxBacked(true)

      keyGenerator.init(builder.build())
      keyGenerator.generateKey()
      keyStore.deleteEntry(testKeyAlias)
      true
    } catch (e: Exception) {
      false
    }
  }

  private fun getKeySecurityLevel(keyAlias: String): String {
    if (!keyStore.containsAlias(keyAlias)) {
      return "unknown"
    }

    return try {
      val key = keyStore.getKey(keyAlias, null) as? SecretKey
      if (key == null) {
        return "unknown"
      }

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        val keyFactory = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
        val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java)

        when {
          Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            // Android 12+: Try to get stored security level info first
            try {
              val masterKey = MasterKey.Builder(reactContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

              val encryptedPrefs = EncryptedSharedPreferences.create(
                reactContext,
                SHARED_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
              )

              val storedLevel = encryptedPrefs.getString("${keyAlias.removePrefix("key_")}_security_level", null)
              if (storedLevel != null) {
                return storedLevel
              }
            } catch (e: Exception) {
              // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
              try {
                val storedLevel = reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
                  .getString("${keyAlias.removePrefix("key_")}_security_level", null)
                if (storedLevel != null) {
                  return storedLevel
                }
              } catch (e2: Exception) {
                // Ignore and fall through to default
              }
            }

            // For Android 12+, we can use reflection to safely access securityLevel if available
            try {
              val securityLevelField = keyInfo.javaClass.getDeclaredField("securityLevel")
              securityLevelField.isAccessible = true
              val securityLevel = securityLevelField.getInt(keyInfo)

              when (securityLevel) {
                2 -> "strongbox"    // SECURITY_LEVEL_STRONGBOX
                1 -> "hardware"     // SECURITY_LEVEL_TRUSTED_ENVIRONMENT
                0 -> "software"     // SECURITY_LEVEL_SOFTWARE
                else -> "hardware"
              }
            } catch (e: Exception) {
              // Fallback to hardware if reflection fails
              "hardware"
            }
          }
          Build.VERSION.SDK_INT >= Build.VERSION_CODES.P -> {
            // Android 9-11: Check if key was generated with StrongBox flag
            // This is a heuristic approach since direct detection is limited
            try {
              // Try to get stored security level info first
              val masterKey = MasterKey.Builder(reactContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

              val encryptedPrefs = EncryptedSharedPreferences.create(
                reactContext,
                SHARED_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
              )

              val storedLevel = encryptedPrefs.getString("${keyAlias.removePrefix("key_")}_security_level", null)
              if (storedLevel != null) {
                return storedLevel
              }

              // Fallback: assume hardware-backed for AndroidKeyStore
              "hardware"
            } catch (e: Exception) {
              // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
              try {
                val storedLevel = reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
                  .getString("${keyAlias.removePrefix("key_")}_security_level", null)
                if (storedLevel != null) {
                  return storedLevel
                }
              } catch (e2: Exception) {
                // Ignore
              }
              "hardware"
            }
          }
          else -> {
            // Android 6-8: AndroidKeyStore keys are hardware-backed by default
            "hardware"
          }
        }
      } else {
        // For older versions, assume hardware-backed if using AndroidKeyStore
        "hardware"
      }
    } catch (e: Exception) {
      "unknown"
    }
  }

  private fun saveSecurityLevelInfo(key: String, securityLevel: String) {
    try {
      val masterKey = MasterKey.Builder(reactContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

      val encryptedPrefs = EncryptedSharedPreferences.create(
        reactContext,
        SHARED_PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      )

      encryptedPrefs.edit()
        .putString("${key}_security_level", securityLevel)
        .apply()
    } catch (e: Exception) {
      // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
      reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
        .edit()
        .putString("${key}_security_level", securityLevel)
        .apply()
    }
  }

  private fun authenticateAndEncrypt(
    keyAlias: String,
    value: String,
    key: String,
    promise: Promise,
    options: ReadableMap
  ) {
    val activity = currentActivity as? FragmentActivity
    if (activity == null) {
      promise.reject("NO_ACTIVITY", "No current activity available for authentication")
      return
    }

    currentActivity?.runOnUiThread {
      val executor = ContextCompat.getMainExecutor(activity)
      val biometricPrompt = BiometricPrompt(
        activity,
        executor,
        object : BiometricPrompt.AuthenticationCallback() {
          override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            super.onAuthenticationSucceeded(result)
            try {
              val cryptoObject = result.cryptoObject
              if (cryptoObject?.cipher == null) {
                promise.reject("CIPHER_ERROR", "CryptoObject's cipher is null")
                return
              }

              val cipher = cryptoObject.cipher!!
              val iv = cipher.iv
              if (iv.size != GCM_IV_LENGTH) {
                throw IllegalStateException("Invalid IV size: ${iv.size}, expected: $GCM_IV_LENGTH")
              }

              val encryptedBytes = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
              val combined = ByteArray(iv.size + encryptedBytes.size)
              System.arraycopy(iv, 0, combined, 0, iv.size)
              System.arraycopy(encryptedBytes, 0, combined, iv.size, encryptedBytes.size)

              val encryptedBase64 = Base64.encodeToString(combined, Base64.NO_WRAP)
              saveToPreferences(key, encryptedBase64)
              promise.resolve(true)
            } catch (e: Exception) {
              promise.reject(
                "ENCRYPTION_ERROR",
                "Failed to encrypt after authentication: ${e.message}",
                e
              )
            }
          }

          override fun onAuthenticationFailed() {
            super.onAuthenticationFailed()
            promise.reject("AUTHENTICATION_FAILED", "Authentication failed")
          }

          override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            super.onAuthenticationError(errorCode, errString)
            when (errorCode) {
              BiometricPrompt.ERROR_USER_CANCELED,
              BiometricPrompt.ERROR_CANCELED -> {
                promise.reject("AUTHENTICATION_CANCELLED", "Authentication was cancelled")
              }
              else -> {
                promise.reject("AUTHENTICATION_ERROR", "Authentication error: $errString")
              }
            }
          }
        }
      )

      try {
        val secretKey = keyStore.getKey(keyAlias, null) as? SecretKey
        if (secretKey == null) {
          promise.reject("KEY_ERROR", "Secret key not found for alias $keyAlias")
          return@runOnUiThread
        }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val promptTitle = options.getString("authenticatePrompt") ?: "Authenticate to store data"
        val promptSubtitle = options.getString("authenticatePromptSubtitle")
          ?: "Use your biometric credential to secure this data"

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
          .setTitle(promptTitle)
          .setSubtitle(promptSubtitle)
          .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
          )
          .build()

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
      } catch (e: Exception) {
        promise.reject("CIPHER_INIT_ERROR", "Failed to initialize cipher: ${e.message}", e)
      }
    }
  }

  private fun encryptValue(keyAlias: String, value: String): String {
    try {
      val secretKeyEntry = keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry
        ?: throw IllegalStateException("Secret key not found for alias: $keyAlias")

      val secretKey = secretKeyEntry.secretKey
      val cipher = Cipher.getInstance(TRANSFORMATION)
      cipher.init(Cipher.ENCRYPT_MODE, secretKey)

      val iv = cipher.iv
      if (iv.size != GCM_IV_LENGTH) {
        throw IllegalStateException("Invalid IV size: ${iv.size}, expected: $GCM_IV_LENGTH")
      }

      val encryptedData = cipher.doFinal(value.toByteArray(Charsets.UTF_8))

      // Combine IV + encrypted data
      val combined = ByteArray(iv.size + encryptedData.size)
      System.arraycopy(iv, 0, combined, 0, iv.size)
      System.arraycopy(encryptedData, 0, combined, iv.size, encryptedData.size)

      return Base64.encodeToString(combined, Base64.NO_WRAP)
    } catch (e: Exception) {
      throw RuntimeException("Encryption failed for key $keyAlias: ${e.message}", e)
    }
  }

  private fun decryptValue(keyAlias: String, encryptedValue: String): String {
    val secretKey = keyStore.getKey(keyAlias, null) as SecretKey
    val combined = Base64.decode(encryptedValue, Base64.NO_WRAP)

    if (combined.size < GCM_IV_LENGTH + GCM_TAG_LENGTH) {
      throw IllegalArgumentException("Invalid encrypted data length")
    }

    val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
    val encryptedData = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

    val cipher = Cipher.getInstance(TRANSFORMATION)
    val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)

    cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

    val decryptedData = cipher.doFinal(encryptedData)
    return String(decryptedData, Charsets.UTF_8)
  }

  private fun saveToPreferences(key: String, value: String) {
    try {
      // Try EncryptedSharedPreferences first
      val masterKey = MasterKey.Builder(reactContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

      val encryptedPrefs = EncryptedSharedPreferences.create(
        reactContext,
        SHARED_PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      )

      encryptedPrefs.edit()
        .putString(key, value)
        .apply()
    } catch (e: Exception) {
      // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
      reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
        .edit()
        .putString(key, value)
        .apply()
    }
  }

  private fun loadFromPreferences(key: String): String? {
    return try {
      // Try EncryptedSharedPreferences first
      val masterKey = MasterKey.Builder(reactContext)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

      val encryptedPrefs = EncryptedSharedPreferences.create(
        reactContext,
        SHARED_PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
      )

      encryptedPrefs.getString(key, null)
    } catch (e: Exception) {
      // Fallback to regular SharedPreferences if EncryptedSharedPreferences fails
      reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
        .getString(key, null)
    }
  }

  private fun isKeyRequiresAuthentication(keyAlias: String): Boolean {
    return try {
      val key = keyStore.getKey(keyAlias, null) as SecretKey
      val keyFactory = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
      val keyInfo = keyFactory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
      keyInfo.isUserAuthenticationRequired
    } catch (e: Exception) {
      false
    }
  }

  /**
   * Clean up corrupted EncryptedSharedPreferences data
   */
  private fun cleanupCorruptedData() {
    try {
      // Clear both encrypted and regular preferences to ensure clean state
      reactContext.getSharedPreferences(SHARED_PREFS_NAME, 0)
        .edit()
        .clear()
        .apply()

      // Also try to clear the encrypted preferences file
      val encryptedPrefsFile = reactContext.getSharedPreferences("${SHARED_PREFS_NAME}_encrypted", 0)
      encryptedPrefsFile.edit().clear().apply()

    } catch (e: Exception) {
      // Ignore cleanup errors
    }
  }

  @ReactMethod
  fun cleanupStorage(promise: Promise) {
    try {
      cleanupCorruptedData()
      promise.resolve(true)
    } catch (e: Exception) {
      promise.reject("CLEANUP_ERROR", "Failed to cleanup storage: ${e.message}", e)
    }
  }

  private fun authenticateAndDecrypt(
    keyAlias: String,
    encryptedValue: String,
    promise: Promise,
    options: ReadableMap
  ) {
    val activity = currentActivity as? FragmentActivity
    if (activity == null) {
      promise.reject("NO_ACTIVITY", "No current activity available for authentication")
      return
    }

    currentActivity?.runOnUiThread {
      try {
        val secretKey = keyStore.getKey(keyAlias, null) as? SecretKey
          ?: throw IllegalStateException("Secret key not found for alias: $keyAlias")

        val combined = Base64.decode(encryptedValue, Base64.NO_WRAP)
        if (combined.size < GCM_IV_LENGTH + GCM_TAG_LENGTH) {
          throw IllegalArgumentException("Invalid encrypted data length")
        }
        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val encryptedData = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

        val cipher = Cipher.getInstance(TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH * 8, iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)

        val executor = ContextCompat.getMainExecutor(activity)
        val biometricPrompt = BiometricPrompt(
          activity,
          executor,
          object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
              super.onAuthenticationSucceeded(result)
              try {
                val cryptoCipher = result.cryptoObject?.cipher
                if (cryptoCipher == null) {
                  promise.reject("CIPHER_ERROR", "CryptoObject cipher is null")
                  return
                }
                val decryptedBytes = cryptoCipher.doFinal(encryptedData)
                val decryptedValue = String(decryptedBytes, Charsets.UTF_8)
                promise.resolve(decryptedValue)
              } catch (e: Exception) {
                promise.reject("DECRYPTION_ERROR", "Failed to decrypt after auth: ${e.message}", e)
              }
            }

            override fun onAuthenticationFailed() {
              super.onAuthenticationFailed()
              promise.reject("AUTHENTICATION_FAILED", "Authentication failed")
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
              super.onAuthenticationError(errorCode, errString)
              when (errorCode) {
                BiometricPrompt.ERROR_USER_CANCELED,
                BiometricPrompt.ERROR_CANCELED -> promise.reject(
                  "AUTHENTICATION_CANCELLED",
                  "Authentication cancelled"
                )
                else -> promise.reject("AUTHENTICATION_ERROR", "Authentication error: $errString")
              }
            }
          }
        )

        val promptTitle = options.getString("authenticatePrompt") ?: "Authenticate to access data"
        val promptSubtitle = options.getString("authenticatePromptSubtitle")
          ?: "Use your biometric credential to access this data"

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
          .setTitle(promptTitle)
          .setSubtitle(promptSubtitle)
          .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
          .build()

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))

      } catch (e: Exception) {
        promise.reject("CIPHER_INIT_ERROR", "Failed to init cipher for decryption: ${e.message}", e)
      }
    }
  }
}
