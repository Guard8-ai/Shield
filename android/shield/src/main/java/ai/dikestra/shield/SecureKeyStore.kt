package ai.dikestra.shield

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Secure key storage using Android Keystore and EncryptedSharedPreferences.
 *
 * Provides hardware-backed key storage when available.
 *
 * Example:
 * ```kotlin
 * val keyStore = SecureKeyStore(context)
 *
 * // Store a key
 * keyStore.storeKey("my_key", secretKey)
 *
 * // Retrieve a key
 * val key = keyStore.getKey("my_key")
 *
 * // Generate hardware-backed key
 * val hwKey = keyStore.generateHardwareKey("hw_key")
 * ```
 */
class SecureKeyStore(private val context: Context) {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS_NAME = "shield_secure_prefs"
        private const val KEY_PREFIX = "shield_key_"
    }

    private val masterKey: MasterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private val encryptedPrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    /**
     * Store a key securely in EncryptedSharedPreferences.
     *
     * @param alias Key identifier
     * @param key Key bytes to store
     */
    fun storeKey(alias: String, key: ByteArray) {
        encryptedPrefs.edit()
            .putString(KEY_PREFIX + alias, key.toHexString())
            .apply()
    }

    /**
     * Retrieve a stored key.
     *
     * @param alias Key identifier
     * @return Key bytes, or null if not found
     */
    fun getKey(alias: String): ByteArray? {
        val hex = encryptedPrefs.getString(KEY_PREFIX + alias, null) ?: return null
        return hex.hexToByteArray()
    }

    /**
     * Delete a stored key.
     *
     * @param alias Key identifier
     * @return true if key was deleted
     */
    fun deleteKey(alias: String): Boolean {
        if (encryptedPrefs.contains(KEY_PREFIX + alias)) {
            encryptedPrefs.edit().remove(KEY_PREFIX + alias).apply()
            return true
        }
        // Also try hardware keystore
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
            return true
        }
        return false
    }

    /**
     * Check if a key exists.
     *
     * @param alias Key identifier
     * @return true if key exists
     */
    fun hasKey(alias: String): Boolean {
        return encryptedPrefs.contains(KEY_PREFIX + alias) || keyStore.containsAlias(alias)
    }

    /**
     * Generate a hardware-backed key in Android Keystore.
     *
     * This key never leaves the secure hardware (TEE/SE).
     *
     * @param alias Key identifier
     * @return Generated SecretKey
     */
    fun generateHardwareKey(alias: String): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )

        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    /**
     * Get a hardware-backed key from Android Keystore.
     *
     * @param alias Key identifier
     * @return SecretKey, or null if not found
     */
    fun getHardwareKey(alias: String): SecretKey? {
        return keyStore.getKey(alias, null) as? SecretKey
    }

    /**
     * Check if hardware-backed keys are available.
     */
    fun isHardwareBackedAvailable(): Boolean {
        return try {
            val testAlias = "_shield_hw_test_${System.currentTimeMillis()}"
            generateHardwareKey(testAlias)
            keyStore.deleteEntry(testAlias)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Create a Shield instance with a stored or new key.
     *
     * @param alias Key identifier
     * @param password Password for key derivation (if creating new)
     * @param service Service name for key derivation (if creating new)
     * @return Shield instance
     */
    fun getOrCreateShield(alias: String, password: String, service: String): Shield {
        val existingKey = getKey(alias)
        if (existingKey != null) {
            return Shield.withKey(existingKey)
        }

        // Derive a fresh key from the password using a random salt, persist it,
        // and return a Shield bound to exactly that key. First call and every
        // later call therefore operate in the same pre-shared-key mode (0x13)
        // with the same key, so data written before a restart stays decryptable.
        val salt = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val key = deriveKey(password, service, salt)
        storeKey(alias, key)
        return Shield.withKey(key)
    }

    private fun deriveKey(password: String, service: String, salt: ByteArray): ByteArray {
        // Salt layout matches Shield.create: random_salt(16) || service bytes,
        // so the derived key is per-service and not precomputable.
        val pbkdf2Salt = salt + service.toByteArray(Charsets.UTF_8)
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, 600_000, 256)
        return factory.generateSecret(spec).encoded
    }

    private fun ByteArray.toHexString(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToByteArray(): ByteArray {
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
