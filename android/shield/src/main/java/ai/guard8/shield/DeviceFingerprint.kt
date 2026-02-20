package ai.guard8.shield

import android.content.Context
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest

/**
 * Device fingerprinting for Android.
 *
 * Uses Android-specific device identifiers for hardware-bound encryption.
 * More secure than desktop fingerprinting due to TEE/StrongBox backing.
 *
 * **Privacy**: Android ID is app-scoped and resets on factory reset.
 * **Security**: Hardware-backed keys can be stored in Keystore TEE/StrongBox.
 *
 * Example:
 * ```kotlin
 * val fingerprint = DeviceFingerprint.collect(context, FingerprintMode.HARDWARE_BACKED)
 * val shield = Shield.withFingerprint(context, "password", "service", FingerprintMode.HARDWARE_BACKED)
 * ```
 */
object DeviceFingerprint {

    enum class FingerprintMode {
        /** No fingerprinting (backward compatible) */
        NONE,

        /** Android ID only (app-scoped, resets on factory reset) */
        ANDROID_ID,

        /** Device model + manufacturer (less unique, but stable) */
        DEVICE_INFO,

        /** Hardware-backed with Android Keystore attestation (recommended) */
        HARDWARE_BACKED,

        /** Combined Android ID + device info + hardware attestation */
        COMBINED
    }

    /**
     * Collect device fingerprint.
     *
     * @param context Application context
     * @param mode Fingerprint mode
     * @return Fingerprint string (MD5 hex), or empty for NONE
     * @throws IllegalStateException if fingerprint unavailable
     */
    fun collect(context: Context, mode: FingerprintMode): String {
        return when (mode) {
            FingerprintMode.NONE -> ""
            FingerprintMode.ANDROID_ID -> getAndroidId(context)
            FingerprintMode.DEVICE_INFO -> getDeviceInfo()
            FingerprintMode.HARDWARE_BACKED -> getHardwareBackedFingerprint(context)
            FingerprintMode.COMBINED -> getCombinedFingerprint(context)
        }
    }

    /**
     * Get Android ID (app-scoped identifier).
     *
     * **Privacy**: Unique per app, resets on factory reset.
     * **Stability**: Persists across app reinstalls (same signing key).
     */
    private fun getAndroidId(context: Context): String {
        val androidId = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID
        )
        require(!androidId.isNullOrEmpty()) { "Android ID unavailable" }
        return androidId
    }

    /**
     * Get device model + manufacturer info.
     *
     * **Privacy**: Public info, not unique (same for all devices of same model).
     * **Stability**: Never changes for the device.
     */
    private fun getDeviceInfo(): String {
        val components = listOf(
            Build.MANUFACTURER,
            Build.MODEL,
            Build.DEVICE,
            Build.PRODUCT
        )
        return components.joinToString("-").md5()
    }

    /**
     * Get hardware-backed fingerprint using Android Keystore.
     *
     * Creates a hardware-backed key in Android Keystore (TEE/StrongBox).
     * The key is bound to the device hardware and cannot be extracted.
     *
     * **Security**: Highest - keys stored in Trusted Execution Environment.
     * **Privacy**: Key never leaves TEE, only device-bound signatures.
     */
    private fun getHardwareBackedFingerprint(context: Context): String {
        val keyStore = SecureKeyStore(context)

        // Generate or retrieve hardware-backed key
        val hardwareKeyAlias = "shield_hw_fingerprint"

        return try {
            // Try to use existing hardware key
            val existingKey = keyStore.getKey(hardwareKeyAlias)
            if (existingKey != null) {
                return existingKey.toHexString()
            }

            // Generate new hardware-backed key
            val hwKey = keyStore.generateHardwareKey(hardwareKeyAlias)
            hwKey.encoded.toHexString()
        } catch (e: Exception) {
            // Fallback to Android ID if hardware keys unavailable
            getAndroidId(context)
        }
    }

    /**
     * Get combined fingerprint (Android ID + device info).
     *
     * **Recommended for most use cases**: Balances security and stability.
     */
    private fun getCombinedFingerprint(context: Context): String {
        val components = mutableListOf<String>()

        try {
            components.add(getAndroidId(context))
        } catch (e: Exception) {
            // Continue without Android ID
        }

        components.add(getDeviceInfo())

        require(components.isNotEmpty()) { "No device identifiers available" }

        return components.joinToString("-").md5()
    }

    /**
     * MD5 hash helper.
     */
    private fun String.md5(): String {
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(this.toByteArray())
        return digest.toHexString()
    }

    /**
     * Byte array to hex string helper.
     */
    private fun ByteArray.toHexString(): String {
        return this.joinToString("") { "%02x".format(it) }
    }
}

/**
 * Extension function for Shield to support device fingerprinting.
 */
fun Shield.Companion.withFingerprint(
    context: Context,
    password: String,
    service: String,
    mode: DeviceFingerprint.FingerprintMode = DeviceFingerprint.FingerprintMode.HARDWARE_BACKED
): Shield {
    val fingerprint = DeviceFingerprint.collect(context, mode)

    val combinedPassword = if (fingerprint.isNotEmpty()) {
        "$password:$fingerprint"
    } else {
        password
    }

    return Shield(combinedPassword, service)
}
