package ai.guard8.shield

import android.util.Base64
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

/**
 * Time-based One-Time Password generator/verifier (RFC 6238).
 *
 * Compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.
 *
 * Example:
 * ```kotlin
 * val secret = TOTP.generateSecret()
 * val totp = TOTP(secret)
 * val code = totp.generate()
 * totp.verify(code) // true
 * ```
 */
class TOTP(
    private val secret: ByteArray,
    private val digits: Int = 6,
    private val interval: Int = 30,
    private val algorithm: Algorithm = Algorithm.SHA1
) {

    /**
     * Supported HMAC algorithms.
     */
    enum class Algorithm(val value: String, val hmacName: String) {
        SHA1("SHA1", "HmacSHA1"),
        SHA256("SHA256", "HmacSHA256")
    }

    companion object {
        /**
         * Generate random secret for new 2FA setup.
         *
         * @param length Secret length in bytes (default: 20)
         * @return Random secret bytes
         */
        @JvmStatic
        @JvmOverloads
        fun generateSecret(length: Int = 20): ByteArray {
            val secret = ByteArray(length)
            SecureRandom().nextBytes(secret)
            return secret
        }

        /**
         * Convert secret to base32 for QR codes.
         *
         * @param secret Secret bytes
         * @return Base32 encoded string (without padding)
         */
        @JvmStatic
        fun secretToBase32(secret: ByteArray): String {
            return base32Encode(secret).trimEnd('=')
        }

        /**
         * Parse base32 secret from authenticator app.
         *
         * @param b32 Base32 encoded secret
         * @return Secret bytes
         */
        @JvmStatic
        fun secretFromBase32(b32: String): ByteArray {
            // Add padding if needed
            val padded = b32.uppercase().let { s ->
                val padding = (8 - (s.length % 8)) % 8
                s + "=".repeat(padding)
            }
            return base32Decode(padded)
        }

        private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

        private fun base32Encode(data: ByteArray): String {
            if (data.isEmpty()) return ""
            val result = StringBuilder()
            var buffer = 0
            var bitsLeft = 0

            for (byte in data) {
                buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
                bitsLeft += 8
                while (bitsLeft >= 5) {
                    val index = (buffer shr (bitsLeft - 5)) and 0x1F
                    result.append(BASE32_ALPHABET[index])
                    bitsLeft -= 5
                }
            }

            if (bitsLeft > 0) {
                val index = (buffer shl (5 - bitsLeft)) and 0x1F
                result.append(BASE32_ALPHABET[index])
            }

            // Add padding
            while (result.length % 8 != 0) {
                result.append('=')
            }

            return result.toString()
        }

        private fun base32Decode(data: String): ByteArray {
            val cleanData = data.uppercase().trimEnd('=')
            if (cleanData.isEmpty()) return byteArrayOf()

            val result = mutableListOf<Byte>()
            var buffer = 0
            var bitsLeft = 0

            for (char in cleanData) {
                val value = BASE32_ALPHABET.indexOf(char)
                if (value == -1) continue
                buffer = (buffer shl 5) or value
                bitsLeft += 5
                if (bitsLeft >= 8) {
                    result.add((buffer shr (bitsLeft - 8)).toByte())
                    bitsLeft -= 8
                }
            }

            return result.toByteArray()
        }
    }

    /**
     * Generate current TOTP code.
     *
     * @param timestamp Unix timestamp in seconds (default: current time)
     * @return OTP code as string (zero-padded)
     */
    @JvmOverloads
    fun generate(timestamp: Long = System.currentTimeMillis() / 1000): String {
        val counter = timestamp / interval
        return hotp(counter)
    }

    /**
     * Verify TOTP code with time window.
     *
     * @param code User-provided code
     * @param timestamp Time to verify against (default: now)
     * @param window Number of intervals to check before/after (default: 1)
     * @return True if code is valid
     */
    @JvmOverloads
    fun verify(
        code: String,
        timestamp: Long = System.currentTimeMillis() / 1000,
        window: Int = 1
    ): Boolean {
        val counter = timestamp / interval

        // Check current and adjacent intervals (handles clock skew)
        for (offset in -window..window) {
            val expected = hotp(counter + offset)
            if (constantTimeEquals(code, expected)) {
                return true
            }
        }
        return false
    }

    /**
     * Generate URI for QR code (otpauth://).
     *
     * @param account User account identifier (e.g., email)
     * @param issuer Service name (default: "Shield")
     * @return otpauth:// URI for QR code generation
     */
    @JvmOverloads
    fun provisioningUri(account: String, issuer: String = "Shield"): String {
        val secretB32 = secretToBase32(secret)
        return "otpauth://totp/$issuer:$account" +
                "?secret=$secretB32&issuer=$issuer" +
                "&algorithm=${algorithm.value}&digits=$digits"
    }

    /**
     * HOTP algorithm (RFC 4226).
     */
    private fun hotp(counter: Long): String {
        // Counter as 8-byte big-endian
        val counterBytes = ByteArray(8)
        var value = counter
        for (i in 7 downTo 0) {
            counterBytes[i] = (value and 0xFF).toByte()
            value = value shr 8
        }

        // HMAC
        val mac = Mac.getInstance(algorithm.hmacName)
        mac.init(SecretKeySpec(secret, algorithm.hmacName))
        val h = mac.doFinal(counterBytes)

        // Dynamic truncation
        val offset = (h[h.size - 1] and 0x0F).toInt()
        val codeInt = ((h[offset].toInt() and 0x7F) shl 24) or
                ((h[offset + 1].toInt() and 0xFF) shl 16) or
                ((h[offset + 2].toInt() and 0xFF) shl 8) or
                (h[offset + 3].toInt() and 0xFF)

        // Modulo to get digits
        var code = (codeInt % Math.pow(10.0, digits.toDouble()).toInt()).toString()
        return code.padStart(digits, '0')
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }
}

/**
 * Recovery codes for 2FA backup.
 *
 * Use when user loses access to their authenticator app.
 * Each code can only be used once.
 *
 * Example:
 * ```kotlin
 * val recovery = RecoveryCodes()
 * println(recovery.codes) // Show codes to user
 * recovery.verify("ABCD-1234") // Consumes the code
 * ```
 */
class RecoveryCodes(
    codes: List<String>? = null
) {
    private val _codes: MutableSet<String>
    private val _used: MutableSet<String> = mutableSetOf()

    init {
        _codes = (codes ?: generateCodes()).toMutableSet()
    }

    companion object {
        /**
         * Generate recovery codes.
         *
         * @param count Number of codes to generate (default: 10)
         * @param length Length of each code in hex chars (default: 8)
         * @return List of recovery codes
         */
        @JvmStatic
        @JvmOverloads
        fun generateCodes(count: Int = 10, length: Int = 8): List<String> {
            val random = SecureRandom()
            return (0 until count).map {
                val bytes = ByteArray(length / 2)
                random.nextBytes(bytes)
                val hex = bytes.joinToString("") { "%02X".format(it) }
                "${hex.substring(0, 4)}-${hex.substring(4)}"
            }
        }
    }

    /**
     * Verify and consume a recovery code.
     *
     * @param code Recovery code to verify
     * @return True if valid (code is now consumed)
     */
    fun verify(code: String): Boolean {
        // Normalize format
        val normalized = code.uppercase().replace("-", "").replace(" ", "")
        val formatted = if (normalized.length == 8) {
            "${normalized.substring(0, 4)}-${normalized.substring(4)}"
        } else {
            code.uppercase()
        }

        if (formatted in _codes && formatted !in _used) {
            _used.add(formatted)
            return true
        }
        return false
    }

    /**
     * Number of unused recovery codes.
     */
    val remaining: Int
        get() = _codes.size - _used.size

    /**
     * Get all recovery codes (for display to user).
     */
    val codes: List<String>
        get() = _codes.sorted()
}
