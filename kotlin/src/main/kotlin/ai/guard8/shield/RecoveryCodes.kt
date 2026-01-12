package ai.guard8.shield

import java.security.SecureRandom

/**
 * RecoveryCodes - Backup codes for 2FA.
 *
 * Use when user loses access to their authenticator app.
 * Each code can only be used once.
 */
class RecoveryCodes(codes: List<String> = generate()) {
    private val codes = codes.toMutableSet()
    private val used = mutableSetOf<String>()

    /** Secondary constructor for backward compatibility */
    constructor(count: Int) : this(generate(count))

    companion object {
        private val random = SecureRandom()
        private val hexChars = "0123456789ABCDEF".toCharArray()

        /**
         * Generate recovery codes.
         *
         * @param count Number of codes to generate
         * @param length Length of each code (must be even)
         * @return List of formatted codes (XXXX-XXXX)
         */
        @JvmStatic
        @JvmOverloads
        fun generate(count: Int = 10, length: Int = 8): List<String> {
            return (0 until count).map {
                val bytes = ByteArray(length / 2)
                random.nextBytes(bytes)

                val code = buildString {
                    bytes.forEach { byte ->
                        append(hexChars[(byte.toInt() shr 4) and 0x0F])
                        append(hexChars[byte.toInt() and 0x0F])
                    }
                }

                // Format as XXXX-XXXX
                "${code.substring(0, 4)}-${code.substring(4)}"
            }
        }
    }

    /**
     * Verify and consume a recovery code.
     *
     * @param code Code to verify
     * @return true if valid (code is now consumed)
     */
    fun verify(code: String): Boolean {
        // Normalize format (remove dashes, uppercase)
        val normalized = code.replace("-", "").uppercase()
        if (normalized.length < 8) return false

        val formatted = "${normalized.substring(0, 4)}-${normalized.substring(4)}"

        if (formatted in used) {
            return false
        }

        return if (formatted in codes) {
            used.add(formatted)
            codes.remove(formatted)
            true
        } else {
            false
        }
    }

    /**
     * Get remaining (unused) codes.
     */
    val remainingCodes: List<String>
        get() = codes.toList()

    /** Alias for backward compatibility */
    val allCodes: List<String>
        get() = remainingCodes

    /**
     * Get count of remaining codes.
     */
    val remainingCount: Int
        get() = codes.size

    /** Alias for backward compatibility */
    val remaining: Int
        get() = remainingCount

    /**
     * Get used codes.
     */
    val usedCodes: List<String>
        get() = used.toList()
}
