package ai.guard8.shield

import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * TOTP - Time-based One-Time Password (RFC 6238)
 */
class TOTP(
    private val secret: ByteArray,
    private val digits: Int = DEFAULT_DIGITS,
    private val interval: Long = DEFAULT_INTERVAL
) : AutoCloseable {

    companion object {
        const val DEFAULT_DIGITS = 6
        const val DEFAULT_INTERVAL = 30L
        const val DEFAULT_SECRET_SIZE = 20

        fun generateSecret(): ByteArray = Shield.randomBytes(DEFAULT_SECRET_SIZE)

        fun fromBase32(encoded: String): TOTP = TOTP(Base32.decode(encoded))
    }

    fun generate(timestamp: Long = System.currentTimeMillis() / 1000): String {
        val counter = timestamp / interval
        return generateHOTP(counter)
    }

    fun verify(code: String, timestamp: Long = System.currentTimeMillis() / 1000, window: Int = 1): Boolean {
        for (i in 0..window) {
            if (generate(timestamp - i * interval) == code) return true
            if (i > 0 && generate(timestamp + i * interval) == code) return true
        }
        return false
    }

    private fun generateHOTP(counter: Long): String {
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()

        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(secret, "HmacSHA1"))
        val hash = mac.doFinal(counterBytes)

        val offset = hash[19].toInt() and 0x0f
        val code = ((hash[offset].toInt() and 0x7f) shl 24) or
                   ((hash[offset + 1].toInt() and 0xff) shl 16) or
                   ((hash[offset + 2].toInt() and 0xff) shl 8) or
                   (hash[offset + 3].toInt() and 0xff)

        var modulo = 1
        repeat(digits) { modulo *= 10 }

        return (code % modulo).toString().padStart(digits, '0')
    }

    fun toBase32(): String = Base32.encode(secret)

    fun provisioningUri(account: String, issuer: String): String {
        val secretB32 = toBase32()
        return "otpauth://totp/$issuer:$account?secret=$secretB32&issuer=$issuer&algorithm=SHA1&digits=$digits&period=$interval"
    }

    fun getSecret(): ByteArray = secret.copyOf()

    override fun close() {
        Shield.secureWipe(secret)
    }
}

/**
 * Recovery codes for backup authentication.
 */
class RecoveryCodes(count: Int = 10) {
    private val codes = mutableSetOf<String>()

    init {
        repeat(count) {
            codes.add(generateCode())
        }
    }

    private fun generateCode(): String {
        val bytes = Shield.randomBytes(4)
        val part1 = ((bytes[0].toInt() and 0xff) shl 8) or (bytes[1].toInt() and 0xff)
        val part2 = ((bytes[2].toInt() and 0xff) shl 8) or (bytes[3].toInt() and 0xff)
        return String.format("%04X-%04X", part1, part2)
    }

    fun verify(code: String): Boolean {
        val normalized = code.uppercase().replace(" ", "")
        val formatted = if (normalized.length == 8) "${normalized.take(4)}-${normalized.takeLast(4)}" else normalized

        return if (codes.contains(formatted)) {
            codes.remove(formatted)
            true
        } else {
            false
        }
    }

    val allCodes: List<String> get() = codes.toList()
    val remaining: Int get() = codes.size
}

// Simple Base32 encoder/decoder
private object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(data: ByteArray): String {
        val result = StringBuilder()
        var buffer = 0
        var bufferLength = 0

        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xff)
            bufferLength += 8
            while (bufferLength >= 5) {
                bufferLength -= 5
                result.append(ALPHABET[(buffer shr bufferLength) and 0x1f])
            }
        }
        if (bufferLength > 0) {
            result.append(ALPHABET[(buffer shl (5 - bufferLength)) and 0x1f])
        }
        return result.toString()
    }

    fun decode(encoded: String): ByteArray {
        val clean = encoded.uppercase().replace("=", "")
        val result = ByteArray(clean.length * 5 / 8)
        var buffer = 0
        var bufferLength = 0
        var index = 0

        for (char in clean) {
            val value = ALPHABET.indexOf(char)
            if (value < 0) continue
            buffer = (buffer shl 5) or value
            bufferLength += 5
            if (bufferLength >= 8) {
                bufferLength -= 8
                result[index++] = ((buffer shr bufferLength) and 0xff).toByte()
            }
        }
        return result.copyOf(index)
    }
}
