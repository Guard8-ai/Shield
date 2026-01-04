package ai.guard8.shield

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * SymmetricSignature provides HMAC-based signatures.
 */
class SymmetricSignature private constructor(private val signingKey: ByteArray) : AutoCloseable {
    val verificationKey: ByteArray

    init {
        val data = "verify:".toByteArray() + signingKey
        verificationKey = Shield.sha256(data)
    }

    companion object {
        fun generate(): SymmetricSignature {
            return SymmetricSignature(Shield.randomBytes(Shield.KEY_SIZE))
        }

        fun fromPassword(password: String, identity: String): SymmetricSignature {
            val salt = Shield.sha256("sign:$identity".toByteArray())
            val key = Shield.pbkdf2(password, salt, Shield.ITERATIONS, Shield.KEY_SIZE)
            return SymmetricSignature(key)
        }

        fun withKey(signingKey: ByteArray): SymmetricSignature {
            require(signingKey.size == Shield.KEY_SIZE) { "Invalid key size" }
            return SymmetricSignature(signingKey.copyOf())
        }
    }

    fun sign(message: ByteArray, includeTimestamp: Boolean = false): ByteArray {
        if (includeTimestamp) {
            val timestamp = System.currentTimeMillis() / 1000
            val tsBytes = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(timestamp).array()

            val sigData = tsBytes + message
            val sig = Shield.hmacSha256(signingKey, sigData)

            return tsBytes + sig
        }

        return Shield.hmacSha256(signingKey, message)
    }

    fun verify(message: ByteArray, signature: ByteArray, verificationKey: ByteArray, maxAge: Long = 0): Boolean {
        if (!Shield.constantTimeEquals(verificationKey, this.verificationKey)) {
            return false
        }

        if (signature.size == 40) {
            val timestamp = ByteBuffer.wrap(signature, 0, 8).order(ByteOrder.LITTLE_ENDIAN).long

            if (maxAge > 0) {
                val now = System.currentTimeMillis() / 1000
                val diff = kotlin.math.abs(now - timestamp)
                if (diff > maxAge) return false
            }

            val sigData = signature.copyOfRange(0, 8) + message
            val expected = Shield.hmacSha256(signingKey, sigData)

            return Shield.constantTimeEquals(signature.copyOfRange(8, 40), expected)
        }

        if (signature.size == 32) {
            val expected = Shield.hmacSha256(signingKey, message)
            return Shield.constantTimeEquals(signature, expected)
        }

        return false
    }

    fun fingerprint(): String {
        val hash = Shield.sha256(verificationKey)
        return hash.take(8).joinToString("") { "%02x".format(it) }
    }

    override fun close() {
        Shield.secureWipe(signingKey)
    }
}

/**
 * LamportSignature provides one-time post-quantum signatures.
 */
class LamportSignature private constructor() : AutoCloseable {
    private val privateKey = Array(256) { Array(2) { ByteArray(Shield.KEY_SIZE) } }
    val publicKey = ByteArray(256 * 64)
    var isUsed = false
        private set

    companion object {
        fun generate(): LamportSignature {
            val ls = LamportSignature()

            for (i in 0 until 256) {
                ls.privateKey[i][0] = Shield.randomBytes(Shield.KEY_SIZE)
                ls.privateKey[i][1] = Shield.randomBytes(Shield.KEY_SIZE)

                val h0 = Shield.sha256(ls.privateKey[i][0])
                val h1 = Shield.sha256(ls.privateKey[i][1])

                System.arraycopy(h0, 0, ls.publicKey, i * 64, 32)
                System.arraycopy(h1, 0, ls.publicKey, i * 64 + 32, 32)
            }

            return ls
        }

        fun verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean {
            if (signature.size != 256 * 32 || publicKey.size != 256 * 64) {
                return false
            }

            val msgHash = Shield.sha256(message)

            for (i in 0 until 256) {
                val byteIdx = i / 8
                val bitIdx = i % 8
                val bit = (msgHash[byteIdx].toInt() shr bitIdx) and 1

                val revealed = signature.copyOfRange(i * 32, (i + 1) * 32)
                val hashed = Shield.sha256(revealed)

                val expected = if (bit == 1) {
                    publicKey.copyOfRange(i * 64 + 32, i * 64 + 64)
                } else {
                    publicKey.copyOfRange(i * 64, i * 64 + 32)
                }

                if (!Shield.constantTimeEquals(hashed, expected)) {
                    return false
                }
            }

            return true
        }
    }

    fun sign(message: ByteArray): ByteArray {
        if (isUsed) throw ShieldException.LamportKeyUsed()
        isUsed = true

        val msgHash = Shield.sha256(message)
        val signature = ByteArray(256 * 32)

        for (i in 0 until 256) {
            val byteIdx = i / 8
            val bitIdx = i % 8
            val bit = (msgHash[byteIdx].toInt() shr bitIdx) and 1

            System.arraycopy(privateKey[i][bit], 0, signature, i * 32, 32)
        }

        return signature
    }

    fun fingerprint(): String {
        val hash = Shield.sha256(publicKey)
        return hash.take(8).joinToString("") { "%02x".format(it) }
    }

    override fun close() {
        for (i in 0 until 256) {
            Shield.secureWipe(privateKey[i][0])
            Shield.secureWipe(privateKey[i][1])
        }
    }
}
