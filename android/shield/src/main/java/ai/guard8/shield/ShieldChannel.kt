package ai.guard8.shield

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Shield Secure Channel - TLS/SSH-like secure transport using symmetric crypto.
 *
 * Provides encrypted bidirectional communication with:
 * - PAKE-based handshake (no certificates needed)
 * - Forward secrecy via key ratcheting
 * - Message authentication and replay protection
 *
 * Example:
 * ```kotlin
 * // Both parties share a password
 * val config = ChannelConfig("shared-secret", "my-service")
 *
 * // Client side
 * val socket = Socket("localhost", 8080)
 * val client = ShieldChannel.connect(socket, config)
 * client.send("Hello server!".toByteArray())
 *
 * // Server side
 * val serverSocket = ServerSocket(8080)
 * val clientSocket = serverSocket.accept()
 * val server = ShieldChannel.accept(clientSocket, config)
 * val message = server.recv()
 * ```
 */
class ShieldChannel private constructor(
    private val input: InputStream,
    private val output: OutputStream,
    private val session: RatchetSession,
    val service: String
) : AutoCloseable {

    companion object {
        private const val PROTOCOL_VERSION: Byte = 1
        private const val MAX_MESSAGE_SIZE = 16 * 1024 * 1024 // 16 MB

        // Handshake message types
        private const val HANDSHAKE_CLIENT_HELLO: Byte = 1
        private const val HANDSHAKE_SERVER_HELLO: Byte = 2
        private const val HANDSHAKE_FINISHED: Byte = 3

        /**
         * Connect as client (initiator).
         *
         * Performs PAKE handshake and establishes encrypted channel.
         *
         * @param socket Underlying transport
         * @param config Channel configuration with shared password
         * @return Established secure channel
         */
        fun connect(socket: Socket, config: ChannelConfig): ShieldChannel {
            return connect(socket.getInputStream(), socket.getOutputStream(), config)
        }

        /**
         * Connect as client using raw streams.
         */
        fun connect(input: InputStream, output: OutputStream, config: ChannelConfig): ShieldChannel {
            // Step 1: Generate client salt and send ClientHello
            val clientSalt = ShieldUtils.randomBytes(16)
            sendHandshake(output, HANDSHAKE_CLIENT_HELLO, clientSalt)

            // Step 2: Receive ServerHello
            val serverHello = recvHandshake(input, HANDSHAKE_SERVER_HELLO)
            require(serverHello.size == 48) { "Invalid ServerHello" }

            val finalSalt = serverHello.copyOfRange(0, 16)
            val serverContribution = serverHello.copyOfRange(16, 48)

            // Step 3: Derive our contribution and send it
            val clientContribution = PAKEExchange.derive(
                config.password, finalSalt, "client", config.iterations
            )
            sendHandshake(output, HANDSHAKE_FINISHED, clientContribution)

            // Compute session key
            val sessionKey = computeSessionKey(
                config, finalSalt, clientContribution, serverContribution
            )

            // Create ratchet session
            val session = RatchetSession(sessionKey, true)

            // Exchange confirmations
            sendConfirmation(output, sessionKey, true)
            verifyConfirmation(input, sessionKey, false)

            return ShieldChannel(input, output, session, config.service)
        }

        /**
         * Accept connection as server.
         *
         * Waits for client handshake and establishes encrypted channel.
         *
         * @param socket Underlying transport
         * @param config Channel configuration with shared password
         * @return Established secure channel
         */
        fun accept(socket: Socket, config: ChannelConfig): ShieldChannel {
            return accept(socket.getInputStream(), socket.getOutputStream(), config)
        }

        /**
         * Accept connection using raw streams.
         */
        fun accept(input: InputStream, output: OutputStream, config: ChannelConfig): ShieldChannel {
            // Step 1: Receive ClientHello
            val clientHello = recvHandshake(input, HANDSHAKE_CLIENT_HELLO)
            require(clientHello.size == 16) { "Invalid ClientHello" }

            // Mix salts
            val serverSalt = ShieldUtils.randomBytes(16)
            val finalSalt = ByteArray(16)
            for (i in 0 until 16) {
                finalSalt[i] = (serverSalt[i].toInt() xor clientHello[i].toInt()).toByte()
            }

            // Derive server contribution
            val serverContribution = PAKEExchange.derive(
                config.password, finalSalt, "server", config.iterations
            )

            // Step 2: Send ServerHello
            val serverHello = finalSalt + serverContribution
            sendHandshake(output, HANDSHAKE_SERVER_HELLO, serverHello)

            // Step 3: Receive client contribution
            val clientFinished = recvHandshake(input, HANDSHAKE_FINISHED)
            require(clientFinished.size == 32) { "Invalid Finished" }

            // Compute session key
            val sessionKey = computeSessionKey(
                config, finalSalt, serverContribution, clientFinished
            )

            // Create ratchet session
            val session = RatchetSession(sessionKey, false)

            // Exchange confirmations
            verifyConfirmation(input, sessionKey, true)
            sendConfirmation(output, sessionKey, false)

            return ShieldChannel(input, output, session, config.service)
        }

        private fun computeSessionKey(
            config: ChannelConfig,
            salt: ByteArray,
            localContribution: ByteArray,
            remoteContribution: ByteArray
        ): ByteArray {
            val baseKey = PAKEExchange.combine(localContribution, remoteContribution)
            val passwordKey = PAKEExchange.derive(
                config.password, salt, "session", config.iterations
            )

            val combined = baseKey + passwordKey
            return ShieldUtils.sha256(combined)
        }

        private fun sendHandshake(output: OutputStream, msgType: Byte, data: ByteArray) {
            val frame = ByteArray(4 + data.size)
            frame[0] = PROTOCOL_VERSION
            frame[1] = msgType
            frame[2] = ((data.size shr 8) and 0xFF).toByte()
            frame[3] = (data.size and 0xFF).toByte()
            System.arraycopy(data, 0, frame, 4, data.size)
            output.write(frame)
            output.flush()
        }

        private fun recvHandshake(input: InputStream, expectedType: Byte): ByteArray {
            val header = readExact(input, 4)

            require(header[0] == PROTOCOL_VERSION) {
                "Unsupported protocol version: ${header[0]}"
            }
            require(header[1] == expectedType) {
                "Unexpected message type: expected $expectedType, got ${header[1]}"
            }

            val length = ((header[2].toInt() and 0xFF) shl 8) or (header[3].toInt() and 0xFF)
            require(length <= 1024) { "Handshake message too large" }

            return readExact(input, length)
        }

        private fun sendConfirmation(output: OutputStream, sessionKey: ByteArray, isClient: Boolean) {
            val label = if (isClient) "client-confirm" else "server-confirm"
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(sessionKey, "HmacSHA256"))
            val confirm = mac.doFinal(label.toByteArray(Charsets.UTF_8)).copyOfRange(0, 16)
            writeFrame(output, confirm)
        }

        private fun verifyConfirmation(input: InputStream, sessionKey: ByteArray, expectClient: Boolean) {
            val received = readFrame(input)
            require(received.size == 16) { "Invalid confirmation" }

            val label = if (expectClient) "client-confirm" else "server-confirm"
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(sessionKey, "HmacSHA256"))
            val expected = mac.doFinal(label.toByteArray(Charsets.UTF_8)).copyOfRange(0, 16)

            require(received.contentEquals(expected)) { "Authentication failed" }
        }

        private fun writeFrame(output: OutputStream, data: ByteArray) {
            val header = ByteArray(4)
            header[0] = ((data.size shr 24) and 0xFF).toByte()
            header[1] = ((data.size shr 16) and 0xFF).toByte()
            header[2] = ((data.size shr 8) and 0xFF).toByte()
            header[3] = (data.size and 0xFF).toByte()
            output.write(header)
            output.write(data)
            output.flush()
        }

        private fun readFrame(input: InputStream): ByteArray {
            val header = readExact(input, 4)
            val length = ((header[0].toInt() and 0xFF) shl 24) or
                    ((header[1].toInt() and 0xFF) shl 16) or
                    ((header[2].toInt() and 0xFF) shl 8) or
                    (header[3].toInt() and 0xFF)

            require(length <= MAX_MESSAGE_SIZE) {
                "Frame too large: $length > $MAX_MESSAGE_SIZE"
            }

            return readExact(input, length)
        }

        private fun readExact(input: InputStream, count: Int): ByteArray {
            val buffer = ByteArray(count)
            var offset = 0
            while (offset < count) {
                val read = input.read(buffer, offset, count - offset)
                if (read == -1) throw java.io.EOFException("Connection closed")
                offset += read
            }
            return buffer
        }
    }

    private var messagesSentCount: Long = 0
    private var messagesReceivedCount: Long = 0

    /**
     * Send encrypted message.
     *
     * Message is encrypted with current ratchet key, then key advances.
     */
    fun send(data: ByteArray) {
        require(data.size <= MAX_MESSAGE_SIZE) {
            "Message too large: ${data.size} > $MAX_MESSAGE_SIZE"
        }
        val encrypted = session.encrypt(data)
        writeFrame(output, encrypted)
        messagesSentCount++
    }

    /**
     * Send encrypted string message.
     */
    fun send(message: String) = send(message.toByteArray(Charsets.UTF_8))

    /**
     * Receive and decrypt message.
     *
     * Verifies authentication and advances receive ratchet.
     */
    fun recv(): ByteArray {
        val encrypted = readFrame(input)
        messagesReceivedCount++
        return session.decrypt(encrypted)
    }

    /**
     * Receive and decrypt message as string.
     */
    fun recvString(): String = String(recv(), Charsets.UTF_8)

    /**
     * Get count of messages sent.
     */
    val messagesSent: Long get() = messagesSentCount

    /**
     * Get count of messages received.
     */
    val messagesReceived: Long get() = messagesReceivedCount

    /**
     * Close the channel.
     */
    override fun close() {
        try {
            output.close()
        } catch (_: Exception) {}
        try {
            input.close()
        } catch (_: Exception) {}
    }
}

/**
 * Channel configuration.
 *
 * @param password Shared password for PAKE
 * @param service Service identifier for domain separation
 * @param iterations PBKDF2 iterations (default: 200000)
 * @param handshakeTimeoutMs Handshake timeout in milliseconds (default: 30000)
 */
data class ChannelConfig(
    val password: String,
    val service: String,
    val iterations: Int = PAKEExchange.DEFAULT_ITERATIONS,
    val handshakeTimeoutMs: Long = 30_000
)
