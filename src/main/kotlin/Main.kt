// KotlinOTGameServer.kt
package org.example

import ChecksumMethod
import GameClientSession
import adlerChecksum
import models.AccountToken
import models.AccountTokenTable
import models.Player
import models.PlayersTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.jetbrains.exposed.sql.and
import org.jetbrains.exposed.sql.transactions.transaction
import plugins.configureDatabases
import java.io.BufferedReader
import java.io.File
import java.io.StringReader
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.RSAPrivateCrtKeySpec
import java.util.Base64
import java.util.concurrent.Executors
import java.security.Security
import java.time.LocalDateTime
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.pow

sealed class ParsedLoginResult {
    data class Success(val login: ParsedLogin) : ParsedLoginResult()
    data class FailureBeforeXtea(val reason: String) : ParsedLoginResult()
    data class FailureAfterXtea(val reason: String, val xtea: IntArray) : ParsedLoginResult()
}

class NetworkBuffer(private val buf: ByteArray) {
    fun getBackingArray(): ByteArray = buf
    private val bb: ByteBuffer = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
    fun remaining(): Int = bb.remaining()
    fun position(): Int = bb.position()
    fun setPosition(p: Int) {
        bb.position(p)
    }

    fun getByte(): Int = bb.get().toInt() and 0xFF
    fun getShort(): Int = bb.short.toInt() and 0xFFFF
    fun getInt(): Int = bb.int
    fun getUInt(): Long = bb.int.toLong() and 0xFFFFFFFFL
    fun get8(): Int = bb.get().toInt() and 0xFF
    fun get16(): Int = bb.short.toInt() and 0xFFFF
    fun get32(): Int = (bb.int.toLong() and 0xFFFFFFFF).toInt()

    fun getBytes(len: Int): ByteArray {
        val out = ByteArray(len)
        bb.get(out)
        return out
    }

    fun putBytesAt(pos: Int, data: ByteArray) {
        val old = bb.position()
        bb.position(pos)
        bb.put(data)
        bb.position(old)
    }

    fun readTibiaString(): String {
        if (remaining() < 2) return ""
        var len = get16()
        val bytes = getBytes(len)
        return String(bytes, Charsets.UTF_8)
    }

    fun asArray(): ByteArray = bb.array()
}

// ---------------- GameProtocol (unchanged) ----------------
class GameProtocol() {
    /**
     * Decrypts next RSA block (128 bytes) in place and returns true iff first decrypted byte == 0.
     */

    val RSA_PRIVATE_KEY: PrivateKey by lazy {
        // Read PEM text into one string
        val RSA_FILE_CONTENT: String =
            File("./key.pem").readText(Charsets.UTF_8)
        // Remove PEM headers/footers
        val base64Data = BufferedReader(StringReader(RSA_FILE_CONTENT))
            .readLines()
            .filterNot { it.contains("BEGIN") || it.contains("END") }
            .joinToString("")
            .replace("\\s".toRegex(), "")

        val bytes = Base64.getDecoder().decode(base64Data)

        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(bytes)
        val key = org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(seq)

        val spec = RSAPrivateCrtKeySpec(
            key.modulus,
            key.publicExponent,
            key.privateExponent,
            key.prime1,
            key.prime2,
            key.exponent1,
            key.exponent2,
            key.coefficient
        )

        KeyFactory.getInstance("RSA").generatePrivate(spec)
    }

    fun generateHMACSHA256TRIMMED(data: String, secret: String): String {
        val hmacSHA256 = Mac.getInstance("HmacSHA256")
        val secretKeySpec = SecretKeySpec(secret.toByteArray(), "HmacSHA256")
        hmacSHA256.init(secretKeySpec)
        val hash = hmacSHA256.doFinal(data.toByteArray())
        val hmac = hash.joinToString("") { String.format("%02x", it) }
        val hmacTrimmed = hmac.substring(0, hmac.length - 10)
        return hmacTrimmed
    }
    fun fastEquals(a: String, b: String): Boolean {
        if (a.length != b.length) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].code xor b[i].code)
        }
        return result == 0
    }
    @OptIn(ExperimentalUnsignedTypes::class)
    fun parseGameLoginPacket(packetBytes: ByteArray): ParsedLoginResult {
        var nb = NetworkBuffer(packetBytes)

        try {
            // --- PRELIM CHECKS (before XTEA) ---
            if (nb.remaining() < 2 + 2 + 4) {
                return ParsedLoginResult.FailureBeforeXtea("Packet too short")
            }

            repeat(6) { nb.get8() } // trash bytes

            val os = nb.get16()
            val version = nb.get16()
            val clientVersion = nb.get32()
            val oldProtocol = version <= 1100

            var versionString: String? = null
            var assetHash: String? = null
            var datRevision: Int? = null

            if (!oldProtocol) {
                versionString = nb.readTibiaString()
                if (version >= 1334) {
                    assetHash = nb.readTibiaString()
                }
            }
            if (version < 1334 && nb.remaining() >= 2) {
                datRevision = nb.get16()
            }

            val preview = nb.getByte()

            // --- RSA ---
            val decrypted = RSA_2.decrypt(
                nb.getBytes(minOf(nb.remaining(), 128)),
                RSA_PRIVATE_KEY
            )
            nb = NetworkBuffer(decrypted)

            if (nb.getByte().toByte() != 0x00.toByte()) {
                return ParsedLoginResult.FailureBeforeXtea("RSA decrypt failed")
            }

            // --- XTEA KEY (critical boundary) ---
            val xtea = if (nb.remaining() >= 16) {
                UIntArray(4) { nb.get32().toUInt() }.toIntArray()
            } else {
                return ParsedLoginResult.FailureBeforeXtea("Missing XTEA key")
            }

            // FROM THIS POINT ON, WE HAVE XTEA → FAILURES SWITCH MODE

            val gm = nb.getByte().toInt() != 0
            val sessionRaw = nb.readTibiaString()

            if (sessionRaw.length < 33) {
                return ParsedLoginResult.FailureAfterXtea("Invalid session format", xtea)
            }

            val token = sessionRaw.substring(0,32)
            val clientHmac = sessionRaw.substring(32)
            val serverHmac = generateHMACSHA256TRIMMED(
                token,
                "2e8498c0487c5b77833bdb8df82d9db77e414fb4ca2da559aec70d83148b25d7"
            )

            if (!fastEquals(serverHmac, clientHmac)) {
                return ParsedLoginResult.FailureAfterXtea("Invalid authentication token", xtea)
            }

            if (!oldProtocol && os == 0x0C) {
                if (nb.remaining() >= 2) nb.readTibiaString()
                if (nb.remaining() >= 2) nb.readTibiaString()
            }

            val charName = nb.readTibiaString()

            val (player, account, validToken) = transaction {
                val player = Player.find { PlayersTable.name eq charName }.firstOrNull()
                val account = player?.account
                val tokenObj = account?.let {
                    AccountToken.find {
                        (AccountTokenTable.accountId eq it.id) and
                                (AccountTokenTable.token eq token)
                    }.firstOrNull()
                }
                Triple(player, account, tokenObj)
            }

            if (player == null) {
                return ParsedLoginResult.FailureAfterXtea("Character does not exist", xtea)
            }
            if (validToken == null) {
                return ParsedLoginResult.FailureAfterXtea("Authentication token invalid", xtea)
            }

            if (validToken.expiresAt < LocalDateTime.now()) {
                return ParsedLoginResult.FailureAfterXtea("Authentication token expired", xtea)
            }

            val stamp = if (nb.remaining() >= 4) nb.getInt() else 0
            val rand  = if (nb.remaining() >= 1) nb.getByte() else 0

            return ParsedLoginResult.Success(
                ParsedLogin(
                    operatingSystem = os,
                    version = version,
                    oldProtocol = oldProtocol,
                    clientVersion = clientVersion,
                    versionString = versionString,
                    assetHash = assetHash,
                    datRevision = datRevision,
                    previewState = preview,
                    xteaKey = xtea,
                    isGameMaster = gm,
                    characterName = charName,
                    timestamp = stamp,
                    randomByte = rand.toInt()
                )
            )

        } catch (ex: Exception) {
            return ParsedLoginResult.FailureBeforeXtea("Exception: ${ex.message}")
        }
    }

}

data class ParsedLogin(
    val operatingSystem: Int,
    val version: Int,
    val oldProtocol: Boolean,
    val clientVersion: Int,
    val versionString: String?,
    val assetHash: String?,
    val datRevision: Int?,
    val previewState: Int,
    val xteaKey: IntArray,
    val isGameMaster: Boolean,
    //val accountDescriptor: String,
    //val password: String,
    val characterName: String,
    val timestamp: Int,
    val randomByte: Int
)


// ---------------- Updated GameServer using CustomRSA ----------------
class GameServer(private val port: Int, private val pemPath: String) {
    private lateinit var protocol: GameProtocol
    private var packetSequence = 0

    private var serverSequenceNumber: Int = 0
    fun start() {
        println("Initializing Custom RSA")

        protocol = GameProtocol()

        val server = ServerSocketChannel.open()
        server.bind(InetSocketAddress(port))
        server.configureBlocking(false)
        val selector = Selector.open()
        server.register(selector, SelectionKey.OP_ACCEPT)
        val pool = Executors.newCachedThreadPool()
        println("Game server listening on port $port")

        while (true) {
            selector.select()
            val it = selector.selectedKeys().iterator()
            while (it.hasNext()) {
                val key = it.next(); it.remove()
                if (key.isAcceptable) {
                    val s = key.channel() as ServerSocketChannel
                    val client = s.accept()
                    client.configureBlocking(true)
                    println("Accepted ${client.remoteAddress}")
                    pool.submit { handleClient(client) }
                }
            }
        }
    }

    fun addCryptoHeader(
        payload: ByteArray,
        method: ChecksumMethod,
        doCompression: Boolean = false
    ): ByteArray {
        // If SEQUENCE, mark compression flag if compression was done
        val compressionFlag = if (doCompression) (1 shl 31) else 0

        val checksum: Int? = when (method) {
            ChecksumMethod.NONE -> null
            ChecksumMethod.ADLER32 -> adlerChecksum(payload, payload.size)
            ChecksumMethod.SEQUENCE -> {
                serverSequenceNumber++
                if (serverSequenceNumber >= 0x7FFFFFFF) {
                    serverSequenceNumber = 0
                }
                compressionFlag or serverSequenceNumber
            }
        }

        val out = ByteBuffer
            .allocate(2 + (if (checksum != null) 4 else 0) + payload.size)
            .order(ByteOrder.LITTLE_ENDIAN)

        // Outer length = (checksum?4:0 + payload.size)
        val outerLen = (if (checksum != null) 4 else 0) + payload.size
        out.putShort(outerLen.toShort())

        if (checksum != null) {
            out.putInt(checksum)
        }

        out.put(payload)
        return out.array()
    }

    private fun handleClient(client: SocketChannel) {
        sendChallenge(client)

        val packet = readPacket(client) ?: run {
            client.close(); return
        }

        when (val result = protocol.parseGameLoginPacket(packet)) {
            is ParsedLoginResult.FailureBeforeXtea -> {
                // We cannot send encrypted disconnect since we have no XTEA
                println("Login fail (pre-XTEA): ${result.reason}")
                client.close()
            }

            is ParsedLoginResult.FailureAfterXtea -> {
                println("Login fail (post-XTEA): ${result.reason}")

                val session = GameClientSession(client, result.xtea)

                // example: send Tibia-style disconnect
                session.disconnectClient(result.reason)

                client.close()
            }

            is ParsedLoginResult.Success -> {
                val session = GameClientSession(client, result.login.xteaKey)
                session.sendAddCreature()
                println("Login OK: ${result.login.characterName}")
            }
        }
    }


    private fun readHandshake(client: SocketChannel): String {
        val sb = StringBuilder()
        val buf = ByteBuffer.allocate(1)
        while (true) {
            buf.clear()
            val r = client.read(buf)
            if (r < 0) break
            buf.flip()
            val b = buf.get()
            if (b == '\n'.toByte()) break
            if (b != '\r'.toByte()) sb.append(b.toInt().toChar())
            if (sb.length > 200) break
        }
        return sb.toString()
    }

    private fun sendChallenge(client: SocketChannel) {
        try {
            val p = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            p.put(0x01u.toByte())
            p.put(0x00u.toByte())

            p.put(0x11u.toByte())
            p.put(0x02u.toByte())
            p.put(0xF1u.toByte())
            p.put(0x05u.toByte())

            p.put(0x01u.toByte())
            p.put(0x1fu.toByte())

            val ts = (System.currentTimeMillis() / 1000).toInt()
            p.putInt(ts)

            p.put(0x92u.toByte())
            p.put(0x71u.toByte())
            p.flip()

            client.write(p)
            println("Sent challenge")
        } catch (e: Exception) {
            println("Failed challenge: ${e.message}")
        }
    }

    /*
    private fun sendAddCreature(client: SocketChannel, xteaKey: IntArray?) {
        // 1. Write message content
        val body = ByteBuffer.allocate(1024).order(ByteOrder.LITTLE_ENDIAN)
        writeCreaturePacket(body)
        val bodyBytes = body.array().copyOf(body.position())

        // 2. PADDING (writePaddingAmount)
        val paddingCount = (8 - ((bodyBytes.size + 1) % 8)) % 8
        val padded = UByteArray(bodyBytes.size + paddingCount + 1)
        System.arraycopy(bodyBytes, 0, padded, 0, bodyBytes.size)
        // pad bytes are zero
        padded[padded.size - 1] = paddingCount.toUByte() // last byte = pad count

        // 3. XTEA encrypt (if key provided)
        val encrypted = if (xteaKey != null) Xtea.encrypt(padded, xteaKey) else return

        // 4. addCryptoHeader (CHECKSUM_METHOD_SEQUENCE)
        val blockCount = encrypted.size / 8
        var seq = nextSequenceNumber()
        if (seq >= 0x7FFFFFFF) seq = 0
        val header = ByteBuffer.allocate(2 + 4).order(ByteOrder.LITTLE_ENDIAN)
        header.putShort(blockCount.toShort())      // u16 block count
        header.putInt(seq)                         // u32 checksum/sequence
        header.flip()

        // 5. Combine header + encrypted payload
        val finalPacket = ByteBuffer.allocate(header.remaining() + encrypted.size)
        finalPacket.put(header)
        finalPacket.put(encrypted.asByteArray())
        finalPacket.flip()

        // 6. send
        client.write(finalPacket)
    }
     */
    private fun readPacket(client: SocketChannel): ByteArray? {
        val header = ByteBuffer.allocate(2)
        var read = 0
        while (read < 2) {
            val r = client.read(header)
            if (r <= 0) return null
            read += r
        }
        header.flip()
        val size = (header.get().toInt() and 0xFF) or ((header.get().toInt() and 0xFF) shl 8)
        if (size <= 0 || size > 65535) {
            println("Invalid size: $size"); return null
        }
        val payload = ByteBuffer.allocate(1024)
        var total = 0
        while (total < size) {
            val r = client.read(payload)
            if (r <= 0) return null
            total += r
        }
        return payload.array()
    }
}

// ---------------- Main ----------------
fun main() {
    configureDatabases()
    Security.addProvider(BouncyCastleProvider())

    val pem = "key.pem"
    val server = GameServer(7172, pem)
    server.start()
}