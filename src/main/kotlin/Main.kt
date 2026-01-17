// KotlinOTGameServer.kt
package org.example

import ChecksumMethod
import adlerChecksum
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
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
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.Executors
import java.security.Security
import kotlin.math.ceil
import kotlin.math.pow


// ---------------- NetworkBuffer (unchanged) ----------------
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
    fun getU8(): Int = bb.get().toInt() and 0xFF
    fun getU16(): Int = bb.short.toInt() and 0xFFFF
    fun getU32(): UInt = (bb.int.toLong() and 0xFFFFFFFFL).toUInt()

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
        val len = getU16()
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

    // Usage in your NetworkBuffer code:
    fun rsaDecryptInPlace(nb: NetworkBuffer): Boolean {
        if (nb.remaining() < 128) {
            return false
        }

        val rsa = RSA.getInstance()
        val pos = nb.position()

        // Decrypt in place
        rsa.decrypt(nb.getBackingArray(), pos)

        val firstByte = nb.getByte()
        // Check if first decrypted byte is 0
        return firstByte.toByte() == 0.toByte()
    }

    val test = 1
    val skipBytes = 1

    @OptIn(ExperimentalUnsignedTypes::class)
    fun parseGameLoginPacket(packetBytes: ByteArray): ParsedLogin? {
        var nb = NetworkBuffer(packetBytes)
        try {
            if (nb.remaining() < 2 + 2 + 4) {
                println("Packet too short")
                return null
            }
            val randomTrash1 = nb.getU8()
            val randomTrash2 = nb.getU8()
            val randomTrash3 = nb.getU8()
            val randomTrash4 = nb.getU8()
            val randomTrash5 = nb.getU8()
            val randomTrash6 = nb.getU8()

            val os = nb.getU16()
            val version = nb.getU16()
            val clientVersion = nb.getU32()
            val oldProtocol = version <= 1100
            println("OS=$os version=$version oldProtocol=$oldProtocol clientVersion=$clientVersion")

            var versionString: String? = null
            var assetHash: String? = null
            var datRevision: Int? = null
            if (!oldProtocol) {
                versionString = nb.readTibiaString()
                println("versionString='$versionString'")
                if (version >= 1334) {
                    assetHash = nb.readTibiaString()
                    println("assetHash='$assetHash'")
                }
            }
            if (version < 1334 && nb.remaining() >= 2) {
                datRevision = nb.getU16()
                println("datRevision=$datRevision")
            }

            val preview = nb.getByte()
            println("preview=$preview")

            // RSA decrypt
            //val ok = rsaDecryptInPlace(nb)
            val decrypted = RSA_2.decrypt(nb.getBytes(minOf(nb.remaining(), 128)), RSA_PRIVATE_KEY)
            nb = NetworkBuffer(decrypted)
            val firstByte = nb.getByte()
            val ok = firstByte == 0x00
            if (!ok) {
                println("RSA decrypt failed (first byte != 0)")
                //return null
            }
            println("RSA decrypted OK")

            // XTEA key
            var xtea: UIntArray? = null
            if (nb.remaining() >= 16) {
                val arr = UIntArray(4)
                for (i in 0..3) arr[i] = nb.getU32()
                xtea = arr
                println("XTEA: ${arr.joinToString { "0x${it.toString(16)}" }}")
            }

            val gmByte = nb.getByte()
            val gm = if (nb.remaining() >= 1) gmByte != 0 else false
            println("GM=$gm")

            val session = nb.readTibiaString()
            println("sessionRaw='$session'")
            val (acct, pass) = if (session.contains('\n')) {
                val idx = session.indexOf('\n')
                session.substring(0, idx) to session.substring(idx + 1)
            } else session to ""

            // optional linux strings
            if (!oldProtocol && os == 0x0C) {
                if (nb.remaining() >= 2) println("linux1='${nb.readTibiaString()}'")
                if (nb.remaining() >= 2) println("linux2='${nb.readTibiaString()}'")
            }

            val charName = nb.readTibiaString()
            println("charName='$charName'")

            var stamp = 0
            if (nb.remaining() >= 4) {
                stamp = nb.getInt()
                println("stamp=$stamp")
            }

            var rand = 0
            if (nb.remaining() >= 1) {
                rand = nb.getByte()
                println("rand=$rand")
            }

            return ParsedLogin(
                os, version, oldProtocol, clientVersion,
                versionString, assetHash, datRevision, preview,
                xtea!!.toIntArray(), gm, acct, pass, charName, stamp, rand
            )

        } catch (ex: Exception) {
            println("Parse error: ${ex.message}")
            ex.printStackTrace()
            return null
        }
    }
}

data class ParsedLogin(
    val operatingSystem: Int,
    val version: Int,
    val oldProtocol: Boolean,
    val clientVersion: UInt,
    val versionString: String?,
    val assetHash: String?,
    val datRevision: Int?,
    val previewState: Int,
    val xteaKey: IntArray?,
    val isGameMaster: Boolean,
    val accountDescriptor: String,
    val password: String,
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
        try {
            val sock = client.socket()
            sendChallenge(client)
            val handshake = readHandshake(client)
            println("Handshake from ${sock.remoteSocketAddress}: '$handshake'")
            val packet = readPacket(client) ?: run {
                println("Failed reading packet")
                client.close(); return
            }
            println("Received packet ${packet.size} bytes")
            val parsed = protocol.parseGameLoginPacket(packet)
            if (parsed != null) {
                //sendAddCreature(client, parsed.xteaKey)
                sendSrakenPierdaken(client, parsed.xteaKey)
                println("Parsed login: account='${parsed.accountDescriptor}' char='${parsed.characterName}'")
            } else {
                println("Failed to parse login packet")
            }
        } catch (e: Exception) {
            println("Client error: ${e.message}"); e.printStackTrace()
        } finally {
            //try { client.close() } catch (_: Exception) {}
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

    private val SCALING_BASE = 10.0

    private fun putDoubleWithPrecision(buffer: ByteBuffer, value: Double, precision: Byte = 0x03) {
        buffer.put(precision)
        val scaled = value * SCALING_BASE.pow(precision.toInt())
        buffer.putInt(scaled.toInt() + 0x7fffffff) // ✅ fix: putInt takes Int, not UInt
    }

    private fun putCipString(buffer: ByteBuffer, value: String) {
        val stringAsByteArray = value.toByteArray()
        buffer.put(stringAsByteArray.size.toByte())
        buffer.put(0x00)
        buffer.put(stringAsByteArray)
    }

    private fun appendPosition(buffer: ByteBuffer, pos: Position) {
        buffer.putShort(pos.x)
        buffer.putShort(pos.y)
        buffer.put(pos.z)
    }

    private fun appendAllowBugReport(inner: ByteBuffer, allow: Boolean) {
        // 0x1A + 0x00 (allow) / 0x01 (disable)
        inner.put(0x1A)
        inner.put(if (allow) 0x00 else 0x01)
        // Ref: ProtocolGame::sendAllowBugReport. :contentReference[oaicite:34]{index=34}
    }

    private fun appendPendingStateEntered(inner: ByteBuffer) {
        inner.put(0x0A) // Ref: sendPendingStateEntered. :contentReference[oaicite:35]{index=35}
    }

    private fun appendEnterWorld(inner: ByteBuffer) {
        inner.put(0x0F) // Ref: sendEnterWorld. :contentReference[oaicite:36]{index=36}
    }

    private fun appendTibiaTime(inner: ByteBuffer, secondsSinceMidnight: Int) {
        inner.put(0xEF.toByte()) // Ref: sendTibiaTime. :contentReference[oaicite:37]{index=37}
        inner.put((secondsSinceMidnight / 60).toByte())
        inner.put((secondsSinceMidnight % 60).toByte())
    }

    private fun appendFloorDescription(inner: ByteBuffer, skip: Int, pos: Position): Int {
        //pos for mock only sending player pos
        var skip = skip
        //appendTileDescription(inner)

        return skip
    }

    private fun appendMagicEffect(inner: ByteBuffer, pos: Position) {
        inner.put(0x83.toByte())
        appendPosition(inner, pos)
        inner.put(0x03)
        inner.putShort(11)
        inner.put(0x00)
    }

    private fun appendMapDescription(inner: ByteBuffer, pos: Position) {
        inner.put(0x64)
        appendPosition(inner, pos)

        //TODO
        var skip = appendFloorDescription(inner, -1, pos)
        if (skip >= 0) {
            inner.put(skip.toByte())
            inner.put(0xFF.toByte())
        }
    }

    private fun nextSequenceNumber(): Int {
        val seq = packetSequence
        packetSequence = (packetSequence + 1) and 0xFFFF // wrap for U16
        return seq
    }

    private fun writeCreaturePacket(inner: ByteBuffer) {
        val storeImagesUrl = "http://127.0.0.1/images/store/"

        inner.put(0x17)
        inner.putInt(268435464)
        inner.putShort(50)
        putDoubleWithPrecision(inner, 857.36)
        putDoubleWithPrecision(inner, 261.29)
        putDoubleWithPrecision(inner, -4795.01)
        inner.put(0x00)
        inner.put(0x00)
        putCipString(inner, storeImagesUrl)

        inner.putShort(25)
        inner.put(0x00)

        appendAllowBugReport(inner, true)
        appendTibiaTime(inner, 0)
        appendPendingStateEntered(inner)
        appendEnterWorld(inner)
        val pos = Position(17568, 17406, 7)
        appendMapDescription(inner, pos)
        //appendMagicEffect(inner, pos)
        inner.put(0x75.toByte())
        inner.put(0xff.toByte())
        inner.put(0xa3.toByte())
        inner.put(0x11.toByte())
        inner.put(0x61.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x06.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x10.toByte())
        inner.put(0x00.toByte())
        inner.put(0x03.toByte())
        inner.put(0x00.toByte())
        inner.put(0x47.toByte())
        inner.put(0x4f.toByte())
        inner.put(0x44.toByte())
        inner.put(0x64.toByte())
        inner.put(0x02.toByte())
        inner.put(0x88.toByte())
        inner.put(0x00.toByte())
        inner.put(0x5f.toByte())
        inner.put(0x71.toByte())
        inner.put(0x27.toByte())
        inner.put(0x73.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0xff.toByte())
        inner.put(0xd7.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0xff.toByte())
        inner.put(0x00.toByte())
        inner.put(0x00.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0xff.toByte())
        inner.put(0x69.toByte())
        inner.put(0xff.toByte())
        inner.put(0x00.toByte())
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
    private fun sendSrakenPierdaken(client: SocketChannel, xteaKey: IntArray?) {
        val messageStr = "You may only login with 1 character\nof your account at the same time."
        val plain = messageStr.toByteArray()

        if (xteaKey == null) {
            return
        }

        // 1) Build inner payload: header (1 byte) + payload
        val buf = ByteArrayOutputStream()
        buf.write(0x07) // header byte
        buf.write(0x14) // header byte
        buf.write(messageStr.length)
        buf.write(0x00)
        buf.write(plain) // payload

        // 2) Calculate padding amount
        val currentLength = buf.size()
        val paddingAmount = (currentLength - 2) % 8

        // 3) Add padding bytes (0x33)
        repeat(paddingAmount) { buf.write(0x33) }

        // 4) Add padding amount as last byte (before encryption)
        var innerMsg = buf.toByteArray()

        // 5) XTEA encrypt the entire buffer
        innerMsg = Xtea.encrypt(innerMsg, xteaKey)

        // 6) Build crypto header using add_header logic (prepending in reverse)
        val sequence = ++serverSequenceNumber
        if (serverSequenceNumber >= 0x7FFFFFFF) serverSequenceNumber = 0

        // Check if compression would be used (length >= 128)
        val sendMessageChecksum = if (innerMsg.size >= 128) {
            (1u shl 31) or sequence.toUInt()
        } else {
            sequence.toUInt()
        }

        // messageLength = encryptedLength / 8
        val messageLength = (innerMsg.size / 8).toUShort()

        // Build final packet by prepending headers in reverse order
        val out = ByteArrayOutputStream()

        // First write the encrypted message
        out.write(innerMsg)

        // Now prepend headers using a helper to write in little-endian
        val finalBuffer = ByteArrayOutputStream()

        // Add checksum (4 bytes, little-endian) - prepended last, so appears first
        finalBuffer.write(0x0A)
        finalBuffer.write(0x00)
        finalBuffer.write(0x01)
        finalBuffer.write(0x00)

        // Add message length (2 bytes, little-endian) - prepended second, so appears after checksum
        finalBuffer.write(0x00)
        finalBuffer.write(0x00)

        // Add encrypted message
        finalBuffer.write(innerMsg)

        client.write(ByteBuffer.wrap(finalBuffer.toByteArray()))
    }

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
    Security.addProvider(BouncyCastleProvider())

    val pem = "key.pem"
    val server = GameServer(7172, pem)
    server.start()
}