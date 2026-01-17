// KotlinOTGameServer.kt
package org.example

import ChecksumMethod
import GameClientSession
import adlerChecksum
import org.bouncycastle.jce.provider.BouncyCastleProvider
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
        val len = get16()
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

    @OptIn(ExperimentalUnsignedTypes::class)
    fun parseGameLoginPacket(packetBytes: ByteArray): ParsedLogin? {
        var nb = NetworkBuffer(packetBytes)
        try {
            if (nb.remaining() < 2 + 2 + 4) {
                println("Packet too short")
                return null
            }
            val randomTrash1 = nb.get8()
            val randomTrash2 = nb.get8()
            val randomTrash3 = nb.get8()
            val randomTrash4 = nb.get8()
            val randomTrash5 = nb.get8()
            val randomTrash6 = nb.get8()

            val os = nb.get16()
            val version = nb.get16()
            val clientVersion = nb.get32()
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
                datRevision = nb.get16()
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
                for (i in 0..3) arr[i] = nb.get32().toUInt()
                xtea = arr
                println("XTEA: ${arr.joinToString { "0x${it.toString(16)}" }}")
            }
            if (xtea == null){
                return null
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
                xtea.toIntArray(), gm, acct, pass, charName, stamp, rand
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
    val clientVersion: Int,
    val versionString: String?,
    val assetHash: String?,
    val datRevision: Int?,
    val previewState: Int,
    val xteaKey: IntArray,
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
            //val handshake = readHandshake(client)
            //println("Handshake from ${sock.remoteSocketAddress}: '$handshake'")
            val packet = readPacket(client) ?: run {
                println("Failed reading packet")
                client.close(); return
            }
            println("Received packet ${packet.size} bytes")
            val parsed = protocol.parseGameLoginPacket(packet)
            if (parsed != null) {
                val session = GameClientSession(client, parsed.xteaKey)

                //sendAddCreature(client, parsed.xteaKey)
                session.sendAddCreature()

                session.disconnectClient("You may only login with 1 character\nof your account at the same time.")
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
    Security.addProvider(BouncyCastleProvider())

    val pem = "key.pem"
    val server = GameServer(7172, pem)
    server.start()
}