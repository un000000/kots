// KotlinOTGameServer.kt
package org.example

import ChecksumMethod
import adlerChecksum
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.Executors
import kotlin.math.pow
import kotlin.random.Random

// ---------------- Updated RsaDecryptor using CustomRSA ----------------
class RsaDecryptor(private val customRSA: CustomRSA) {
    // RSA block size is always 128 bytes (1024 bits) to match C++ implementation
    private val blockSize = 128

    /** Return modulus block size in bytes (always 128 for this implementation) */
    fun blockSizeBytes(): Int = blockSize

    /** Decrypt exactly 128 bytes using custom RSA implementation */
    fun decryptBlock(encrypted: ByteArray): ByteArray {
        require(encrypted.size >= blockSize) { "Encrypted block must be at least $blockSize bytes" }

        val block = encrypted.copyOf(blockSize)
        customRSA.decrypt(block)
        return block
    }
}

// ---------------- NetworkBuffer (unchanged) ----------------
class NetworkBuffer(private val buf: ByteArray) {
    private val bb: ByteBuffer = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)
    fun remaining(): Int = bb.remaining()
    fun position(): Int = bb.position()
    fun setPosition(p: Int) { bb.position(p) }
    fun getByte(): Int = bb.get().toInt() and 0xFF
    fun getShort(): Int = bb.short.toInt() and 0xFFFF
    fun getInt(): Int = bb.int
    fun getUInt(): Long = bb.int.toLong() and 0xFFFFFFFFL
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
        val len = getShort()
        if (len == 0) return ""
        val bytes = getBytes(len)
        return String(bytes, Charsets.UTF_8)
    }
    fun asArray(): ByteArray = bb.array()
}

// ---------------- GameProtocol (unchanged) ----------------
class GameProtocol(private val rsaDecryptor: RsaDecryptor) {
    /**
     * Decrypts next RSA block (128 bytes) in place and returns true iff first decrypted byte == 0.
     */
    fun rsaDecryptInPlace(nb: NetworkBuffer): Boolean {
        val blockSize = rsaDecryptor.blockSizeBytes()
        if (nb.remaining() < blockSize) return false
        val start = nb.position()
        val encrypted = nb.getBytes(blockSize)
        val decrypted = rsaDecryptor.decryptBlock(encrypted)
        nb.putBytesAt(start, decrypted)
        nb.setPosition(start)
        val first = nb.getByte()
        return first == 0
    }

    fun parseGameLoginPacket(packetBytes: ByteArray): ParsedLogin? {
        val nb = NetworkBuffer(packetBytes)
        try {
            if (nb.remaining() < 2 + 2 + 4) {
                println("Packet too short")
                return null
            }
            nb.getInt()
            nb.getByte()
            val os = nb.getShort()
            val version = nb.getShort()
            val oldProtocol = version <= 1100
            val clientVersion = nb.getInt()
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
                datRevision = nb.getShort()
                println("datRevision=$datRevision")
            }

            if (nb.remaining() < 1) {
                println("missing preview")
                return null
            }
            val preview = nb.getByte()
            println("preview=$preview")

            // RSA decrypt
            val ok = rsaDecryptInPlace(nb)
            if (!ok) {
                println("RSA decrypt failed (first byte != 0)")
                return null
            }
            println("RSA decrypted OK")

            // XTEA key
            var xtea: IntArray? = null
            if (nb.remaining() >= 16) {
                val arr = IntArray(4)
                for (i in 0..3) arr[i] = nb.getInt()
                xtea = arr
                println("XTEA: ${arr.joinToString { "0x${it.toString(16)}" }}")
            }

            val gm = if (nb.remaining() >= 1) nb.getByte() != 0 else false
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
                xtea, gm, acct, pass, charName, stamp, rand
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
    private lateinit var rsaDecryptor: RsaDecryptor
    private lateinit var customRSA: CustomRSA

    private var serverSequenceNumber: Int = 0
    fun start() {
        println("Initializing Custom RSA")
        customRSA = CustomRSA()
        customRSA.start(pemPath)

        rsaDecryptor = RsaDecryptor(customRSA)
        protocol = GameProtocol(rsaDecryptor)

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
            val handshake = readHandshake(client)
            println("Handshake from ${sock.remoteSocketAddress}: '$handshake'")
            if (handshake != "OTServBR-Global") {
                println("Invalid handshake, closing")
                client.close()
                return
            }
            sendChallenge(client)
            val packet = readPacket(client) ?: run {
                println("Failed reading packet")
                client.close(); return
            }
            println("Received packet ${packet.size} bytes")
            val parsed = protocol.parseGameLoginPacket(packet)
            if (parsed != null) {
                sendAddCreature(client, parsed.xteaKey)
                 //sendSrakenPierdaken(client, parsed.xteaKey)
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
            if (r <= 0) break
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
            val ts = (System.currentTimeMillis() / 1000).toInt()
            val rand = Random.nextInt(0, 256).toByte()
            val p = ByteBuffer.allocate(14).order(ByteOrder.LITTLE_ENDIAN)
            p.put(0x0c.toByte()); p.put(0x00.toByte()); p.put(0xc0.toByte()); p.put(0x02.toByte())
            p.put(0xd3.toByte()); p.put(0x09.toByte()); p.put(0x06.toByte()); p.put(0x00.toByte())
            p.put(0x1f.toByte()); p.put(0xbc.toByte()); p.put(0x97.toByte()); p.put(0x95.toByte()); p.put(0x68.toByte())
            p.rewind()
            client.write(p)
            println("Sent challenge ts=$ts rand=${rand.toInt() and 0xFF}")
        } catch (e: Exception) {
            println("Failed challenge: ${e.message}")
        }
    }
    private val SCALING_BASE = 10.0

    private fun putDoubleWithPrecision(buffer: ByteBuffer, value: Double, precision: Byte = 0x03) {
        buffer.put(precision)
        val scaled = value * SCALING_BASE.pow(precision.toInt())
        buffer.putInt(scaled.toInt()+0x7fffffff) // ✅ fix: putInt takes Int, not UInt
    }
    private fun putCipString(buffer: ByteBuffer, value: String){
        val stringAsByteArray = value.toByteArray()
        buffer.put(stringAsByteArray.size.toByte())
        buffer.put(0x00)
        buffer.put(stringAsByteArray)
    }
    private fun appendPosition(buffer: ByteBuffer, pos: Position){
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
    private fun appendFloorDescription(inner: ByteBuffer, skip: Int, pos: Position):Int {
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

    private fun appendMapDescription(inner: ByteBuffer, pos: Position){
        inner.put(0x64)
        appendPosition(inner, pos)

        //TODO
        var skip = appendFloorDescription(inner, -1, pos)
        if (skip >= 0){
            inner.put(skip.toByte())
            inner.put(0xFF.toByte())
        }
    }

    private fun sendAddCreature(client: SocketChannel, xteaKey: IntArray?) {
        try{
            val storeImagesUrl = "http://127.0.0.1/images/store/"
            val inner = ByteBuffer
                //.allocate(27 + storeImagesUrl.toByteArray().size + 2)
                .allocate(512)
                .order(ByteOrder.LITTLE_ENDIAN)
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
            appendMapDescription(inner,pos)
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

            val innerBytes = inner.array()

            val encrypted = if (xteaKey != null) Xtea.encrypt(innerBytes, xteaKey) else innerBytes

            val finalPacket = addCryptoHeader(encrypted, ChecksumMethod.SEQUENCE)

            client.write(ByteBuffer.wrap(finalPacket))
        } catch (e: Exception){

        }
    }
    private fun sendSrakenPierdaken(client: SocketChannel, xteaKey: IntArray?) {
        try {
            val messageStr = "Sraken pierdaken"
            val message = messageStr.toByteArray()

            val inner = ByteBuffer
                .allocate(2 + 3 + message.size)
                .order(ByteOrder.LITTLE_ENDIAN)

            // inner length (will be encrypted) = 3 + message.size
            inner.putShort((3 + message.size).toShort())

            inner.put(0x14)
            putCipString(inner, messageStr)

            val innerBytes = inner.array()

            // 1) Encrypt inner with XTEA if key exists
            val encrypted = if (xteaKey != null) Xtea.encrypt(innerBytes, xteaKey) else innerBytes

            // 2) Wrap with outer header (pick your checksum mode)
            val finalPacket = addCryptoHeader(encrypted, ChecksumMethod.SEQUENCE)

            client.write(ByteBuffer.wrap(finalPacket))
            println("Sent TreleMorele (Checksum=${ChecksumMethod.SEQUENCE}, XTEA=${xteaKey != null})")
        } catch (e: Exception) {
            println("sendTreleMorele failed :( : ${e.message}")
        }
    }

    private fun readPacket(client: SocketChannel): ByteArray? {
        val header = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN)
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
        val payload = ByteBuffer.allocate(size)
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
    val pem = "key.pem"
    val server = GameServer(7172, pem)
    server.start()
}