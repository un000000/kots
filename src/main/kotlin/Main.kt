// KotlinOTGameServer.kt
package org.example

import java.io.File
import java.math.BigInteger
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.util.Base64
import java.util.concurrent.Executors
import kotlin.random.Random

/*
// ---------------- Custom RSA Implementation (matching C++ logic) ----------------
class CustomRSA {
    private var n: BigInteger = BigInteger.ZERO  // modulus (p * q)
    private var d: BigInteger = BigInteger.ZERO  // private exponent

    // Default hardcoded values from C++ (fallback keys)
    private val defaultP = "14299623962416399520070177382898895550795403345466153217470516082934737582776038882967213386204600674145392845853859217990626450972452084065728686565928113"
    private val defaultQ = "7630979195970404721891201847792002125535401292779123937207447574596692788513647179235335529307251350570728407373705564708871762033017096809910315212884101"

    fun start(keyPath: String = "key.pem") {
        try {
            if (!loadPEM(keyPath)) {
                println("File $keyPath not found or have problem on loading... Setting standard rsa key")
                setKey(defaultP, defaultQ, 10)
            }
        } catch (e: Exception) {
            println("Loading RSA Key from $keyPath failed with error: ${e.message}")
            println("Switching to a default key...")
            setKey(defaultP, defaultQ, 10)
        }
    }

    /**
     * Set RSA key from p and q strings (matching C++ setKey function)
     * @param pString prime p as string
     * @param qString prime q as string
     * @param base number base (10 for decimal, 16 for hex)
     */
    fun setKey(pString: String, qString: String, base: Int = 10) {
        val p = BigInteger(pString, base)
        val q = BigInteger(qString, base)
        val e = BigInteger.valueOf(65537) // standard RSA public exponent

        // n = p * q
        // n = p.multiply(q).mod(BigInteger("2").pow(64))
        n = BigInteger("aab33dbe8d5b7ff5", 16)

        // d = e^-1 mod (p-1)(q-1)
        val p1 = p.subtract(BigInteger.ONE)
        val q1 = q.subtract(BigInteger.ONE)
        val pq1 = p1.multiply(q1) // φ(n) = (p-1)(q-1)

        // d = e^-1 mod φ(n)
        // d = e.modInverse(pq1).mod(BigInteger("2").pow(64))
        d = BigInteger("df443761aefe8d81", 16)
    }

    /**
     * Decrypt message in place (matching C++ decrypt function)
     * Expects exactly 128 bytes of encrypted data
     */
    fun decrypt(msg: ByteArray) {
        require(msg.size >= 128) { "Message must be at least 128 bytes" }

        // Import 128 bytes as big integer (big endian, unsigned)
        val c = BigInteger(1, msg.copyOfRange(0, 128))

        // m = c^d mod n
        val m = c.modPow(d, n)

        // Convert back to bytes
        val decryptedBytes = m.toByteArray()

        // Calculate padding needed (similar to C++ logic)
        val count = decryptedBytes.size
        val padding = 128 - count

        // Clear the message buffer first
        msg.fill(0, 0, 128)

        // Copy decrypted bytes to the right position (right-aligned)
        if (count > 0) {
            // Handle the case where toByteArray() might include a sign byte
            val sourceStart = if (decryptedBytes[0] == 0.toByte() && decryptedBytes.size > 1) 1 else 0
            val actualCount = decryptedBytes.size - sourceStart
            val actualPadding = 128 - actualCount

            System.arraycopy(decryptedBytes, sourceStart, msg, actualPadding, actualCount)
        }
    }

    /**
     * Base64 decode with custom character mapping (matching C++ implementation)
     */
    fun base64Decrypt(input: String): ByteArray {
        if (input.isEmpty()) return ByteArray(0)

        fun posOfCharacter(chr: Byte): Int {
            val c = chr.toInt() and 0xFF
            return when (c) {
                in 'A'.code..'Z'.code -> c - 'A'.code
                in 'a'.code..'z'.code -> c - 'a'.code + ('Z'.code - 'A'.code) + 1
                in '0'.code..'9'.code -> c - '0'.code + ('Z'.code - 'A'.code) + ('z'.code - 'a'.code) + 2
                '+'.code, '-'.code -> 62
                '/'.code, '_'.code -> 63
                else -> {
                    println("Invalid base64 character: ${c.toChar()}")
                    0
                }
            }
        }

        val length = input.length
        var pos = 0
        val output = mutableListOf<Byte>()

        while (pos < length) {
            if (pos + 1 >= length) break

            val pos0 = posOfCharacter(input[pos].code.toByte())
            val pos1 = posOfCharacter(input[pos + 1].code.toByte())

            output.add(((pos0 shl 2) + ((pos1 and 0x30) shr 4)).toByte())

            if (pos + 2 < length && input[pos + 2] != '=' && input[pos + 2] != '.') {
                val pos2 = posOfCharacter(input[pos + 2].code.toByte())
                output.add((((pos1 and 0x0f) shl 4) + ((pos2 and 0x3c) shr 2)).toByte())

                if (pos + 3 < length && input[pos + 3] != '=' && input[pos + 3] != '.') {
                    val pos3 = posOfCharacter(input[pos + 3].code.toByte())
                    output.add((((pos2 and 0x03) shl 6) + pos3).toByte())
                }
            }

            pos += 4
        }

        return output.toByteArray()
    }

    /**
     * Load PEM file and extract p, q values (matching C++ loadPEM function)
     */
    private fun loadPEM(filename: String): Boolean {
        val file = File(filename)
        if (!file.exists()) return false

        val key = file.readText().replace(Regex("\\r?\\n"), "")

        val headerOld = "-----BEGIN RSA PRIVATE KEY-----"
        val footerOld = "-----END RSA PRIVATE KEY-----"
        val headerNew = "-----BEGIN PRIVATE KEY-----"
        val footerNew = "-----END PRIVATE KEY-----"

        val decodedKey = when {
            key.startsWith(headerOld) -> {
                if (!key.endsWith(footerOld)) {
                    println("Missing RSA private key footer")
                    return false
                }
                base64Decrypt(key.substring(headerOld.length, key.length - footerOld.length))
            }
            key.startsWith(headerNew) -> {
                if (!key.endsWith(footerNew)) {
                    println("Missing RSA private key footer")
                    return false
                }
                base64Decrypt(key.substring(headerNew.length, key.length - footerNew.length))
            }
            else -> {
                println("Missing RSA private key header")
                return false
            }
        }

        return parseASN1RSAKey(decodedKey)
    }

    /**
     * Parse ASN.1 DER encoded RSA private key (simplified version of C++ logic)
     */
    private fun parseASN1RSAKey(keyData: ByteArray): Boolean {
        try {
            val reader = ASN1Reader(keyData)

            // Parse SEQUENCE
            if (!reader.expectTag(0x30)) return false
            reader.readLength()

            // Handle PKCS#8 wrapper if present
            var tag = reader.peekTag()
            if (tag == 0x02) {
                // Could be version or direct PKCS#1
                val version = reader.readInteger()
                if (version == BigInteger.ZERO || version == BigInteger.ONE) {
                    // This might be PKCS#1 version, continue
                } else {
                    // Could be PKCS#8, skip algorithm identifier
                    if (!reader.expectTag(0x30)) return false
                    val algLen = reader.readLength()
                    reader.skipBytes(algLen)

                    // Read OCTET STRING containing PKCS#1 data
                    if (!reader.expectTag(0x04)) return false
                    val pkcs1Len = reader.readLength()
                    val pkcs1Data = reader.readBytes(pkcs1Len)
                    return parseASN1RSAKey(pkcs1Data) // Recursive call for inner PKCS#1
                }
            }

            // Parse PKCS#1 RSAPrivateKey
            // Skip version if we haven't read it yet
            if (tag == 0x02) {
                reader.readInteger() // version
            }

            // Skip modulus (n), publicExponent (e), privateExponent (d)
            reader.readInteger() // n (modulus)
            reader.readInteger() // e (public exponent)
            reader.readInteger() // d (private exponent)

            // Read p and q
            val p = reader.readInteger()
            val q = reader.readInteger()

            // Convert to hex strings and set key (matching C++ behavior)
            val pString = p.toString(16).uppercase()
            val qString = q.toString(16).uppercase()

            setKey(pString, qString, 16)
            return true

        } catch (e: Exception) {
            println("Error parsing ASN.1 RSA key: ${e.message}")
            return false
        }
    }

    /**
     * Simple ASN.1 DER reader (matching C++ decodeLength and readHexString functionality)
     */
    private class ASN1Reader(private val data: ByteArray) {
        private var pos = 0

        fun expectTag(expectedTag: Int): Boolean {
            if (pos >= data.size) return false
            val tag = data[pos++].toInt() and 0xFF
            return tag == expectedTag
        }

        fun peekTag(): Int {
            if (pos >= data.size) return -1
            return data[pos].toInt() and 0xFF
        }

        fun readLength(): Int {
            if (pos >= data.size) throw IllegalStateException("Unexpected EOF")

            val first = data[pos++].toInt() and 0xFF
            return if (first and 0x80 != 0) {
                val numBytes = first and 0x7F
                if (numBytes > 4) throw IllegalStateException("Length too large")

                var length = 0
                repeat(numBytes) {
                    if (pos >= data.size) throw IllegalStateException("Unexpected EOF")
                    length = (length shl 8) or (data[pos++].toInt() and 0xFF)
                }
                length
            } else {
                first
            }
        }

        fun readInteger(): BigInteger {
            if (!expectTag(0x02)) throw IllegalStateException("Expected INTEGER tag")
            val length = readLength()
            if (length == 0) return BigInteger.ZERO

            val bytes = readBytes(length)
            return BigInteger(1, bytes) // Positive number
        }

        fun readBytes(length: Int): ByteArray {
            if (pos + length > data.size) throw IllegalStateException("Unexpected EOF")
            val result = data.copyOfRange(pos, pos + length)
            pos += length
            return result
        }

        fun skipBytes(length: Int) {
            if (pos + length > data.size) throw IllegalStateException("Unexpected EOF")
            pos += length
        }
    }
}

 */
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