package org.example

import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64
import javax.crypto.Cipher

internal object RSA_2 {
    fun encrypt(data: ByteArray, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(data)
    }

    fun decrypt(data: ByteArray, privateKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(data)
    }
}
class RSA {
    private var n: BigInteger = BigInteger.ZERO
    private var d: BigInteger = BigInteger.ZERO

    init {
        loadKey()
    }

    private fun loadKey() {
        val pemFile = File("./key.pem")

        if (!pemFile.exists()) {
            println("File key.pem not found. Setting standard RSA key")
            setDefaultKey()
            return
        }

        try {
            if (!loadPEM(pemFile)) {
                println("Failed to load key.pem. Setting standard RSA key")
                setDefaultKey()
            }
        } catch (e: Exception) {
            println("Loading RSA Key from key.pem failed: ${e.message}")
            println("Switching to default key...")
            setDefaultKey()
        }
    }

    private fun setDefaultKey() {
        val p = "14299623962416399520070177382898895550795403345466153217470516082934737582776038882967213386204600674145392845853859217990626450972452084065728686565928113"
        val q = "7630979195970404721891201847792002125535401292779123937207447574596692788513647179235335529307251350570728407373705564708871762033017096809910315212884101"
        setKey(p, q, 10)
    }

    private fun setKey(pString: String, qString: String, base: Int = 10) {
        val p = BigInteger(pString, base)
        val q = BigInteger(qString, base)
        val e = BigInteger.valueOf(65537)

        // n = p * q
        n = p.multiply(q)

        // d = e^-1 mod (p-1)(q-1)
        val p1 = p.subtract(BigInteger.ONE)
        val q1 = q.subtract(BigInteger.ONE)
        val pq1 = p1.multiply(q1)
        d = e.modInverse(pq1)
    }

    fun decrypt(msg: ByteArray, offset: Int = 0): Boolean {
        if (msg.size - offset < 128) {
            return false
        }

        // Import 128 bytes as big integer
        val cBytes = msg.copyOfRange(offset, offset + 128)
        val c = BigInteger(1, cBytes)

        // m = c^d mod n
        val m = c.modPow(d, n)

        // Export back to bytes
        val mBytes = m.toByteArray()
        val count = mBytes.size

        // Clear the 128-byte block
        for (i in 0 until 128) {
            msg[offset + i] = 0
        }

        // Copy decrypted bytes to the end of the 128-byte block
        val startPos = offset + (128 - count)
        System.arraycopy(mBytes, 0, msg, startPos, count)

        return true
    }

    private fun loadPEM(file: File): Boolean {
        val content = file.readText().replace("\n", "").replace("\r", "")

        val headerOld = "-----BEGIN RSA PRIVATE KEY-----"
        val footerOld = "-----END RSA PRIVATE KEY-----"
        val headerNew = "-----BEGIN PRIVATE KEY-----"
        val footerNew = "-----END PRIVATE KEY-----"

        val key: ByteArray = when {
            content.startsWith(headerOld) -> {
                if (!content.endsWith(footerOld)) {
                    println("Missing RSA private key footer")
                    return false
                }
                val base64 = content.substring(headerOld.length, content.length - footerOld.length)
                base64Decode(base64)
            }
            content.startsWith(headerNew) -> {
                if (!content.endsWith(footerNew)) {
                    println("Missing RSA private key footer")
                    return false
                }
                val base64 = content.substring(headerNew.length, content.length - footerNew.length)
                base64Decode(base64)
            }
            else -> {
                println("Missing RSA private key header")
                return false
            }
        }

        return parseDER(key)
    }

    private fun base64Decode(input: String): ByteArray {
        // Handle both standard and URL-safe base64
        val normalized = input.replace('-', '+').replace('_', '/')
        return Base64.getDecoder().decode(normalized)
    }

    private fun parseDER(key: ByteArray): Boolean {
        var pos = 0

        // Check for SEQUENCE tag
        if (key[pos++].toInt() and 0xFF != 0x30) { // SEQUENCE
            println("Invalid RSA key: expected SEQUENCE")
            return false
        }

        var length = decodeLength(key, pos)
        pos += getLengthBytes(key[pos])

        var tag = key[pos++].toInt() and 0xFF

        // Handle PKCS#8 format
        if (tag == 0x02 && key[pos].toInt() and 0xFF == 0x01 &&
            key[pos + 1].toInt() and 0xFF == 0x00 && key[pos + 2].toInt() and 0xFF == 0x30) {
            pos += 3
            tag = 0x30
        }

        if (tag == 0x30) { // SEQUENCE
            length = decodeLength(key, pos)
            pos += getLengthBytes(key[pos])

            tag = key[pos++].toInt() and 0xFF
            length = decodeLength(key, pos)
            pos += getLengthBytes(key[pos])

            if (tag == 0x03) { // BIT STRING
                pos++ // Skip unused bits byte
            }

            if (key[pos++].toInt() and 0xFF != 0x30) { // SEQUENCE
                println("Invalid RSA key")
                return false
            }

            length = decodeLength(key, pos)
            pos += getLengthBytes(key[pos])
            tag = key[pos++].toInt() and 0xFF
        }

        if (tag != 0x02) { // INTEGER
            println("Invalid RSA key: expected INTEGER")
            return false
        }

        // Skip version
        length = decodeLength(key, pos)
        pos += getLengthBytes(key[pos]) + length

        // Skip modulus (n)
        if (key[pos++].toInt() and 0xFF != 0x02) return false
        length = decodeLength(key, pos)
        pos += getLengthBytes(key[pos]) + length

        // Skip public exponent (e)
        if (key[pos++].toInt() and 0xFF != 0x02) return false
        length = decodeLength(key, pos)
        pos += getLengthBytes(key[pos]) + length

        // Skip private exponent (d)
        if (key[pos++].toInt() and 0xFF != 0x02) return false
        length = decodeLength(key, pos)
        pos += getLengthBytes(key[pos]) + length

        // Read prime p
        if (key[pos++].toInt() and 0xFF != 0x02) return false
        length = decodeLength(key, pos)
        pos += getLengthBytes(key[pos])
        val pString = readHexString(key, pos, length)
        pos += length

        // Read prime q
        if (key[pos++].toInt() and 0xFF != 0x02) return false
        length = decodeLength(key, pos)
        pos += getLengthBytes(key[pos])
        val qString = readHexString(key, pos, length)

        setKey(pString, qString, 16)
        return true
    }

    private fun decodeLength(data: ByteArray, pos: Int): Int {
        var p = pos
        var length = data[p++].toInt() and 0xFF

        if (length and 0x80 != 0) {
            val numBytes = length and 0x7F
            if (numBytes > 4) {
                println("Invalid length encoding")
                return 0
            }

            length = 0
            for (i in 0 until numBytes) {
                length = (length shl 8) or (data[p++].toInt() and 0xFF)
            }
        }

        return length
    }

    private fun getLengthBytes(lengthByte: Byte): Int {
        val b = lengthByte.toInt() and 0xFF
        return if (b and 0x80 != 0) {
            (b and 0x7F) + 1
        } else {
            1
        }
    }

    private fun readHexString(data: ByteArray, pos: Int, length: Int): String {
        val hex = StringBuilder(length * 2)
        for (i in 0 until length) {
            val byte = data[pos + i].toInt() and 0xFF
            hex.append(String.format("%02X", byte))
        }
        return hex.toString()
    }

    companion object {
        private var instance: RSA? = null

        fun getInstance(): RSA {
            if (instance == null) {
                instance = RSA()
            }
            return instance!!
        }
    }
}

