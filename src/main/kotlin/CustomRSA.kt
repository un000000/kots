package org.example

import java.io.File
import java.math.BigInteger

// Fixed CustomRSA Implementation
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
     * Set RSA key from p and q strings (matching C++ setKey function exactly)
     * @param pString prime p as string
     * @param qString prime q as string
     * @param base number base (10 for decimal, 16 for hex)
     */
    fun setKey(pString: String, qString: String, base: Int = 10) {
        val p = BigInteger(pString, base)
        val q = BigInteger(qString, base)
        val e = BigInteger.valueOf(65537) // standard RSA public exponent

        // n = p * q (exactly as in C++: mpz_mul(n, p, q))
        n = p.multiply(q)

        // d = e^-1 mod (p-1)(q-1) (exactly as in C++)
        val p1 = p.subtract(BigInteger.ONE)  // p - 1
        val q1 = q.subtract(BigInteger.ONE)  // q - 1
        val pq1 = p1.multiply(q1)            // (p-1)(q-1) = φ(n)

        // d = e^-1 mod φ(n) (exactly as in C++: mpz_invert(d, e, pq1))
        d = e.modInverse(pq1)

        println("RSA key set: n has ${n.bitLength()} bits, d has ${d.bitLength()} bits")
    }

    /**
     * Decrypt message in place (matching C++ decrypt function exactly)
     * Expects exactly 128 bytes of encrypted data
     */
    fun decrypt(msg: ByteArray) {
        require(msg.size >= 128) { "Message must be at least 128 bytes" }

        // Import 128 bytes as big integer (matching C++: mpz_import(c, 128, 1, 1, 0, 0, msg))
        // Parameters: 1 = most significant word first, 1 = each word is 1 byte, 0 = native endian, 0 = no nails
        val c = BigInteger(1, msg.copyOfRange(0, 128))

        // m = c^d mod n (matching C++: mpz_powm(m, c, d, n))
        val m = c.modPow(d, n)

        // Convert back to bytes (matching C++ export logic)
        val decryptedBytes = m.toByteArray()

        // Calculate count exactly as in C++: (mpz_sizeinbase(m, 2) + 7) / 8
        // But we need to handle BigInteger.toByteArray() which may include sign byte
        val actualBytes = if (decryptedBytes.isNotEmpty() && decryptedBytes[0] == 0.toByte()) {
            // Remove sign byte if present
            decryptedBytes.copyOfRange(1, decryptedBytes.size)
        } else {
            decryptedBytes
        }

        val count = actualBytes.size

        // Clear the message buffer first (matching C++: std::fill(msg, msg + (128 - count), 0))
        msg.fill(0, 0, 128 - count)

        // Copy decrypted bytes to the right position (matching C++: mpz_export(msg + (128 - count), ...))
        if (count > 0 && count <= 128) {
            System.arraycopy(actualBytes, 0, msg, 128 - count, count)
        }
    }

    /**
     * Base64 decode with custom character mapping (matching C++ implementation exactly)
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
     * This matches the C++ parseASN1RSAKey functionality
     */
    private fun parseASN1RSAKey(keyData: ByteArray): Boolean {
        try {
            val reader = ASN1Reader(keyData)

            // Parse SEQUENCE (matching C++ CRYPT_RSA_ASN1_SEQUENCE check)
            if (!reader.expectTag(0x30)) {
                println("Invalid unsupported RSA key - missing SEQUENCE")
                return false
            }
            
            val topLength = reader.readLength()
            if (topLength != keyData.size - reader.pos) {
                println("Invalid unsupported RSA key - length mismatch")
                return false
            }

            // Handle different key formats (matching C++ logic)
            var tag = reader.peekTag()
            
            // Check for PKCS#8 format (version + algorithm identifier)
            if (tag == 0x02) { // INTEGER
                val versionOrLength = reader.readInteger()
                
                // Check if this looks like PKCS#8 (version 0 or 1, followed by algorithm identifier)
                val nextTag = reader.peekTag()
                if ((versionOrLength == BigInteger.ZERO || versionOrLength == BigInteger.ONE) && nextTag == 0x30) {
                    // This is PKCS#8, skip algorithm identifier
                    if (!reader.expectTag(0x30)) return false
                    val algLen = reader.readLength()
                    reader.skipBytes(algLen)

                    // Read OCTET STRING containing PKCS#1 data
                    if (!reader.expectTag(0x04)) return false
                    val pkcs1Len = reader.readLength()
                    val pkcs1Data = reader.readBytes(pkcs1Len)
                    return parseASN1RSAKey(pkcs1Data) // Recursive call for inner PKCS#1
                } else {
                    // This might be direct PKCS#1, rewind
                    reader.pos -= reader.getIntegerBytes(versionOrLength).size + 2 // tag + length
                }
            }

            // Parse PKCS#1 RSAPrivateKey structure
            // RSAPrivateKey ::= SEQUENCE {
            //     version           Version,
            //     modulus           INTEGER,  -- n
            //     publicExponent    INTEGER,  -- e  
            //     privateExponent   INTEGER,  -- d
            //     prime1            INTEGER,  -- p
            //     prime2            INTEGER,  -- q
            //     exponent1         INTEGER,  -- d mod (p-1)
            //     exponent2         INTEGER,  -- d mod (q-1)
            //     coefficient       INTEGER   -- (inverse of q) mod p
            // }

            // Version should be 0
            val version = reader.readInteger()
            if (version != BigInteger.ZERO) {
                println("Unsupported RSA key version: $version")
            }

            // Skip modulus (n), publicExponent (e), privateExponent (d)
            reader.readInteger() // n (modulus)
            reader.readInteger() // e (public exponent) 
            reader.readInteger() // d (private exponent)

            // Read p and q (prime1 and prime2)
            val p = reader.readInteger()
            val q = reader.readInteger()

            println("Loaded RSA key: p has ${p.bitLength()} bits, q has ${q.bitLength()} bits")

            // Convert to hex strings and set key (matching C++ behavior: readHexString + setKey(..., 16))
            val pString = p.toString(16).uppercase()
            val qString = q.toString(16).uppercase()

            setKey(pString, qString, 16)
            return true

        } catch (e: Exception) {
            println("Error parsing ASN.1 RSA key: ${e.message}")
            e.printStackTrace()
            return false
        }
    }

    /**
     * Simple ASN.1 DER reader (matching C++ decodeLength and readHexString functionality)
     */
    private class ASN1Reader(private val data: ByteArray) {
        var pos = 0

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
            return BigInteger(1, bytes) // Always treat as positive
        }

        fun getIntegerBytes(value: BigInteger): ByteArray {
            return value.toByteArray()
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