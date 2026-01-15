package org.example

object Xtea {
    private const val ROUNDS = 32
    private const val DELTA = 0x61C88647u

    data class EncryptResult(val data: ByteArray, val paddingSize: Int)

    fun encrypt(data: ByteArray, key: UIntArray): EncryptResult {
        require(key.size == 4) { "XTEA key must be 4 x 32-bit UInts" }

        // Calculate padding needed to make size multiple of 8
        val paddingBytes = (8 - (data.size % 8)) % 8
        val buffer = if (paddingBytes > 0) {
            data + ByteArray(paddingBytes) { 0x33.toByte() }
        } else {
            data.copyOf()
        }

        transform(buffer, key, true)
        return EncryptResult(buffer, paddingBytes)
    }

    fun decrypt(data: ByteArray, key: UIntArray, paddingSize: Int): ByteArray {
        require(key.size == 4) { "XTEA key must be 4 x 32-bit UInts" }
        require(data.size % 8 == 0) { "Encrypted buffer must be multiple of 8 bytes" }

        val buffer = data.copyOf()
        transform(buffer, key, false)

        // Remove padding - return only the meaningful data
        val actualSize = buffer.size - paddingSize
        require(actualSize >= 0) { "Invalid padding size" }

        return buffer.copyOfRange(0, actualSize)
    }

    private fun transform(buffer: ByteArray, key: UIntArray, encrypt: Boolean) {
        // Initial sum: 0 for encrypt, delta * rounds for decrypt
        var sum: UInt = if (encrypt) 0u else (DELTA * ROUNDS.toUInt())

        // Precompute control sums exactly like Canary
        val cs = Array(ROUNDS) { UIntArray(2) }

        if (encrypt) {
            for (i in 0 until ROUNDS) {
                cs[i][0] = sum + key[(sum and 3u).toInt()]
                sum -= DELTA
                cs[i][1] = sum + key[((sum shr 11) and 3u).toInt()]
            }
        } else {
            for (i in 0 until ROUNDS) {
                cs[i][0] = sum + key[((sum shr 11) and 3u).toInt()]
                sum += DELTA
                cs[i][1] = sum + key[(sum and 3u).toInt()]
            }
        }

        var pos = 0
        while (pos < buffer.size) {
            var v0 = loadUIntLE(buffer, pos)
            var v1 = loadUIntLE(buffer, pos + 4)

            if (encrypt) {
                for (i in 0 until ROUNDS) {
                    v0 += (((v1 shl 4) xor (v1 shr 5)) + v1) xor cs[i][0]
                    v1 += (((v0 shl 4) xor (v0 shr 5)) + v0) xor cs[i][1]
                }
            } else {
                for (i in 0 until ROUNDS) {
                    v1 -= (((v0 shl 4) xor (v0 shr 5)) + v0) xor cs[i][0]
                    v0 -= (((v1 shl 4) xor (v1 shr 5)) + v1) xor cs[i][1]
                }
            }

            storeUIntLE(buffer, pos, v0)
            storeUIntLE(buffer, pos + 4, v1)
            pos += 8
        }
    }

    private fun loadUIntLE(buf: ByteArray, pos: Int): UInt =
        (buf[pos + 0].toUInt() and 0xFFu) or
                ((buf[pos + 1].toUInt() and 0xFFu) shl 8) or
                ((buf[pos + 2].toUInt() and 0xFFu) shl 16) or
                ((buf[pos + 3].toUInt() and 0xFFu) shl 24)

    private fun storeUIntLE(buf: ByteArray, pos: Int, value: UInt) {
        buf[pos + 0] = (value and 0xFFu).toByte()
        buf[pos + 1] = ((value shr 8) and 0xFFu).toByte()
        buf[pos + 2] = ((value shr 16) and 0xFFu).toByte()
        buf[pos + 3] = ((value shr 24) and 0xFFu).toByte()
    }
}