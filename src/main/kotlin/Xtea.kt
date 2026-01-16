package org.example

// Put this anywhere top-level in the file (e.g., above GameServer)
object Xtea {
    private const val ROUNDS = 32
    private const val DELTA = 0x61C88647.toInt() // same as Protocol::XTEA_transform

    /**
     * Encrypts the given bytes with the 128-bit XTEA key.
     * Pads with zeros to a multiple of 8 (like Protocol::XTEA_encrypt).
     */
    fun encrypt(data: ByteArray, key: IntArray): ByteArray {
        require(key.size == 4) { "XTEA key must be 4 x 32-bit ints" }

        val pad = (8 - (data.size % 8)) % 8
        val out = data.copyOf(data.size + pad)

        // Precompute control sums exactly like the C++ version
        val ctrl = Array(ROUNDS) { IntArray(2) }
        var sum = 0
        for (i in 0 until ROUNDS) {
            ctrl[i][0] = sum + key[sum and 3]
            sum -= DELTA
            ctrl[i][1] = sum + key[(sum ushr 11) and 3]
        }

        var i = 0
        while (i < out.size) {
            var v0 =  (out[i].toInt() and 0xFF) or
                    ((out[i+1].toInt() and 0xFF) shl 8) or
                    ((out[i+2].toInt() and 0xFF) shl 16) or
                    ((out[i+3].toInt() and 0xFF) shl 24)
            var v1 =  (out[i+4].toInt() and 0xFF) or
                    ((out[i+5].toInt() and 0xFF) shl 8) or
                    ((out[i+6].toInt() and 0xFF) shl 16) or
                    ((out[i+7].toInt() and 0xFF) shl 24)

            for (r in 0 until ROUNDS) {
                v0 += (((v1 shl 4) xor (v1 ushr 5)) + v1) xor ctrl[r][0]
                v1 += (((v0 shl 4) xor (v0 ushr 5)) + v0) xor ctrl[r][1]
            }

            // write back little-endian
            out[i]   = (v0 and 0xFF).toByte()
            out[i+1] = ((v0 ushr 8) and 0xFF).toByte()
            out[i+2] = ((v0 ushr 16) and 0xFF).toByte()
            out[i+3] = ((v0 ushr 24) and 0xFF).toByte()
            out[i+4] = (v1 and 0xFF).toByte()
            out[i+5] = ((v1 ushr 8) and 0xFF).toByte()
            out[i+6] = ((v1 ushr 16) and 0xFF).toByte()
            out[i+7] = ((v1 ushr 24) and 0xFF).toByte()

            i += 8
        }
        return out
    }
}
