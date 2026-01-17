import org.example.Xtea
import java.io.ByteArrayOutputStream

class GameMessageBuilder(
    private val sequenceProvider: () -> Int,
    private val xteaKey: IntArray
) {

    /**
     * Builds the disconnect packet that matches the legacy "sraken pierdaken"
     */
    fun buildDisconnectPacket(message: String): ByteArray {
        val plain = message.toByteArray()

        // ---- A) Build method-specific block (header + payload) ----
        val body = ByteArrayOutputStream()
        body.write(0x14) // disconnect header

        // write UTF-8 length (2 bytes LE)
        body.write((plain.size and 0x00FF) shr 0)
        body.write((plain.size and 0xFF00) shr 8)

        body.write(plain)

        val bodyBytes = body.toByteArray()

        // ---- B) Compose A = paddingAmount + body + padding ----
        val currentLength = bodyBytes.size
        val paddingAmount = (currentLength - 1) % 8

        val msg = ByteArrayOutputStream()
        msg.write(paddingAmount)              // first byte = paddingAmount
        msg.write(bodyBytes)                  // method-specific bytes

        repeat(paddingAmount) { msg.write(0x33) } // padding bytes

        var inner = msg.toByteArray()

        // ---- C) Encrypt ----
        inner = Xtea.encrypt(inner, xteaKey)

        // ---- D) Crypto header (6 bytes) ----
        val sequence = sequenceProvider()
        val sendMessageChecksum =
            if (inner.size >= 128)
                (1 shl 31) or sequence
            else
                sequence

        val messageLength = inner.size / 8 // block count

        val finalBuf = ByteArrayOutputStream()

        // length (2 bytes LE)
        finalBuf.write((messageLength and 0x00FF) shr 0)
        finalBuf.write((messageLength and 0xFF00) shr 8)

        // sequence/checksum (2 bytes LE)
        finalBuf.write((sendMessageChecksum and 0x00FF) shr 0)
        finalBuf.write((sendMessageChecksum and 0xFF00) shr 8)

        // reserved 2 bytes (0x00, 0x00)
        finalBuf.write(0x00)
        finalBuf.write(0x00)

        // encrypted data
        finalBuf.write(inner)

        return finalBuf.toByteArray()
    }
}
