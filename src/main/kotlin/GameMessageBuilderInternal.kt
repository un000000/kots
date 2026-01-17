import org.example.Xtea
import java.io.ByteArrayOutputStream

internal class GameMessageBuilderInternal(
    private val sequenceProvider: () -> Int,
    private val xteaKey: IntArray
) {
    internal inline fun buildPacket(block: (ByteArrayOutputStream) -> Unit): ByteArray {
        val body = buildPlainBody(block)
        val encrypted = wrapAndEncrypt(body)
        return wrapCryptoHeader(encrypted)
    }

    fun wrapAndEncrypt(body: ByteArray): ByteArray {
        val currentLength = body.size
        val paddingAmount = (currentLength - 1) % 8

        val buf = ByteArrayOutputStream()
        buf.write(paddingAmount)
        buf.write(body)
        repeat(paddingAmount) { buf.write(0x33) }

        return Xtea.encrypt(buf.toByteArray(), xteaKey)
    }

    fun wrapCryptoHeader(encrypted: ByteArray): ByteArray {
        val sequence = sequenceProvider()
        val checksum = if (encrypted.size >= 128)
            (1 shl 31) or sequence else sequence

        val blockCount = encrypted.size / 8
        val out = ByteArrayOutputStream()

        out.write(blockCount and 0xFF)
        out.write((blockCount shr 8) and 0xFF)
        out.write(checksum and 0xFF)
        out.write((checksum shr 8) and 0xFF)
        out.write(0x00)
        out.write(0x00)
        out.write(encrypted)
        return out.toByteArray()
    }
}
