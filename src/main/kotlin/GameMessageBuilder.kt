import org.example.Position
import org.example.Xtea
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.math.pow

class GameMessageBuilder(
    private val sequenceProvider: () -> Int,
    private val xteaKey: IntArray
) {
    // =========  Public Packet APIs  ============= //

    fun buildDisconnectPacket(message: String): ByteArray {
        val body = buildPlainBody { out ->
            out.write(0x14) // disconnect opcode

            val bytes = message.toByteArray()
            out.write(bytes.size and 0xFF)
            out.write((bytes.size shr 8) and 0xFF)
            out.write(bytes)
        }

        val encrypted = wrapAndEncrypt(body)
        return wrapCryptoHeader(encrypted)
    }

    fun buildSendAddCreaturePacket(): ByteArray {
        val body = buildPlainBody { out ->
            // build any opcode-based payload
            val tmp = ByteBuffer.allocate(2048)
            writeCreaturePacket(tmp)
            tmp.flip()
            out.write(tmp.array(), 0, tmp.limit())
        }

        val encrypted = wrapAndEncrypt(body)
        return wrapCryptoHeader(encrypted)
    }

    // =========  Shared Helpers  ============= //

    /**
     * Collects method-specific payload (no padding, no crypto)
     */
    private inline fun buildPlainBody(block: (ByteArrayOutputStream) -> Unit): ByteArray {
        val out = ByteArrayOutputStream()
        block(out)
        return out.toByteArray()
    }

    /**
     * paddingAmount + body + paddingBytes → XTEA encrypt
     */
    private fun wrapAndEncrypt(body: ByteArray): ByteArray {
        // body length = header+payload
        val currentLength = body.size
        val paddingAmount = (currentLength - 1) % 8

        val buf = ByteArrayOutputStream()
        buf.write(paddingAmount)    // 1 byte (dynamic)
        buf.write(body)             // raw opcode payload

        repeat(paddingAmount) { buf.write(0x33) }

        return Xtea.encrypt(buf.toByteArray(), xteaKey)
    }

    /**
     * Adds crypto header (6 bytes) before encrypted blob
     */
    private fun wrapCryptoHeader(encrypted: ByteArray): ByteArray {
        val sequence = sequenceProvider()
        val checksum =
            if (encrypted.size >= 128)
                (1 shl 31) or sequence
            else
                sequence

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
        // appendTileDescription(inner)

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

        var skip = appendFloorDescription(inner, -1, pos)
        if (skip >= 0) {
            inner.put(skip.toByte())
            inner.put(0xFF.toByte())
        }
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

}