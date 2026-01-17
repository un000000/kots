import org.example.Position
import org.example.Xtea
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.math.pow

internal fun ByteArrayOutputStream.putString16(str: String) {
    val bytes = str.toByteArray()
    write(bytes.size and 0xFF)
    write((bytes.size shr 8) and 0xFF)
    write(bytes)
}
internal inline fun buildPlainBody(block: (ByteArrayOutputStream) -> Unit): ByteArray {
    val out = ByteArrayOutputStream()
    block(out)
    return out.toByteArray()
}

// =========  Shared Helpers  ============= //

/**
 * Collects method-specific payload (no padding, no crypto)
 */

/**
 * paddingAmount + body + paddingBytes → XTEA encrypt
 */

internal val SCALING_BASE = 10.0

internal fun putDoubleWithPrecision(buffer: ByteBuffer, value: Double, precision: Byte = 0x03) {
    buffer.put(precision)
    val scaled = value * SCALING_BASE.pow(precision.toInt())
    buffer.putInt(scaled.toInt() + 0x7fffffff) // ✅ fix: putInt takes Int, not UInt
}
internal fun putCipString(buffer: ByteBuffer, value: String) {
    val stringAsByteArray = value.toByteArray()
    buffer.put(stringAsByteArray.size.toByte())
    buffer.put(0x00)
    buffer.put(stringAsByteArray)
}

internal fun appendPosition(buffer: ByteBuffer, pos: Position) {
    buffer.putShort(pos.x)
    buffer.putShort(pos.y)
    buffer.put(pos.z)
}

internal fun appendAllowBugReport(inner: ByteBuffer, allow: Boolean) {
    // 0x1A + 0x00 (allow) / 0x01 (disable)
    inner.put(0x1A)
    inner.put(if (allow) 0x00 else 0x01)
    // Ref: ProtocolGame::sendAllowBugReport. :contentReference[oaicite:34]{index=34}
}

internal fun appendPendingStateEntered(inner: ByteBuffer) {
    inner.put(0x0A) // Ref: sendPendingStateEntered. :contentReference[oaicite:35]{index=35}
}

internal fun appendEnterWorld(inner: ByteBuffer) {
    inner.put(0x0F) // Ref: sendEnterWorld. :contentReference[oaicite:36]{index=36}
}

internal fun appendTibiaTime(inner: ByteBuffer, secondsSinceMidnight: Int) {
    inner.put(0xEF.toByte()) // Ref: sendTibiaTime. :contentReference[oaicite:37]{index=37}
    inner.put((secondsSinceMidnight / 60).toByte())
    inner.put((secondsSinceMidnight % 60).toByte())
}

internal fun appendFloorDescription(inner: ByteBuffer, skip: Int, pos: Position): Int {
    // appendTileDescription(inner)

    return skip
}

internal fun appendMagicEffect(inner: ByteBuffer, pos: Position) {
    inner.put(0x83.toByte())
    appendPosition(inner, pos)
    inner.put(0x03)
    inner.putShort(11)
    inner.put(0x00)
}

internal fun appendMapDescription(inner: ByteBuffer, pos: Position) {
    inner.put(0x64)
    appendPosition(inner, pos)

    var skip = appendFloorDescription(inner, -1, pos)
    if (skip >= 0) {
        inner.put(skip.toByte())
        inner.put(0xFF.toByte())
    }
}

internal fun writeCreaturePacket(inner: ByteBuffer) {
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