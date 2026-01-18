import org.example.Position
import org.example.Xtea
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import kotlin.math.pow

internal data class Tile(val groundId: Int)

internal val validGroundIds = listOf(419, 420, 452, 453)

internal fun generateDummyMap(center: Position, width: Int, height: Int): Array<Array<Tile?>> {
    // center tile always exists; neighbors randomly exist or are null
    return Array(width) { x ->
        Array(height) { y ->
            if (Math.random() > 0.0) Tile(groundId = validGroundIds.random()) else null
        }
    }
}

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

private fun appendTileDescription(inner: ByteBuffer, tile: Tile) {
    // C++: AddItem(msg, ground) → Tibia protocol sends uint16 for ground type
    inner.put((tile.groundId).toByte())
    inner.put(((tile.groundId shr 8) and 0xFF).toByte())
}

private fun appendFloorDescription(
    inner: ByteBuffer,
    map: Array<Array<Tile?>>,
    width: Int,
    height: Int,
    skip: Int
): Int {
    var s = skip
    for (w in 0 until width) {
        for (h in 0 until height) {
            val tile = map[w][h]
            if (tile != null) {
                // flush skip first if pending
                if (s >= 0) {
                    inner.put(s.toByte())
                    inner.put(0xFF.toByte())
                }
                s = 0
                appendTileDescription(inner, tile)
                if (w == 8 && h == 6){
                    writeGodCreature(inner)
                }
            } else {
                // no tile; normal skip behavior
                if (s == 0xFE) {
                    inner.put(0xFF.toByte())
                    inner.put(0xFF.toByte())
                    s = -1
                } else {
                    s++
                }
            }
        }
    }
    return s
}

internal fun appendMagicEffect(inner: ByteBuffer, pos: Position) {
    inner.put(0x83.toByte())
    appendPosition(inner, pos)
    inner.put(0x03)
    inner.putShort(11)
    inner.put(0x00)
}

internal fun appendWorldLight(inner: ByteBuffer) {
    inner.put(0x82.toByte())
    inner.put(0xFF.toByte())
    inner.put(0x16.toByte())
}

internal fun appendCreatureLight(inner: ByteBuffer, creatureId: Int) {
    inner.put(0x8D.toByte())
    inner.putIntLE(creatureId)
    inner.put(0x05.toByte())
    inner.put(0x17.toByte())
}

private fun ByteBuffer.putIntLE(value: Int) {
    put((value and 0xFF).toByte())
    put(((value shr 8) and 0xFF).toByte())
    put(((value shr 16) and 0xFF).toByte())
    put(((value shr 32) and 0xFF).toByte())
}

internal fun appendMapDescription(inner: ByteBuffer, pos: Position) {
    inner.put(0x64) // opcode
    appendPosition(inner, pos)

    // --- CONFIG: tiny viewport (7x7 like mini radar) ---
    val width = 18
    val height = 14

    // generate synthetic map
    val map = generateDummyMap(pos, width, height)

    // C++ logic has layers; here we simplify: only current z
    var skip = -1
    skip = appendFloorDescription(inner, map, width, height, skip)

    // flush remaining skip at end
    if (skip >= 0) {
        inner.put(skip.toByte())
        inner.put(0xFF.toByte())
    }
}

internal fun writeGodCreature(inner: ByteBuffer) {
    inner.put(0x61.toByte()) // opcode
    inner.put(0x00.toByte())

    inner.put(0x00.toByte()) // should remove
    inner.put(0x00.toByte())
    inner.put(0x00.toByte())
    inner.put(0x00.toByte())

    //inner.put(0x06.toByte())
    inner.put(0x08.toByte()) // id
    inner.put(0x00.toByte())
    inner.put(0x00.toByte())
    inner.put(0x10.toByte())

    inner.put(0x00.toByte()) // master id

    inner.put(0x03.toByte()) // str len
    inner.put(0x00.toByte()) // str len
    inner.put(0x47.toByte()) //g
    inner.put(0x4f.toByte()) //o
    inner.put(0x44.toByte()) //d

    inner.put(0x64.toByte()) // currentHealth / maxhealth * 100

    inner.put(0x02.toByte()) // direction

    inner.put(0x88.toByte()) // lookType
    inner.put(0x00.toByte()) // lookType
    inner.put(0x5f.toByte()) // head
    inner.put(0x71.toByte()) // body
    inner.put(0x27.toByte()) // legs
    inner.put(0x73.toByte()) // torso
    inner.put(0x00.toByte()) // addons
    inner.put(0x00.toByte()) // mount
    inner.put(0x00.toByte()) // mount

    inner.put(0xff.toByte()) // light strength
    inner.put(0xd7.toByte()) // light color

    inner.put(0xff.toByte()) // step speed
    inner.put(0xff.toByte()) // step speed

    inner.put(0x00.toByte()) // icon count

    inner.put(0x00.toByte()) // skull
    inner.put(0x00.toByte()) // party shield
    inner.put(0x00.toByte()) // guild emblem
    inner.put(0x00.toByte()) // creatureType
    inner.put(0x00.toByte()) // vocation
    inner.put(0x00.toByte()) // speech bubble
    inner.put(0xff.toByte()) // minimark map
    inner.put(0x00.toByte()) // inspection type?
    inner.put(0x00.toByte()) // can walk through it
}

internal fun writeCreaturePacket(inner: ByteBuffer) {
    val storeImagesUrl = "http://127.0.0.1/images/store/"

    inner.put(0x17)
    val creatureId = 268435464
    inner.putInt(creatureId)
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

    appendWorldLight(inner)
    //appendCreatureLight(inner, creatureId)
    appendMapDescription(inner, pos)

    //appendMagicEffect(inner, pos)

    /*
    inner.put(0x75.toByte())
    inner.put(0xff.toByte())
    inner.put(0xa3.toByte())
    inner.put(0x11.toByte())

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
     */

}

