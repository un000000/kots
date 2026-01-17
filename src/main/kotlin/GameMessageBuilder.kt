import java.nio.ByteBuffer

class GameMessageBuilder(
    private val sequenceProvider: () -> Int,
    private val xteaKey: IntArray
) {
    // =========  Public Packet APIs  ============= //
    private val builderInternal = GameMessageBuilderInternal(sequenceProvider, xteaKey)

    fun buildDisconnectPacket(message: String): ByteArray =
        builderInternal.buildPacket { out ->
            out.write(0x14) // opcode
            out.putString16(message)
        }

    fun buildSendAddCreaturePacket(): ByteArray =
        builderInternal.buildPacket { out ->
            val tmp = ByteBuffer.allocate(2048)
            writeCreaturePacket(tmp)
            tmp.flip()
            out.write(tmp.array(), 0, tmp.limit())
        }
}