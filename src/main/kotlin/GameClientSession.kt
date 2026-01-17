import java.nio.ByteBuffer
import java.nio.channels.SocketChannel

class GameClientSession(
    private val client: SocketChannel,
    private val xteaKey: IntArray
) {
    private var serverSequenceNumber = 0

    fun disconnectClient(
        message: String = "disconnectClientTextPlaceholder"
    ) {
        val builder = GameMessageBuilder(
            sequenceProvider = { nextSequence() },
            xteaKey = xteaKey
        )

        val msg = builder.buildDisconnectPacket(message)
        client.write(ByteBuffer.wrap(msg))
    }

    private fun nextSequence(): Int {
        serverSequenceNumber++
        if (serverSequenceNumber >= 0x7FFFFFFF) {
            serverSequenceNumber = 0
        }
        return serverSequenceNumber
    }
}
