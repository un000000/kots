fun adlerChecksum(data: ByteArray, length: Int, start: Int = 0): Int {
    if (length > 0xFFFF) return 0 // same guard as NETWORKMESSAGE_MAXSIZE

    val MOD_ADLER = 65521
    var a = 1
    var b = 0
    var i = start
    var remaining = length

    while (remaining > 0) {
        var tlen = if (remaining > 5552) 5552 else remaining
        remaining -= tlen
        while (tlen-- > 0) {
            a += (data[i].toInt() and 0xFF)
            b += a
            i++
        }
        a %= MOD_ADLER
        b %= MOD_ADLER
    }
    return (b shl 16) or a
}