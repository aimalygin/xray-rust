package org.xrayrust.mobile

// Bounded syntax/key validation matching Rust and Swift. The low-order
// encodings include RFC 7748 high-bit aliases; this is not key agreement.
internal object XrayVlessEncryption {
    const val expected = "none or bounded mlkem768x25519plus.{native|xorpub|random}.{1rtt|0rtt}.[padding.]<1-8 public keys>"
    private const val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val lowOrder = setOf(
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    )

    fun isSupported(value: String): Boolean {
        if (value == "none") return true
        if (value.toByteArray(Charsets.UTF_8).size > 16_384) return false
        val parts = value.split('.')
        if (parts.size < 4 || parts[0] != "mlkem768x25519plus" ||
            parts[1] !in setOf("native", "xorpub", "random") ||
            parts[2] !in setOf("1rtt", "0rtt")) return false
        val keyStart = (3 until parts.size).firstOrNull { parts[it].length >= 20 } ?: return false
        val padding = parts.subList(3, keyStart)
        val keys = parts.subList(keyStart, parts.size)
        if (padding.size > 32 || keys.size !in 1..8 || !validPadding(padding) ||
            !keys.all(::validKey)) return false
        return true
    }

    private fun validPadding(parts: List<String>): Boolean {
        var totalLength = 0L
        var totalGap = 0L
        for ((index, part) in parts.withIndex()) {
            if (part.length >= 20) return false
            val fields = part.split('-')
            if (fields.size != 3 || fields.any { it.isEmpty() || it.any { char -> char !in '0'..'9' } }) return false
            val values = fields.map { it.toLongOrNull() ?: return false }
            val probability = values[0]
            val low = minOf(values[1], values[2])
            val high = maxOf(values[1], values[2])
            if (probability !in 0..100 || low !in 0..4_294_967_295L ||
                high !in 0..4_294_967_295L) return false
            if (index == 0 && (probability != 100L || low < 35)) return false
            if (index % 2 == 0) {
                totalLength += high
                if (totalLength > 65_553) return false
            } else {
                totalGap += high
                if (high > 1_000 || totalGap > 5_000) return false
            }
        }
        return true
    }

    private fun validKey(encoded: String): Boolean {
        if (encoded.length != 43 && encoded.length != 1579) return false
        // Strict unpadded base64url, also on Android API 24/25 where the Java
        // Base64 API is unavailable. Reject nonzero unused bits explicitly.
        val bytes = IntArray(encoded.length * 6 / 8)
        var bits = 0
        var acc = 0
        var index = 0
        for (char in encoded) {
            val digit = alphabet.indexOf(char)
            if (digit < 0) return false
            acc = (acc shl 6) or digit
            bits += 6
            if (bits >= 8) {
                bits -= 8
                bytes[index++] = (acc shr bits) and 255
                acc = acc and ((1 shl bits) - 1)
            }
        }
        if (acc != 0) return false
        if (bytes.size == 32) {
            bytes[31] = bytes[31] and 127
            return bytes.joinToString("") { it.toString(16).padStart(2, '0') } !in lowOrder
        }
        if (bytes.size != 1184) return false
        for (i in 0 until 1152 step 3) {
            val a = bytes[i] or ((bytes[i + 1] and 15) shl 8)
            val b = (bytes[i + 1] shr 4) or (bytes[i + 2] shl 4)
            if (a >= 3329 || b >= 3329) return false
        }
        return true
    }
}
