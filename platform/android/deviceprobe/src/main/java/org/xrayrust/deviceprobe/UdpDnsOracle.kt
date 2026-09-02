package org.xrayrust.deviceprobe

import java.io.ByteArrayOutputStream
import java.util.UUID
import kotlin.random.Random

internal object UdpDnsOracle {
    private val Answer = byteArrayOf(
        0xc0.toByte(), 0x0c,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x04,
        203.toByte(), 0, 113, 1,
    )

    fun makeQuery(
        transactionId: Int = Random.nextInt(0, 65536),
        nonce: UUID = UUID.randomUUID(),
    ): ByteArray {
        require(transactionId in 0..65535) { "DNS transaction id is outside uint16" }
        val output = ByteArrayOutputStream()
        output.write(transactionId ushr 8)
        output.write(transactionId and 0xff)
        output.write(
            byteArrayOf(
                0x01, 0x00,
                0x00, 0x01,
                0x00, 0x00,
                0x00, 0x00,
                0x00, 0x00,
            ),
        )
        val nonceLabel = "xray-" + nonce.toString().replace("-", "").lowercase()
        for (label in listOf(nonceLabel, "example", "com")) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            check(bytes.size <= 63)
            output.write(bytes.size)
            output.write(bytes)
        }
        output.write(byteArrayOf(0x00, 0x00, 0x01, 0x00, 0x01))
        return output.toByteArray()
    }

    fun isValidResponse(response: ByteArray, query: ByteArray): Boolean {
        if (query.size < 12 || response.size != query.size + Answer.size) {
            return false
        }
        val expectedHeader = byteArrayOf(
            query[0], query[1],
            0x81.toByte(), 0x80.toByte(),
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
        )
        return response.copyOfRange(0, 12).contentEquals(expectedHeader) &&
            response.copyOfRange(12, query.size)
                .contentEquals(query.copyOfRange(12, query.size)) &&
            response.copyOfRange(query.size, response.size).contentEquals(Answer)
    }
}
