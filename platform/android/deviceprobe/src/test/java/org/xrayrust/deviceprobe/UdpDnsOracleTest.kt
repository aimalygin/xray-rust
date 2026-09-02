package org.xrayrust.deviceprobe

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class UdpDnsOracleTest {
    private val nonce = UUID.fromString("11111111-2222-4333-8444-555555555555")

    @Test
    fun validatesTheStrictDnsOracleResponse() {
        val query = UdpDnsOracle.makeQuery(transactionId = 0x1234, nonce = nonce)
        val response = responseFor(query)

        assertTrue(UdpDnsOracle.isValidResponse(response, query))
        assertTrue(query.toString(Charsets.ISO_8859_1).contains("xray-11111111222243338444555555555555"))
    }

    @Test
    fun rejectsChangedTransactionQuestionAnswerAndLength() {
        val query = UdpDnsOracle.makeQuery(transactionId = 0x1234, nonce = nonce)
        val response = responseFor(query)

        assertFalse(UdpDnsOracle.isValidResponse(response.copyOf(response.size - 1), query))
        assertFalse(UdpDnsOracle.isValidResponse(response.copyOf().also { it[0] = 0x22 }, query))
        assertFalse(UdpDnsOracle.isValidResponse(response.copyOf().also { it[20] = 0x22 }, query))
        assertFalse(
            UdpDnsOracle.isValidResponse(
                response.copyOf().also { it[it.lastIndex] = 0x22 },
                query,
            ),
        )
    }

    private fun responseFor(query: ByteArray): ByteArray =
        byteArrayOf(
            query[0], query[1],
            0x81.toByte(), 0x80.toByte(),
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
        ) + query.copyOfRange(12, query.size) + byteArrayOf(
            0xc0.toByte(), 0x0c,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x04,
            203.toByte(), 0, 113, 1,
        )
}
