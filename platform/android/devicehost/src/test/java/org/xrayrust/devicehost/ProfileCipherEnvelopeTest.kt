package org.xrayrust.devicehost

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProfileCipherEnvelopeTest {
    @Test
    fun roundTripsFixedLengthIvAndCiphertext() {
        val iv = ByteArray(12) { it.toByte() }
        val ciphertext = ByteArray(32) { (it + 12).toByte() }

        val (decodedIv, decodedCiphertext) = ProfileCipherEnvelope.decode(
            ProfileCipherEnvelope.encode(iv, ciphertext),
        )

        assertArrayEquals(iv, decodedIv)
        assertArrayEquals(ciphertext, decodedCiphertext)
    }

    @Test
    fun rejectsWrongVersionAndTruncatedCiphertext() {
        val valid = ProfileCipherEnvelope.encode(ByteArray(12), ByteArray(16))
        valid[3] = 2
        assertThrows(IllegalArgumentException::class.java) {
            ProfileCipherEnvelope.decode(valid)
        }
        assertThrows(IllegalArgumentException::class.java) {
            ProfileCipherEnvelope.decode(ByteArray(20))
        }
    }
}
