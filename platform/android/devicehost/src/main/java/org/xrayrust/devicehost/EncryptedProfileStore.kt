package org.xrayrust.devicehost

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal class EncryptedProfileStore(context: Context) {
    private val atomicFile = AtomicFile(File(context.noBackupFilesDir, PROFILE_FILE_NAME))

    fun exists(): Boolean = atomicFile.baseFile.isFile

    fun write(configJson: String) {
        require(configJson.isNotBlank()) { "profile config must not be blank" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, profileKey())
        cipher.updateAAD(ASSOCIATED_DATA)
        val plaintext = configJson.toByteArray(Charsets.UTF_8)
        val ciphertext = try {
            cipher.doFinal(plaintext)
        } finally {
            plaintext.fill(0)
        }
        val envelope = ProfileCipherEnvelope.encode(cipher.iv, ciphertext)
        ciphertext.fill(0)

        val output = atomicFile.startWrite()
        try {
            output.write(envelope)
            output.fd.sync()
            atomicFile.finishWrite(output)
        } catch (error: Throwable) {
            atomicFile.failWrite(output)
            throw error
        } finally {
            envelope.fill(0)
        }
    }

    fun read(): String? {
        if (!exists()) {
            return null
        }
        val envelope = atomicFile.readFully()
        require(envelope.size <= MAX_ENVELOPE_BYTES) { "encrypted profile is too large" }
        val (iv, ciphertext) = try {
            ProfileCipherEnvelope.decode(envelope)
        } finally {
            envelope.fill(0)
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, profileKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        cipher.updateAAD(ASSOCIATED_DATA)
        val plaintext = try {
            cipher.doFinal(ciphertext)
        } finally {
            iv.fill(0)
            ciphertext.fill(0)
        }
        return try {
            plaintext.toString(Charsets.UTF_8)
        } finally {
            plaintext.fill(0)
        }
    }

    fun clear() {
        atomicFile.delete()
    }

    private fun profileKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return generator.generateKey()
    }

    private companion object {
        const val PROFILE_FILE_NAME = "device-gate-profile.bin"
        const val KEY_ALIAS = "xray-rust-device-gate-profile-v1"
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        const val MAX_ENVELOPE_BYTES = 1024 * 1024
        val ASSOCIATED_DATA = "xray-rust-device-gate-profile-v1".toByteArray(Charsets.UTF_8)
    }
}

internal object ProfileCipherEnvelope {
    private val MAGIC = byteArrayOf('X'.code.toByte(), 'R'.code.toByte(), 'G'.code.toByte(), 1)
    private const val IV_BYTES = 12
    private const val MIN_GCM_CIPHERTEXT_BYTES = 16

    fun encode(iv: ByteArray, ciphertext: ByteArray): ByteArray {
        require(iv.size == IV_BYTES) { "unexpected profile IV length" }
        require(ciphertext.size >= MIN_GCM_CIPHERTEXT_BYTES) {
            "encrypted profile ciphertext is too short"
        }
        return MAGIC + iv + ciphertext
    }

    fun decode(envelope: ByteArray): Pair<ByteArray, ByteArray> {
        require(envelope.size >= MAGIC.size + IV_BYTES + MIN_GCM_CIPHERTEXT_BYTES) {
            "encrypted profile envelope is truncated"
        }
        require(envelope.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) {
            "unsupported encrypted profile envelope"
        }
        val ivStart = MAGIC.size
        val ciphertextStart = ivStart + IV_BYTES
        return envelope.copyOfRange(ivStart, ciphertextStart) to
            envelope.copyOfRange(ciphertextStart, envelope.size)
    }
}
