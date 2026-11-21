package ccfb.hsm.crypto

import ccfb.hsm.model.CipherFamily

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Hex helpers. All block representations in this project are upper-case hex strings. */
object Hex {
    private const val DIGITS = "0123456789ABCDEF"

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(DIGITS[v ushr 4]).append(DIGITS[v and 0x0F])
        }
        return sb.toString()
    }

    fun decode(s: String): ByteArray {
        require(s.length % 2 == 0) { "hex string must have even length" }
        val out = ByteArray(s.length / 2)
        for (i in out.indices) {
            out[i] = ((digit(s[2 * i]) shl 4) or digit(s[2 * i + 1])).toByte()
        }
        return out
    }

    fun tryDecode(s: String): ByteArray? = try {
        if (s.length % 2 == 0) decode(s) else null
    } catch (_: IllegalArgumentException) {
        null
    }

    fun isHex(s: String): Boolean = s.isNotEmpty() && s.length % 2 == 0 && s.all { isHexDigit(it) }

    fun isHexDigit(c: Char): Boolean =
        c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

    private fun digit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("not a hex digit: $c")
    }
}

/** Single DES, ECB, no padding. Used as the primitive for 3DES and for PVV / IBM offset. */
object Des {
    fun encrypt(key: ByteArray, data: ByteArray): ByteArray = run(Cipher.ENCRYPT_MODE, key, data)
    fun decrypt(key: ByteArray, data: ByteArray): ByteArray = run(Cipher.DECRYPT_MODE, key, data)

    private fun run(mode: Int, key: ByteArray, data: ByteArray): ByteArray {
        require(key.size == 8) { "DES key must be 8 bytes, got ${key.size}" }
        require(data.isNotEmpty() && data.size % 8 == 0) { "DES data must be a non-empty multiple of 8" }
        val c = Cipher.getInstance("DES/ECB/NoPadding")
        c.init(mode, SecretKeySpec(key, "DES"))
        return c.doFinal(data)
    }
}

/**
 * Triple DES (EDE) implemented over single-DES so that 2-key (16 byte) keys work on every JDK.
 * JDK 27's SunJCE rejects 16-byte DESede keys, and real HSM key material is frequently 2-key.
 */
object Tdes {
    fun expand(key: ByteArray): ByteArray = when (key.size) {
        16 -> key + key.copyOfRange(0, 8)
        24 -> key
        else -> throw IllegalArgumentException("3DES key must be 16 or 24 bytes, got ${key.size}")
    }

    fun encrypt(key: ByteArray, data: ByteArray): ByteArray {
        val k = expand(key)
        require(data.isNotEmpty() && data.size % 8 == 0)
        val k1 = k.copyOfRange(0, 8)
        val k2 = k.copyOfRange(8, 16)
        val k3 = k.copyOfRange(16, 24)
        val out = ByteArray(data.size)
        var off = 0
        while (off < data.size) {
            val block = data.copyOfRange(off, off + 8)
            val step1 = Des.encrypt(k1, block)
            val step2 = Des.decrypt(k2, step1)
            val step3 = Des.encrypt(k3, step2)
            System.arraycopy(step3, 0, out, off, 8)
            off += 8
        }
        return out
    }

    fun decrypt(key: ByteArray, data: ByteArray): ByteArray {
        val k = expand(key)
        require(data.isNotEmpty() && data.size % 8 == 0)
        val k1 = k.copyOfRange(0, 8)
        val k2 = k.copyOfRange(8, 16)
        val k3 = k.copyOfRange(16, 24)
        val out = ByteArray(data.size)
        var off = 0
        while (off < data.size) {
            val block = data.copyOfRange(off, off + 8)
            val step1 = Des.decrypt(k3, block)
            val step2 = Des.encrypt(k2, step1)
            val step3 = Des.decrypt(k1, step2)
            System.arraycopy(step3, 0, out, off, 8)
            off += 8
        }
        return out
    }
}

object Aes {
    fun encrypt(key: ByteArray, data: ByteArray): ByteArray = run(Cipher.ENCRYPT_MODE, key, data)
    fun decrypt(key: ByteArray, data: ByteArray): ByteArray = run(Cipher.DECRYPT_MODE, key, data)

    private fun run(mode: Int, key: ByteArray, data: ByteArray): ByteArray {
        require(key.size == 16 || key.size == 24 || key.size == 32) { "AES key must be 16/24/32 bytes" }
        require(data.isNotEmpty() && data.size % 16 == 0) { "AES data must be a non-empty multiple of 16" }
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(mode, SecretKeySpec(key, "AES"))
        return c.doFinal(data)
    }
}

/**
 * Visa decimalization, exactly as Visa specifies and jPOS implements it:
 *
 *   1. walk the 16 hex characters and emit the decimal ones (0-9) in order;
 *   2. then walk them again and emit A-F mapped to 0-5, appended after the digits.
 *
 * The result is therefore NOT a positional substitution of the hex string. Getting this
 * wrong is the classic PVV/CVV implementation bug: it still produces plausible-looking
 * values, and only a published vector catches it. Verified here by the jPOS vectors
 * (PVV 1226, CVV 204/453).
 */
object Decimalize {
    fun visa(hex: String): String {
        val upper = hex.uppercase()
        val out = StringBuilder(upper.length)
        for (c in upper) {
            if (c !in '0'..'9' && c !in 'A'..'F') throw IllegalArgumentException("not a hex digit: $c")
            if (c in '0'..'9') out.append(c)
        }
        for (c in upper) {
            if (c in 'A'..'F') out.append('0' + (c - 'A'))
        }
        return out.toString()
    }
}

object Hashing {
    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)
    fun sha256Hex(data: ByteArray): String = Hex.encode(sha256(data))
    fun sha256Hex(s: String): String = sha256Hex(s.toByteArray(Charsets.UTF_8))

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun hmacSha256Hex(key: ByteArray, data: String): String =
        Hex.encode(hmacSha256(key, data.toByteArray(Charsets.UTF_8)))
}

/** Constant-time comparison; never short-circuits on the first differing byte. */
object ConstantTime {
    fun equals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)
    fun equals(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(Charsets.US_ASCII), b.toByteArray(Charsets.US_ASCII))
}

object RandomBytes {
    private val rng = SecureRandom()

    fun get(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun hex(nibbles: Int): String {
        val chars = "0123456789ABCDEF"
        val sb = StringBuilder(nibbles)
        repeat(nibbles) { sb.append(chars[rng.nextInt(16)]) }
        return sb.toString()
    }

    /** Random decimal string, used for PIN generation. */
    fun digits(n: Int): String {
        val sb = StringBuilder(n)
        repeat(n) { sb.append(('0' + rng.nextInt(10))) }
        return sb.toString()
    }

    fun int(bound: Int): Int = rng.nextInt(bound)
}

object BlockCipher {
    fun encrypt(family: CipherFamily, key: ByteArray, data: ByteArray): ByteArray = when (family) {
        CipherFamily.DES -> Des.encrypt(key, data)
        CipherFamily.TDES -> Tdes.encrypt(key, data)
        CipherFamily.AES -> Aes.encrypt(key, data)
    }

    fun decrypt(family: CipherFamily, key: ByteArray, data: ByteArray): ByteArray = when (family) {
        CipherFamily.DES -> Des.decrypt(key, data)
        CipherFamily.TDES -> Tdes.decrypt(key, data)
        CipherFamily.AES -> Aes.decrypt(key, data)
    }

    fun familyOf(keyLen: Int): CipherFamily = when (keyLen) {
        8 -> CipherFamily.DES
        16, 24 -> CipherFamily.TDES
        32 -> CipherFamily.AES
        else -> throw IllegalArgumentException("unsupported key length $keyLen")
    }
}
