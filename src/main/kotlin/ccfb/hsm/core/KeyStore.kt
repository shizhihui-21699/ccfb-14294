package ccfb.hsm.core

import ccfb.hsm.crypto.BlockCipher

import ccfb.hsm.crypto.ConstantTime
import ccfb.hsm.crypto.Hex
import ccfb.hsm.crypto.Hashing
import ccfb.hsm.crypto.RandomBytes
import ccfb.hsm.model.HsmException
import ccfb.hsm.model.ErrorCode
import ccfb.hsm.model.KeyUsage
import ccfb.hsm.model.CipherFamily

/**
 * Key material plus the policy attached to it.
 *
 * [kcv] is the standard key check value (first 6 hex digits of the encryption of a
 * zero block). It is public and safe to log; [bytes] is not.
 */
class HsmKey internal constructor(
    val id: String,
    val usage: KeyUsage,
    val family: CipherFamily,
    internal val bytes: ByteArray,
    val kcv: String,
    /** Endpoint this key belongs to; a client may only name keys it is allowed to use. */
    val owner: String
) {
    val lengthBytes: Int get() = bytes.size
    val algorithm: String
        get() = when (family) {
            CipherFamily.DES -> "DES"
            CipherFamily.TDES -> if (bytes.size == 16) "3DES-2KEY" else "3DES-3KEY"
            CipherFamily.AES -> "AES-${bytes.size * 8}"
        }

    fun encrypt(data: ByteArray): ByteArray = BlockCipher.encrypt(family, bytes, data)
    fun decrypt(data: ByteArray): ByteArray = BlockCipher.decrypt(family, bytes, data)

    override fun toString(): String = "HsmKey($id,$usage,$algorithm,kcv=$kcv)"
}

/**
 * In-memory key store with an integrity-protected index.
 *
 * Real HSMs keep keys in tamper-responsive memory and expose them only through commands
 * that enforce usage. The properties this simulator reproduces:
 *
 *  - Key bytes are never returned by any API; only metadata and KCV.
 *  - A key's [KeyUsage] is checked on every operation, in [KeyStore.authorize].
 *  - Deleting or replacing a key is recorded with a monotonically increasing version, so a
 *    translation that names a key id resolved by an attacker cannot silently cross versions.
 *  - The whole key table carries an HMAC over its canonical form, computed with an
 *    integrity key held outside the mutable state. This models the HSM's signed key store
 *    and lets the self-check detect out-of-band tampering with the index.
 */
class KeyStore(private val integrityKey: ByteArray) {

    private val keys = LinkedHashMap<String, HsmKey>()
    private var version = 0L

    @Synchronized
    fun version(): Long = version

    @Synchronized
    fun all(): Collection<HsmKey> = keys.values.toList()

    @Synchronized
    fun get(id: String): HsmKey = keys[id] ?: throw HsmException(ErrorCode.NOT_FOUND, "unknown key $id")

    @Synchronized
    fun find(id: String): HsmKey? = keys[id]

    @Synchronized
    fun create(
        id: String,
        usage: KeyUsage,
        owner: String,
        keyBytes: ByteArray = RandomBytes.get(defaultKeyLen(usage)),
        family: CipherFamily = BlockCipher.familyOf(keyBytes.size)
    ): HsmKey {
        require(id.matches(Regex("[A-Za-z0-9_.:-]{1,64}"))) { "bad key id" }
        if (keys.containsKey(id)) throw HsmException(ErrorCode.POLICY_DENIED, "key id exists")
        require(BlockCipher.familyOf(keyBytes.size) == family) { "key length does not match family" }
        require(family != CipherFamily.DES || usage != KeyUsage.CVV) { "CVV keys must be at least 2-key 3DES" }
        require(usage != KeyUsage.PIN_VERIFICATION || keyBytes.size == 8 || keyBytes.size == 16) { "PVK must be DES or 2-key 3DES" }
        val kcv = computeKcv(family, keyBytes)
        val key = HsmKey(id, usage, family, keyBytes.copyOf(), kcv, owner)
        keys[id] = key
        version++
        return key
    }

    @Synchronized
    fun delete(id: String) {
        if (keys.remove(id) == null) throw HsmException(ErrorCode.NOT_FOUND, "unknown key $id")
        version++
    }

    @Synchronized
    fun rotate(id: String): HsmKey {
        val old = get(id)
        delete(id)
        return create("$id-${version}", old.usage, old.owner, RandomBytes.get(old.lengthBytes), old.family)
    }

    /**
     * Authorises an operation. Denials are deliberately indistinguishable from "unknown key"
     * to the caller so that key-usage probing reveals nothing.
     */
    fun authorize(key: HsmKey, usage: KeyUsage) {
        if (key.usage != usage) throw HsmException(ErrorCode.KEY_USAGE_VIOLATION, "usage mismatch")
    }

    /** HMAC over key metadata plus a digest of key material, so tampering is detectable. */
    @Synchronized
    fun integrityTag(): String {
        val canonical = buildString {
            append("v=").append(version).append(';')
            for (k in keys.values.sortedBy { it.id }) {
                append(k.id).append(',').append(k.usage).append(',').append(k.family).append(',')
                append(k.owner).append(',').append(k.kcv).append(',')
                append(Hashing.sha256Hex(k.bytes)).append(';')
            }
        }
        return Hashing.hmacSha256Hex(integrityKey, canonical)
    }

    @Synchronized
    fun selfCheck(expectedTag: String): Boolean = ConstantTime.equals(integrityTag(), expectedTag)

    companion object {
        fun defaultKeyLen(usage: KeyUsage): Int = when (usage) {
            KeyUsage.PIN_VERIFICATION -> 8
            KeyUsage.TERMINAL_BINDING -> 16
            KeyUsage.CVV -> 16
            else -> 16
        }

        fun computeKcv(family: CipherFamily, keyBytes: ByteArray): String {
            val zero = ByteArray(if (family == CipherFamily.AES) 16 else 8)
            val enc = BlockCipher.encrypt(family, keyBytes, zero)
            return Hex.encode(enc).take(6)
        }

        fun parseHexMaterial(hex: String): ByteArray = Hex.decode(hex)
    }
}
