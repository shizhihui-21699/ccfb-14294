package ccfb.hsm.model

/**
 * PIN block formats supported by the simulator.
 *
 * `boundToPan` records whether the format cryptographically binds the PIN to the card
 * number. Formats 1 and 2 do not; that difference drives several policy rules in
 * [ccfb.hsm.core.Hsm] and is the root of the "format conversion" attack class.
 */
enum class PinFormat(val id: Int, val hexLen: Int, val boundToPan: Boolean, val ciphertextBytes: Int) {
    ISO_0(0, 16, true, 8),
    ISO_1(1, 16, false, 8),
    ISO_2(2, 16, false, 8),
    ISO_3(3, 16, true, 8),
    ISO_4(4, 32, true, 16);

    companion object {
        fun parse(s: String?): PinFormat? {
            if (s == null) return null
            val t = s.trim().uppercase()
            return entries.firstOrNull {
                it.name == t || it.name.replace("_", "") == t.replace("_", "") || it.id.toString() == t
            }
        }
    }
}

/**
 * What a key is allowed to do. Usage separation is enforced inside [ccfb.hsm.core.KeyStore].
 */
enum class KeyUsage {
    /** Zone PIN key: translates between zones, never verifies a PIN. */
    PIN_ENCRYPTION,

    /** Terminal PIN key: encrypts blocks produced by an approved PIN pad. */
    TERMINAL_PIN,

    /** PIN verification key (PVK/offset key). Can never encrypt or translate a block. */
    PIN_VERIFICATION,

    /** Card verification value key. */
    CVV,

    /** Key used only to authenticate PIN-pad binding assertions. Never usable for blocks. */
    TERMINAL_BINDING
}

enum class Role { TERMINAL, ACQUIRER, ISSUER, AUDITOR, SECURITY_OFFICER }

/** Cipher family required by a key. ISO-4 is AES; formats 0-3 are DES/3DES. */
enum class CipherFamily { DES, TDES, AES }

enum class CardState { PROVISIONING, ACTIVE, BLOCKED }

enum class VerifyMethod { VISA_PVV, IBM_3624_OFFSET }

/**
 * A verification profile holds every parameter that determines how a PIN is checked.
 *
 * The profile is never taken from a request. It is looked up from the card record and its
 * integrity tag is re-verified before use, so an insider cannot swap the decimalization
 * table, the PVKI, or the key id by editing a request.
 */
data class ValidationProfile(
    val id: String,
    val method: VerifyMethod,
    val verificationKeyId: String,
    /** PVKI (0-9). Issuer-assigned; a request can never override it. */
    val pvki: Int = 0,
    /** 16 digits mapping hex 0-F to a decimal digit (IBM 3624 only). */
    val decimalizationTable: String = "0123456789012345",
    /** Padding character used when the PAN is shorter than 16 digits (IBM 3624). */
    val panPadChar: Char = '0',
    /** Formats the verifier will accept for this card. ISO-2 is never accepted online. */
    val acceptedFormats: Set<PinFormat> = setOf(PinFormat.ISO_0, PinFormat.ISO_1, PinFormat.ISO_3, PinFormat.ISO_4),
    val minPinLength: Int = 4,
    val maxPinLength: Int = 12,
    val maxTries: Int = 3,
    val lockoutSeconds: Long = 900,
    val translationsPerHour: Int = 60
) {
    fun validate(): ValidationProfile {
        require(id.matches(Regex("[A-Za-z0-9_.-]{1,64}"))) { "bad profile id" }
        require(method == VerifyMethod.VISA_PVV || decimalizationTable.length == 16) { "bad table" }
        require(method == VerifyMethod.VISA_PVV || decimalizationTable.all { it in '0'..'9' }) { "bad table" }
        require(pvki in 0..9) { "bad pvki" }
        require(minPinLength in 4..12 && maxPinLength in minPinLength..12) { "bad pin length range" }
        require(PinFormat.ISO_2 !in acceptedFormats) { "ISO-2 is offline only and must not be accepted online" }
        require(maxTries in 1..10) { "bad maxTries" }
        return this
    }

    /** Deterministic serialisation used for the profile integrity tag. */
    fun canonical(): String = listOf(
        id, method.name, verificationKeyId, pvki.toString(), decimalizationTable,
        panPadChar.toString(), acceptedFormats.map { it.name }.sorted().joinToString(","),
        minPinLength.toString(), maxPinLength.toString(), maxTries.toString(),
        lockoutSeconds.toString(), translationsPerHour.toString()
    ).joinToString("|")
}

data class Card(
    val accountId: String,
    val pan: String,
    val panSequence: String = "00",
    val profileId: String,
    val pvv: String? = null,
    val offset: String? = null,
    val cvv: String? = null,
    val expiry: String = "0000",
    val serviceCode: String = "000",
    val state: CardState = CardState.ACTIVE
) {
    init {
        require(pan.length in 12..19 && pan.all { it in '0'..'9' }) { "invalid PAN" }
    }

    /** Never log the PAN; log a stable token instead. */
    fun token(): String = ccfb.hsm.crypto.Hashing.sha256Hex("pan:$pan").take(16)

    fun maskedPan(): String = if (pan.length <= 4) "****" else "****" + pan.takeLast(4)
}

/** A provisioned client of the service. Secrets are compared in constant time. */
data class Client(
    val id: String,
    val secret: ByteArray,
    val role: Role,
    /** Key ids this client may name in a request. */
    val allowedKeyIds: Set<String> = emptySet(),
    /** Key-pair allow list: source key -> destination keys. */
    val allowedTransfers: Map<String, Set<String>> = emptyMap(),
    /** If set, the client is a PIN-pad-bearing terminal and may assert unbound-format bindings. */
    val bindingKeyId: String? = null,
    val verifyPerSecond: Double = 5.0,
    val verifyBurst: Int = 10,
    val translatePerSecond: Double = 5.0,
    val translateBurst: Int = 10
) {
    override fun equals(other: Any?): Boolean = other is Client && other.id == id
    override fun hashCode(): Int = id.hashCode()
    override fun toString(): String = "Client($id,$role)"
}
