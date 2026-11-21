package ccfb.hsm.api

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.fasterxml.jackson.module.kotlin.readValue

/**
 * Strict JSON codec for the wire.
 *
 * `FAIL_ON_UNKNOWN_PROPERTIES` is a security control, not a convenience: a request that
 * carries `decimalizationTable`, `pvki` or `pan` fields is rejected outright instead of
 * having them silently ignored (which would make an "ignored" field look effective in logs)
 * or silently honoured (the actual attack).
 */
object Wire {
    val mapper: ObjectMapper = ObjectMapper()
        .registerModule(KotlinModule.Builder().build())
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
        .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
        .setSerializationInclusion(JsonInclude.Include.NON_NULL)

    fun toJson(v: Any): String = mapper.writeValueAsString(v)
    fun toBytes(v: Any): ByteArray = mapper.writeValueAsBytes(v)
    inline fun <reified T : Any> fromJson(s: String): T = mapper.readValue(s)
    inline fun <reified T : Any> fromBytes(b: ByteArray): T = mapper.readValue(b)
}

/** Signed by the terminal's binding key; asserts "this card is in this terminal right now". */
data class TerminalAssertion(
    val terminalId: String,
    val sessionId: String,
    val expiresAtMs: Long,
    val mac: String
)

data class BeginSessionRequest(
    val requestId: String,
    val accountId: String,
    val terminalKeyId: String
)

data class PinPadRequest(
    val requestId: String,
    val accountId: String,
    val pin: String,
    val format: String,
    val terminalKeyId: String,
    val sessionId: String
)

data class TranslateRequest(
    val requestId: String,
    val accountId: String,
    val routeId: String,
    val pinBlock: String,
    /** Must equal the route's source format; present so a mislabelled block is rejected. */
    val format: String,
    val terminalAssertion: TerminalAssertion? = null
)

data class VerifyPinRequest(
    val requestId: String,
    val accountId: String,
    /** Key the submitted block is encrypted under (usage PIN_ENCRYPTION). */
    val keyId: String,
    val pinBlock: String,
    val format: String,
    val terminalAssertion: TerminalAssertion? = null
)

data class SetPinRequest(
    val requestId: String,
    val accountId: String,
    val newPin: String
)

data class UnlockRequest(
    val requestId: String,
    val accountId: String,
    /** Free-text reason recorded in the audit log; never interpreted by the HSM. */
    val reason: String
)

data class IssuePvvRequest(
    val requestId: String,
    val accountId: String,
    /** Second-person approval ticket minted by a SECURITY_OFFICER. */
    val approvalTicket: String
)

data class ApproveRequest(
    val requestId: String,
    val accountId: String,
    /** Operation being approved: currently only ISSUE_PVV. */
    val operation: String
)

data class VerifyCvvRequest(
    val requestId: String,
    val accountId: String,
    val cvv: String
)

data class TranslateResponse(
    val requestId: String,
    val pinBlock: String,
    val format: String,
    val destinationKeyKcv: String
)

data class VerifyResponse(
    val requestId: String,
    val decision: String,
    val remainingAttempts: Int
)

data class SessionResponse(
    val requestId: String,
    val sessionId: String,
    val expiresAtMs: Long,
    val bindingMac: String
)

data class PinPadResponse(val requestId: String, val pinBlock: String, val format: String)

data class PvvResponse(val requestId: String, val pvv: String)

data class ApprovalResponse(val requestId: String, val ticket: String, val expiresAtMs: Long)

data class KeyInfo(val id: String, val usage: String, val algorithm: String, val kcv: String, val owner: String)

data class StatusResponse(
    val requestId: String,
    val keyStoreIntegrity: Boolean,
    val profileIntegrity: Boolean,
    val auditChain: Boolean,
    val auditEntries: Int,
    val keys: List<KeyInfo>
)

data class ErrorResponse(val requestId: String?, val code: String, val message: String)

data class AuditEntryView(
    val seq: Long,
    val at: Long,
    val requestId: String,
    val clientId: String,
    val operation: String,
    val accountToken: String?,
    val keyIds: List<String>,
    val formats: List<String>,
    val decision: String,
    val reason: String,
    val bodyDigest: String,
    val hash: String
)

/** A signed envelope travels beside the body; the body bytes are what the MAC covers. */
data class SignedEnvelope(
    val clientId: String,
    val timestampMs: Long,
    val nonce: String,
    val bodySha256: String,
    val mac: String
)

data class SignedCall(val envelope: SignedEnvelope, val body: String)
