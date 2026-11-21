package ccfb.hsm.model

/**
 * Public error taxonomy.
 *
 * Two rules matter for security and are documented on every response:
 *  1. [publicMessage] never contains card data, key material, offsets, PVVs or any
 *     information derived from a decrypted PIN block.
 *  2. Every failure that depends on the *content* of a decrypted PIN block collapses to
 *     [PIN_BLOCK_INVALID] (translation) or a plain `DECLINE` (verification). Distinct
 *     messages for "wrong length", "bad fill nibble" or "PAN mismatch" would hand an
 *     attacker a plaintext oracle.
 */
enum class ErrorCode(val http: Int, val publicMessage: String) {
    INVALID_REQUEST(400, "request rejected"),
    UNKNOWN_FIELD(400, "request rejected"),
    UNAUTHENTICATED(401, "authentication failed"),
    FORBIDDEN(403, "operation not permitted"),
    POLICY_DENIED(403, "operation not permitted"),
    KEY_USAGE_VIOLATION(403, "operation not permitted"),
    NOT_FOUND(404, "resource not found"),
    REPLAY_DETECTED(409, "request rejected"),
    TIMESTAMP_INVALID(401, "authentication failed"),
    CARD_LOCKED(423, "card locked"),
    RATE_LIMITED(429, "rate limit exceeded"),
    PIN_BLOCK_INVALID(400, "pin block rejected"),
    INTERNAL(500, "internal error")
}

class HsmException(
    val code: ErrorCode,
    /** Internal diagnostic only. Must never be serialised to a client. */
    internalDetail: String? = null
) : RuntimeException(internalDetail ?: code.publicMessage)
