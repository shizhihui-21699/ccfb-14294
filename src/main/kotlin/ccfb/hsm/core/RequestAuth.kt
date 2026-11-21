package ccfb.hsm.core

import ccfb.hsm.crypto.Hashing
import ccfb.hsm.model.ErrorCode
import ccfb.hsm.model.HsmException

/**
 * Request authentication.
 *
 * Every mutating or secret-touching call carries:
 *
 *   clientId, timestampMs, nonce, bodySha256, mac
 *
 * where
 *
 *   mac = HMAC-SHA256(clientSecret, canonical(method, path, timestampMs, nonce, bodySha256))
 *
 * Properties this buys us, and which the attack suite exercises:
 *
 *  - An insider cannot hand-craft a translation request "off the record": without the
 *    client secret they cannot produce `mac`, and every accepted request is force-logged
 *    with its body hash, so a request that never appears in the audit log has no valid MAC.
 *  - [bodySha256] binds the MAC to the exact JSON body, so a parameter (PVKI, decimalisation
 *    table, target format, PAN) cannot be swapped in transit or between a log and a replay.
 *  - [nonce] is single-use per client, so a captured legitimate translation cannot be
 *    replayed to accumulate two different observations from one plaintext.
 *  - [timestampMs] with [MAX_SKEW_MS] bounds the window in which a stolen request is useful.
 */
object RequestAuth {

    const val MAX_SKEW_MS = 30_000L

    data class Envelope(
        val clientId: String,
        val timestampMs: Long,
        val nonce: String,
        val bodySha256: String,
        val mac: String
    )

    fun canonical(method: String, path: String, timestampMs: Long, nonce: String, bodySha256: String): String =
        listOf(method.uppercase(), path, timestampMs.toString(), nonce, bodySha256).joinToString("\n")

    fun sign(secret: ByteArray, method: String, path: String, timestampMs: Long, nonce: String, body: ByteArray): String {
        val bodyHash = Hashing.sha256Hex(body)
        return Hashing.hmacSha256Hex(secret, canonical(method, path, timestampMs, nonce, bodyHash))
    }

    fun digestBody(body: ByteArray): String = Hashing.sha256Hex(body)

    /** Full verification; throws a uniform UNAUTHENTICATED on any failure. */
    fun verify(
        secret: ByteArray,
        envelope: Envelope,
        method: String,
        path: String,
        body: ByteArray,
        nowMs: Long,
        nonceStore: NonceStore
    ) {
        val bodyHash = Hashing.sha256Hex(body)
        if (!ccfb.hsm.crypto.ConstantTime.equals(bodyHash, envelope.bodySha256)) {
            throw HsmException(ErrorCode.UNAUTHENTICATED, "body digest mismatch")
        }
        if (kotlin.math.abs(nowMs - envelope.timestampMs) > MAX_SKEW_MS) {
            throw HsmException(ErrorCode.TIMESTAMP_INVALID, "clock skew")
        }
        val expected = Hashing.hmacSha256Hex(
            secret,
            canonical(method, path, envelope.timestampMs, envelope.nonce, envelope.bodySha256)
        )
        if (!ccfb.hsm.crypto.ConstantTime.equals(expected, envelope.mac)) {
            throw HsmException(ErrorCode.UNAUTHENTICATED, "mac mismatch")
        }
        // Only burn the nonce after the MAC checks out, else unauthenticated traffic could
        // exhaust an honest client's nonce space.
        if (!nonceStore.claim(envelope.clientId, envelope.nonce, envelope.timestampMs)) {
            throw HsmException(ErrorCode.REPLAY_DETECTED, "nonce reuse")
        }
    }
}

/**
 * Single-use nonce registry.
 *
 * Entries expire after `MAX_SKEW_MS * 2`, at which point the timestamp check would reject the
 * request anyway, so expiry is safe.
 *
 * Two details matter for security rather than tidiness:
 *
 *  - Expiry is measured against the **server** clock at claim time, not the client-supplied
 *    timestamp. Using the client's value would let an attacker choose a timestamp near the
 *    edge of the skew window and keep an entry alive for nearly twice as long.
 *  - The store is **per-client bounded and fails closed per client**. A single global
 *    capacity with LRU eviction would let one authenticated client flood the cache, evict a
 *    legitimate client's nonce, and then replay that request. Hitting one's own cap is
 *    treated as flooding, not as grounds to forget someone else's entry.
 */
class NonceStore(
    private val perClientCapacity: Int = 20_000,
    private val clock: () -> Long = System::currentTimeMillis
) {
    private class ClientNonces {
        /** nonce -> server time of claim. Insertion order is claim order. */
        val entries = LinkedHashMap<String, Long>(256, 0.75f, false)
    }

    private val clients = HashMap<String, ClientNonces>()

    @Synchronized
    fun claim(clientId: String, nonce: String, timestampMs: Long): Boolean {
        if (!nonce.matches(Regex("[A-Za-z0-9_-]{8,64}"))) return false
        val now = clock()
        val expiry = RequestAuth.MAX_SKEW_MS * 2
        val bucket = clients.getOrPut(clientId) { ClientNonces() }

        // Lazy expiry: drop entries that are no longer replayable anyway.
        val it = bucket.entries.entries.iterator()
        while (it.hasNext()) {
            if (now - it.next().value > expiry) it.remove() else break
        }
        if (bucket.entries.containsKey(nonce)) return false
        // Fail closed for this client rather than evicting (possibly another client's) entry.
        if (bucket.entries.size >= perClientCapacity) return false
        bucket.entries[nonce] = now
        return true
    }

    @Synchronized
    fun size(): Int = clients.values.sumOf { it.entries.size }
}
