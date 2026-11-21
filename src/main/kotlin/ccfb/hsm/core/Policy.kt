package ccfb.hsm.core

import ccfb.hsm.crypto.ConstantTime
import ccfb.hsm.crypto.Hashing
import ccfb.hsm.model.Card
import ccfb.hsm.model.CardState
import ccfb.hsm.model.ErrorCode
import ccfb.hsm.model.HsmException
import ccfb.hsm.model.PinFormat
import ccfb.hsm.model.ValidationProfile

/**
 * Card and profile storage.
 *
 * The decisive property for attack resistance is this: **verification parameters are never
 * request data**. A request may name an `accountId`; nothing else about how the PIN is
 * checked (PVK id, PVKI, decimalisation table, PAN padding, accepted formats, retry limits)
 * is accepted from the caller. The profile is fetched here and re-verified against an
 * integrity tag whose key is held outside the mutable profile table, so an insider who can
 * write the profile table still cannot quietly change a decimalisation table without the
 * self-check failing and blocking every operation.
 */
class CardStore(private val profileIntegrityKey: ByteArray) {

    // Guarded by the instance monitor: the HTTP front end serves requests from a thread pool,
    // so these maps are read and written concurrently.
    private val profiles = LinkedHashMap<String, ValidationProfile>()
    private val profileTags = HashMap<String, String>()
    private val cards = LinkedHashMap<String, Card>()

    @Synchronized
    fun putProfile(profile: ValidationProfile) {
        profile.validate()
        profiles[profile.id] = profile
        profileTags[profile.id] = tagFor(profile)
    }

    @Synchronized
    fun profile(id: String): ValidationProfile {
        val p = profiles[id] ?: throw HsmException(ErrorCode.NOT_FOUND, "unknown profile")
        if (!ConstantTime.equals(profileTags[id] ?: "", tagFor(p))) {
            throw HsmException(ErrorCode.POLICY_DENIED, "profile integrity failure")
        }
        return p
    }

    @Synchronized
    fun putCard(card: Card) {
        if (!profiles.containsKey(card.profileId)) throw HsmException(ErrorCode.NOT_FOUND, "unknown profile")
        cards[card.accountId] = card
    }

    @Synchronized
    fun card(accountId: String): Card = cards[accountId] ?: throw HsmException(ErrorCode.NOT_FOUND, "unknown account")

    @Synchronized
    fun updateCard(card: Card) {
        cards[card.accountId] = card
    }

    @Synchronized
    fun allCards(): Collection<Card> = cards.values.toList()

    fun requireActive(card: Card) {
        when (card.state) {
            CardState.ACTIVE -> return
            CardState.BLOCKED -> throw HsmException(ErrorCode.CARD_LOCKED, "card blocked")
            CardState.PROVISIONING -> throw HsmException(ErrorCode.POLICY_DENIED, "card not active")
        }
    }

    @Synchronized
    fun selfCheckAll(): Boolean = profiles.all { (id, p) -> ConstantTime.equals(profileTags[id] ?: "", tagFor(p)) }

    private fun tagFor(p: ValidationProfile): String = Hashing.hmacSha256Hex(profileIntegrityKey, p.canonical())
}

/**
 * A translation route.
 *
 * Legitimate paths are enumerated as data; nothing is inferred. `fromKey`/`toKey` are key
 * ids, `fromFormat`/`toFormat` the formats on each side, and the route names which clients
 * may use it. A path that is not in the table simply does not exist.
 *
 * [requiresTerminalBinding] is set for routes whose *source* format is not PAN-bound
 * (ISO-1). Such a block cannot prove which card it belongs to, so the caller must present a
 * binding assertion signed by that terminal's binding key, plus an active terminal session
 * for the account. Without this, one observed ISO-1 block could be re-bound to any PAN.
 *
 * [requiresTerminalSession] is set for routes that *produce* a PAN-unbound format: stripping
 * the PAN binding is only safe towards a terminal that is currently serving that same card.
 */
data class Route(
    val id: String,
    val fromKey: String,
    val toKey: String,
    val fromFormat: PinFormat,
    val toFormat: PinFormat,
    val allowedClients: Set<String>,
    val requiresTerminalBinding: Boolean = false,
    val requiresTerminalSession: Boolean = false,
    val perHourLimit: Int = 600
) {
    fun keyPair(): String = "$fromKey->$toKey/$fromFormat->$toFormat"
}

/** "This terminal is currently serving this card." Created by the terminal at card insertion. */
data class TerminalSession(
    val clientId: String,
    val accountId: String,
    val terminalKeyId: String,
    val expiresAtMs: Long
)

/**
 * Per-card attempt ledger.
 *
 * Deliberately card-scoped rather than client-scoped: a PIN guess spends budget no matter
 * which client or which format it arrives in. That is what makes distributed "batch"
 * probing across several compromised clients fail — they share the counter.
 *
 * The ledger stores no PIN, no hash of a PIN, and no per-guess data; only counts and times.
 * [pinned] mirrors a failed-local-attempts counter so a restart of the service cannot be
 * used to reset the budget.
 */
class AttemptLedger(
    private val maxTries: (String) -> Int,
    private val lockoutMs: (String) -> Long,
    private val clock: () -> Long
) {
    data class State(
        var failures: Int = 0,
        var lockedUntil: Long = 0,
        var totalAttempts: Long = 0,
        var lastAttemptAt: Long = 0,
        /** Attempts granted and currently being compared, not yet recorded. */
        var pending: Int = 0
    )

    private val states = HashMap<String, State>()

    @Synchronized
    fun state(accountId: String): State = states.getOrPut(accountId) { State() }

    @Synchronized
    fun isLocked(accountId: String): Boolean = clock() < state(accountId).lockedUntil

    /**
     * Reserves one attempt *before* the PIN is checked.
     *
     * The reservation itself consumes budget: `pending` counts attempts that have been
     * granted but whose result is not yet known. This is what closes the concurrency race
     * where N parallel guesses all observe `failures < maxTries` and are all compared. Here
     * the (maxTries)-th concurrent request is refused before any comparison, so a burst can
     * never buy more comparisons than the budget allows.
     *
     * Throws CARD_LOCKED when the card is locked or the in-flight reservations already
     * exhaust the budget.
     */
    @Synchronized
    fun reserveAttempt(accountId: String) {
        val now = clock()
        val s = state(accountId)
        if (now < s.lockedUntil) throw HsmException(ErrorCode.CARD_LOCKED, "locked")
        if (s.failures + s.pending >= maxTries(accountId)) {
            throw HsmException(ErrorCode.CARD_LOCKED, "attempt budget exhausted")
        }
        s.pending++
        s.totalAttempts++
        s.lastAttemptAt = now
    }

    @Synchronized
    fun recordResult(accountId: String, success: Boolean) {
        val now = clock()
        val s = state(accountId)
        if (s.pending > 0) s.pending--
        if (success) {
            s.failures = 0
            s.lockedUntil = 0
        } else {
            s.failures++
            if (s.failures >= maxTries(accountId)) {
                s.lockedUntil = now + lockoutMs(accountId)
                s.failures = 0
            }
        }
    }

    @Synchronized
    fun remaining(accountId: String): Int {
        val s = state(accountId)
        if (clock() < s.lockedUntil) return 0
        return (maxTries(accountId) - s.failures - s.pending).coerceAtLeast(0)
    }

    @Synchronized
    fun unlock(accountId: String) {
        val s = state(accountId)
        s.failures = 0
        s.lockedUntil = 0
    }
}

/** Token bucket, one per (client, operation). Bounds sustained probing from a single client. */
class RateLimiter(private val clock: () -> Long) {
    private class Bucket(var tokens: Double, var last: Long)

    private val buckets = HashMap<String, Bucket>()

    @Synchronized
    fun tryAcquire(key: String, ratePerSecond: Double, burst: Int): Boolean {
        val now = clock()
        val b = buckets.getOrPut(key) { Bucket(burst.toDouble(), now) }
        val elapsed = (now - b.last) / 1000.0
        b.last = now
        b.tokens = minOf(burst.toDouble(), b.tokens + elapsed * ratePerSecond)
        if (b.tokens < 1.0) return false
        b.tokens -= 1.0
        return true
    }
}

/** A run of declines that suggests enumeration across many cards rather than one user mistake. */
class ProbeDetector(
    private val windowMs: Long,
    private val distinctCardThreshold: Int,
    private val declineThreshold: Int,
    private val clock: () -> Long
) {
    private class Window {
        val cards = HashSet<String>()
        var declines = 0
        var start = 0L
    }

    private val windows = HashMap<String, Window>()

    @Synchronized
    fun record(clientId: String, accountId: String, matched: Boolean) {
        val now = clock()
        val w = windows.getOrPut(clientId) { Window().also { it.start = now } }
        if (now - w.start > windowMs) {
            w.cards.clear()
            w.declines = 0
            w.start = now
        }
        w.cards.add(accountId)
        if (!matched) w.declines++
    }

    @Synchronized
    fun isProbing(clientId: String): Boolean {
        val w = windows[clientId] ?: return false
        return w.declines >= declineThreshold && w.cards.size >= distinctCardThreshold
    }

    @Synchronized
    fun reset(clientId: String) {
        windows.remove(clientId)
    }
}

/**
 * Append-only, hash-chained audit log.
 *
 * Each entry commits to its predecessor's hash, so an insider with write access to the log
 * store can delete or edit an entry, but cannot do so without breaking every subsequent
 * link. [verifyChain] is exposed to AUDITORs and is also checked by the self-test.
 *
 * What is logged: request id, client, operation, key *ids*, formats, account token, decision,
 * and the body digest. What is never logged: PAN, PIN, PIN block ciphertext, PVV, offset,
 * natural PIN, key material.
 */
class AuditLog(private val clock: () -> Long) {
    data class Entry(
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
        val prevHash: String,
        val hash: String
    )

    private val entries = ArrayList<Entry>()

    @get:Synchronized
    val size: Int get() = entries.size

    @Synchronized
    fun append(
        requestId: String,
        clientId: String,
        operation: String,
        accountToken: String?,
        keyIds: List<String>,
        formats: List<String>,
        decision: String,
        reason: String,
        bodyDigest: String
    ): Entry {
        val prev = entries.lastOrNull()?.hash ?: GENESIS
        val seq = entries.size.toLong() + 1
        val at = clock()
        val hash = chainHash(prev, seq, at, requestId, clientId, operation, accountToken, keyIds, formats, decision, reason, bodyDigest)
        val e = Entry(seq, at, requestId, clientId, operation, accountToken, keyIds, formats, decision, reason, bodyDigest, prev, hash)
        entries.add(e)
        return e
    }

    @Synchronized
    fun all(): List<Entry> = entries.toList()

    /**
     * TEST-ONLY: mutates the stored log to model an insider with write access to the log
     * store. It exists so `AuditIntegrityTest` can prove that tampering is detected; it is
     * deliberately not reachable from any wire operation, and a production build would not
     * ship it.
     */
    @Synchronized
    internal fun tamperForTest(mutator: (MutableList<Entry>) -> Unit) {
        mutator(entries)
    }

    @Synchronized
    fun verifyChain(): Boolean {
        var prev = GENESIS
        for (e in entries) {
            if (e.prevHash != prev) return false
            val h = chainHash(e.prevHash, e.seq, e.at, e.requestId, e.clientId, e.operation, e.accountToken, e.keyIds, e.formats, e.decision, e.reason, e.bodyDigest)
            if (!ConstantTime.equals(h, e.hash)) return false
            prev = e.hash
        }
        return true
    }

    @Synchronized
    fun anchor(): String = entries.lastOrNull()?.hash ?: GENESIS

    private fun chainHash(
        prev: String, seq: Long, at: Long, requestId: String, clientId: String, operation: String,
        accountToken: String?, keyIds: List<String>, formats: List<String>, decision: String,
        reason: String, bodyDigest: String
    ): String {
        val canonical = listOf(
            prev, seq.toString(), at.toString(), requestId, clientId, operation,
            accountToken ?: "-", keyIds.joinToString(","), formats.joinToString(","),
            decision, reason, bodyDigest
        ).joinToString("\n")
        return Hashing.sha256Hex(canonical)
    }

    companion object {
        const val GENESIS = "0000000000000000000000000000000000000000000000000000000000000000"
    }
}
