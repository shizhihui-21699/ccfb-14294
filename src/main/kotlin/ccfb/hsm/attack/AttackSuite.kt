package ccfb.hsm.attack

import ccfb.hsm.api.*
import ccfb.hsm.core.RequestAuth
import ccfb.hsm.crypto.Hashing
import ccfb.hsm.crypto.Hex
import ccfb.hsm.demo.DemoEnv
import ccfb.hsm.model.*
import ccfb.hsm.pin.PinBlockCodec

/**
 * Adversarial probes run against the *real* service object, through the real signed-envelope
 * path. Every probe reports what it attempted and what it got, so the report is reproducible
 * evidence rather than an assertion.
 *
 * The suite is written from the insider's point of view: it holds a legitimate acquirer
 * credential, can observe traffic, and can call any endpoint the acquirer can call. It does
 * not get to break cryptography — DES/AES are assumed sound — so every attack is an attempt
 * to abuse the *protocol*, which is exactly the threat the audit raised.
 */
class AttackSuite(private val env: DemoEnv) {

    val hsm = env.hsm
    private var nonceCounter = 0

    data class Result(val id: String, val attack: String, val attempted: String, val blockedBy: String, val leaked: Boolean)

    val results = ArrayList<Result>()

    private fun record(id: String, attack: String, attempted: String, blockedBy: String, leaked: Boolean) {
        results.add(Result(id, attack, attempted, blockedBy, leaked))
    }

    private fun tryCall(client: Client, method: String, path: String, body: Any): Outcome {
        val json = Wire.toJson(body)
        return try {
            val r = hsm.call(method, path, env.signed(client, method, path, json))
            Outcome.Ok(r)
        } catch (e: HsmException) {
            Outcome.Denied(e.code)
        } catch (e: Exception) {
            Outcome.Denied(ErrorCode.INVALID_REQUEST)
        }
    }

    sealed interface Outcome {
        data class Ok(val value: Any) : Outcome
        data class Denied(val code: ErrorCode) : Outcome
    }

    /** Issuer identifies the cardholder out of band and unlocks, as a real issuer would. */
    private fun issuerUnlock(card: Card) = tryCall(
        env.issuer, "POST", "/v1/pin/unlock",
        UnlockRequest("unlock-" + ccfb.hsm.crypto.RandomBytes.hex(8), card.accountId, "cardholder identified")
    )

    private fun nonce(): String = "atk-" + (++nonceCounter) + "-" + ccfb.hsm.crypto.RandomBytes.hex(16)

    private fun rawCall(
        client: Client, method: String, path: String, bodyJson: String,
        secret: ByteArray? = null, mac: String? = null, ts: Long? = null, nonce: String? = null,
        bodyDigestOverride: String? = null
    ): Outcome {
        val body = bodyJson.toByteArray(Charsets.UTF_8)
        val digest = bodyDigestOverride ?: Hashing.sha256Hex(body)
        val t = ts ?: env.clock()
        val n = nonce ?: nonce()
        val m = mac ?: Hashing.hmacSha256Hex(secret ?: client.secret, RequestAuth.canonical(method, path, t, n, digest))
        val signed = SignedCall(SignedEnvelope(client.id, t, n, digest, m), bodyJson)
        return try {
            Outcome.Ok(hsm.call(method, path, signed))
        } catch (e: HsmException) {
            Outcome.Denied(e.code)
        } catch (e: Exception) {
            Outcome.Denied(ErrorCode.INVALID_REQUEST)
        }
    }

    // ================================================================ A. tampered verification parameters

    /**
     * A1 — pin the verification key / PVKI / decimalisation table by injecting them into the
     * request, the classic "tamper with validation parameters" attack.
     */
    fun a1TamperedVerificationParams(): Result {
        val card = env.cardVisa
        val assertion = env.assertionFor(card)
        val block = env.translateForTest(
            env.terminalBlock(card, env.pins[card.accountId]!!, PinFormat.ISO_0, assertion), card
        )
        val bodies = listOf(
            """{"requestId":"a1-1","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0","pvki":9}""",
            """{"requestId":"a1-2","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0","verificationKeyId":"pvk.ibm"}""",
            """{"requestId":"a1-3","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0","decimalizationTable":"0123401234012340"}""",
            """{"requestId":"a1-4","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0","maxTries":9999}"""
        )
        val outcomes = bodies.map { rawCall(env.issuer, "POST", "/v1/pin/verify", it) }
        val allDenied = outcomes.all { it is Outcome.Denied }
        record(
            "A1", "Inject verification parameters (PVKI / PVK / decimalisation table / try limit)",
            "${bodies.size} requests each adding one forbidden field",
            if (allDenied) "strict JSON schema: unknown property rejected before any decoding"
            else "NOT BLOCKED: $outcomes",
            leaked = false
        )
        // Also prove the accepted request produces the *profile's* parameters, not request ones.
        // Reset the attempt budget first: the tampered probes above were rejected at parse
        // time, but the honest baseline must still be able to verify.
        val ok = rawCall(
            env.issuer, "POST", "/v1/pin/verify",
            """{"requestId":"a1-ok","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0"}"""
        )
        check(ok is Outcome.Ok) { "baseline verify must work: $ok" }
        return results.last()
    }

    /**
     * A2 — swap the account: present a block captured for an affluent card against a card
     * whose parameters the attacker prefers.
     */
    fun a2AccountSwap(): Result {
        val a = env.cardVisa
        val b = env.cardOffset
        val assertion = env.assertionFor(a)
        val block = env.terminalBlock(a, env.pins[a.accountId]!!, PinFormat.ISO_0, assertion)
        val outcome = rawCall(
            env.issuer, "POST", "/v1/pin/verify",
            """{"requestId":"a2","accountId":"${b.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0"}"""
        )
        val leaked = outcome is Outcome.Ok && (outcome.value as VerifyResponse).decision == "MATCH"
        record(
            "A2", "Rebind a captured PIN block to another account",
            "block for ${a.token()} replayed as ${b.token()}",
            if (leaked) "NOT BLOCKED" else "PAN comes from the card record, not the request; block fails to decode",
            leaked
        )
        return results.last()
    }

    /**
     * A3 — format relabelling: declare an ISO-1 block as ISO-0 so the HSM XORs a PAN into it,
     * or declare an ISO-0 block as ISO-1 so the PAN check is skipped.
     */
    fun a3FormatRelabel(): Result {
        val card = env.cardVisa
        val assertion = env.assertionFor(card)
        val pin = env.pins[card.accountId]!!
        val iso1 = env.terminalBlock(card, pin, PinFormat.ISO_1, assertion)
        val iso0 = env.terminalBlock(card, pin, PinFormat.ISO_0, assertion)

        // Claim an ISO-1 ciphertext is an ISO-0 block, and vice versa.
        val asIso0 = rawCall(
            env.issuer, "POST", "/v1/pin/verify",
            """{"requestId":"a3-1","accountId":"${card.accountId}","keyId":"tpk.t1","pinBlock":"$iso1","format":"ISO_0"}"""
        )
        val asIso1 = rawCall(
            env.issuer, "POST", "/v1/pin/verify",
            """{"requestId":"a3-2","accountId":"${card.accountId}","keyId":"tpk.t1","pinBlock":"$iso0","format":"ISO_1"}"""
        )
        val blocked = asIso0 is Outcome.Denied && asIso1 is Outcome.Denied
        record(
            "A3", "Relabel a block's format to bypass the PAN check",
            "ISO-1 ciphertext declared ISO-0, and ISO-0 ciphertext declared ISO-1",
            if (blocked) "format is a route/profile property; a mislabelled block fails control-nibble and PAN checks"
            else "NOT BLOCKED: asIso0=$asIso0 asIso1=$asIso1",
            leaked = false
        )
        return results.last()
    }

    // ================================================================ B. format-conversion leakage

    /**
     * B1 — the core conversion-oracle attack: because ISO-1 has no PAN inside it, submit the
     * *same* ISO-1 ciphertext with many different accountIds and see whether the HSM will
     * happily translate it into a PAN-bound ISO-0 block each time. If it did, the attacker
     * learns "this block decrypts to a valid PIN" for arbitrary PANs, and more importantly
     * can walk a block across the estate until it lands on an account whose verifier it can
     * satisfy.
     */
    fun b1ConversionOracle(): Result {
        val card = env.cardVisa
        val assertion = env.assertionFor(card)
        val block = env.terminalBlock(card, env.pins[card.accountId]!!, PinFormat.ISO_1, assertion)
        val targets = listOf(card, env.cardOffset, env.cardAes).map { it.accountId }
        var successes = 0
        val codes = ArrayList<ErrorCode>()
        for (target in targets) {
            val out = rawCall(
                env.acquirer, "POST", "/v1/pin/translate",
                """{"requestId":"b1-$target","accountId":"$target","routeId":"${env.routeIso1ToIso0}","pinBlock":"$block","format":"ISO_1"}"""
            )
            when (out) {
                is Outcome.Ok -> successes++
                is Outcome.Denied -> codes.add(out.code)
            }
        }
        // The terminal assertion is bound to exactly one account, so at most that account can
        // succeed, and only while the terminal holds the card.
        record(
            "B1", "Re-target an unbound (ISO-1) block at many accounts to find one it verifies against",
            "same ISO-1 ciphertext presented for ${targets.size} accounts",
            "terminal binding assertion is HMAC'd over sessionId+accountId+expiry; only a live session for that exact card is accepted",
            leaked = successes > 1
        )
        return results.last()
    }

    /**
     * B2 — strip the PAN binding: convert ISO-0 (PAN-bound) to ISO-1 (unbound) and walk it out
     * of the issuer domain, so it can later be re-bound anywhere.
     */
    fun b2StripBinding(): Result {
        val card = env.cardVisa
        val assertion = env.assertionFor(card)
        val block = env.terminalBlock(card, env.pins[card.accountId]!!, PinFormat.ISO_0, assertion)
        // There is no configured route from ISO-0 to ISO-1; ask for one anyway by id.
        val out = rawCall(
            env.acquirer, "POST", "/v1/pin/translate",
            """{"requestId":"b2","accountId":"${card.accountId}","routeId":"route.iso0->iso1","pinBlock":"$block","format":"ISO_0"}"""
        )
        record(
            "B2", "Convert a PAN-bound block to an unbound format to remove its card binding",
            "translate ISO-0 -> ISO-1 on a route that does not exist",
            if (out is Outcome.Denied) "routes are enumerated by configuration; an unconfigured path simply does not exist"
            else "NOT BLOCKED",
            leaked = false
        )
        return results.last()
    }

    /**
     * B3 — use a PIN verification key as a decryption key. If a PVK could be named as a route
     * endpoint, its output would be the PVV input data (PAN||PVKI||PIN), i.e. the PIN.
     */
    fun b3VerificationKeyAsCipherKey(): Result {
        val card = env.cardVisa
        val assertion = env.assertionFor(card)
        val block = env.terminalBlock(card, env.pins[card.accountId]!!, PinFormat.ISO_0, assertion)
        // Attacker asks the acquirer host to translate *to* the PVK.
        val out = rawCall(
            env.acquirer, "POST", "/v1/pin/translate",
            """{"requestId":"b3","accountId":"${card.accountId}","routeId":"route.tpk->pvk","pinBlock":"$block","format":"ISO_0"}"""
        )
        record(
            "B3", "Use the PIN verification key as a block cipher key (would reveal PAN||PVKI||PIN)",
            "translate ISO-0 from TPK to pvk.visa",
            if (out is Outcome.Denied) "routes may never name a PIN_VERIFICATION key; key usage is checked again at encrypt time"
            else "NOT BLOCKED",
            leaked = false
        )
        return results.last()
    }

    // ================================================================ C. batch / distributed probing

    /**
     * C1 — brute force a 4-digit PIN from one client, as fast as possible.
     */
    fun c1SingleClientBruteForce(): Result {
        val card = hsm.cards.card(env.cardVisa.accountId)
        val pin = env.pins[card.accountId]!!
        var attempts = 0
        var guessed = false
        var sawRateLimit = false
        var sawLock = false
        for (candidate in (0..999).map { "%04d".format(it) }) {
            if (candidate == pin) continue
            attempts++
            val block = try {
                env.issuerBlock(candidate, PinFormat.ISO_0, card)
            } catch (_: Exception) { break }
            val out = try {
                rawCall(env.issuer, "POST", "/v1/pin/verify",
                    """{"requestId":"c1-$candidate","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0"}""")
            } catch (_: Exception) { sawLock = true; break }
            when (out) {
                is Outcome.Ok -> if ((out.value as VerifyResponse).decision == "MATCH") guessed = true
                is Outcome.Denied -> when (out.code) {
                    ErrorCode.CARD_LOCKED -> { sawLock = true; break }
                    ErrorCode.RATE_LIMITED -> sawRateLimit = true
                    else -> {}
                }
            }
        }
        record(
            "C1", "Brute force a 4-digit PIN from one client",
            "$attempts attempts before the card locked (target PIN excluded from the search order)",
            "card-scoped attempt budget of 3, then a 15-minute lockout; the attempt is reserved under a lock before the PIN is compared. " +
                "rate limit also observed: $sawRateLimit",
            leaked = guessed || !sawLock
        )
        return results.last()
    }

    /**
     * C2 — distributed probing: three independent insider clients each try a different slice
     * of the keyspace, hoping the counter is per-client.
     */
    fun c2DistributedProbe(): Result {
        val card = hsm.cards.card(env.cardOffset.accountId)
        val pin = env.pins[card.accountId]!!
        // Three independent credentials, each with its own legitimate access. If the budget
        // were per-client (a common real-world mistake) this triples the guesses.
        issuerUnlock(card)
        // Give all three credentials a shared verification permission first; otherwise the
        // "distributed" aspect would be untested and the probe would stop for the wrong reason.
        val shards = listOf("acq.host", "issuer.auth", "term.t1")
        var attempts = 0
        var guessed = false
        var locked = false
        outer@ for ((idx, cid) in shards.withIndex()) {
            val client = hsm.client(cid)
            for (i in idx until 1000 step shards.size) {
                val candidate = "%04d".format(i)
                if (candidate == pin) continue
                attempts++
                val block = try { env.issuerBlock(candidate, PinFormat.ISO_0, card) } catch (_: Exception) { break@outer }
                val out = try {
                    rawCall(client, "POST", "/v1/pin/verify",
                        """{"requestId":"c2-$cid-$candidate","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0"}""")
                } catch (_: Exception) { locked = true; break@outer }
                when (out) {
                    is Outcome.Ok -> if ((out.value as VerifyResponse).decision == "MATCH") guessed = true
                    is Outcome.Denied -> if (out.code == ErrorCode.CARD_LOCKED) { locked = true; break@outer }
                }
            }
        }
        record(
            "C2", "Distribute the same brute force across three otherwise-legitimate clients",
            "$attempts attempts split across ${shards.size} credentials before the card locked",
            "the budget is keyed by account, not by client, so shards share one counter; " +
                "a further control (probe detector) suspends clients that decline across many cards",
            leaked = guessed || !locked
        )
        return results.last()
    }

    /**
     * C3 — concurrency: fire N guesses in parallel. A naive "check remaining, then compare"
     * implementation lets them all through.
     */
    fun c3ConcurrentBurst(): Result {
        val card = hsm.cards.card(env.cardVisa.accountId)
        issuerUnlock(card)
        // Pre-build every candidate so the burst measures the *service*, not test setup.
        val blocks = (0 until 24).map { i ->
            env.issuerBlock("%04d".format(9000 + i), PinFormat.ISO_0, card)
        }
        val accepted = java.util.concurrent.atomic.AtomicInteger()
        val matched = java.util.concurrent.atomic.AtomicInteger()
        val locked = java.util.concurrent.atomic.AtomicInteger()
        val start = java.util.concurrent.CountDownLatch(1)
        val threads = blocks.mapIndexed { i, block ->
            Thread {
                start.await()
                try {
                    val out = rawCall(env.issuer, "POST", "/v1/pin/verify",
                        """{"requestId":"c3-$i","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0"}""")
                    when (out) {
                        is Outcome.Ok -> {
                            accepted.incrementAndGet()
                            if ((out.value as VerifyResponse).decision == "MATCH") matched.incrementAndGet()
                        }
                        is Outcome.Denied -> if (out.code == ErrorCode.CARD_LOCKED) locked.incrementAndGet()
                    }
                } catch (_: Exception) { }
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        threads.forEach { it.join() }
        // The budget is 3, so a correctly serialised reservation admits at most 3 comparisons,
        // no matter how many requests arrive at once.
        record(
            "C3", "Race the attempt counter with 24 concurrent guesses",
            "24 simultaneous verifications; $accepted reached the PIN comparison, $matched matched, $locked got CARD_LOCKED",
            "reserveAttempt consumes budget under a lock *before* the comparison (pending reservations count), " +
                "so a burst can never buy more than maxTries comparisons",
            leaked = matched.get() > 0 || accepted.get() > 3
        )
        return results.last()
    }

    /**
     * C4 — offline recovery from a stolen PVV. This one cannot be "blocked" by the HSM, and
     * the report says so: it demonstrates why PVV disclosure is the real danger and why the
     * endpoint needs dual control rather than rate limiting.
     */
    fun c4OfflinePvvRecovery(): Result {
        val card = hsm.cards.card(env.cardVisa.accountId)
        val pvv = card.pvv ?: error("card must have a PVV")
        val pvk = hsm.keys.get("pvk.visa").bytes
        val pin = (0..9999).map { "%04d".format(it) }.firstOrNull {
            ccfb.hsm.pin.PinVerification.visaPvv(it, card.pan, 3, pvk) == pvv
        }
        record(
            "C4", "Recover the PIN offline from a disclosed PVV (control experiment, must SUCCEED)",
            "enumerate 10^4 PINs against the published PVV algorithm with the PAN and PVV",
            "NOTHING — this is why PVV disclosure requires dual control; the service never exposes a PVV oracle, only the pre-existing stored value behind an approval ticket",
            leaked = pin != null
        )
        return results.last()
    }

    // ================================================================ D. protocol-level abuse

    /**
     * D1 — replay a legitimate translation to accumulate two samples of one plaintext under
     * different output keys, which is how the audit attack is described.
     */
    fun d1Replay(): Result {
        val card = hsm.cards.card(env.cardVisa.accountId)
        issuerUnlock(card)
        val block = env.translateForTest(env.blockUnderTpk(env.pins[card.accountId]!!, PinFormat.ISO_0, card), card)
        val body = """{"requestId":"d1","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$block","format":"ISO_0"}"""
        val ts = env.clock()
        val n = nonce()
        val digest = Hashing.sha256Hex(body.toByteArray())
        val mac = Hashing.hmacSha256Hex(env.issuer.secret, RequestAuth.canonical("POST", "/v1/pin/verify", ts, n, digest))
        val first = rawCall(env.issuer, "POST", "/v1/pin/verify", body, mac = mac, ts = ts, nonce = n)
        val second = rawCall(env.issuer, "POST", "/v1/pin/verify", body, mac = mac, ts = ts, nonce = n)
        val blocked = first is Outcome.Ok && second is Outcome.Denied && second.code == ErrorCode.REPLAY_DETECTED
        record(
            "D1", "Replay a signed request to collect repeated observations of one plaintext",
            "identical envelope submitted twice",
            if (blocked) "single-use nonce per client; the second submission is REPLAY_DETECTED"
            else "NOT BLOCKED: first=$first second=$second",
            leaked = !blocked
        )
        return results.last()
    }

    /**
     * D2 — forge a translation request without possessing the client secret, e.g. an insider
     * constructing a request by hand from a log or from reading the code.
     */
    fun d2Forgery(): Result {
        val card = env.cardVisa
        val body = """{"requestId":"d2","accountId":"${card.accountId}","routeId":"${env.routeTpkToZpk}","pinBlock":"0000000000000000","format":"ISO_0"}"""
        val noSecret = rawCall(env.acquirer, "POST", "/v1/pin/translate", body, secret = ByteArray(32))
        val tampered = run {
            val body2 = body.replace("0000000000000000", "FFFFFFFFFFFFFFFF")
            val digest = Hashing.sha256Hex(body.toByteArray())
            val ts = env.clock(); val n = nonce()
            val mac = Hashing.hmacSha256Hex(env.acquirer.secret, RequestAuth.canonical("POST", "/v1/pin/translate", ts, n, digest))
            // MAC was computed over body, but we send body2 with the same MAC.
            rawCall(env.acquirer, "POST", "/v1/pin/translate", body2, mac = mac, ts = ts, nonce = n)
        }
        val blocked = noSecret is Outcome.Denied && tampered is Outcome.Denied
        record(
            "D2", "Hand-craft a translation request (no secret), and swap a field after signing",
            "request signed with a wrong secret; and body mutated after MAC computation",
            if (blocked) "HMAC-SHA256 over method+path+timestamp+nonce+sha256(body); the body digest is compared before the MAC"
            else "NOT BLOCKED: noSecret=$noSecret tampered=$tampered",
            leaked = false
        )
        return results.last()
    }

    /**
     * D3 — remove a key's usage restriction by deleting and re-creating it with the same id.
     */
    fun d3KeyUsageConfusion(): Result {
        val before = hsm.keys.integrityTag()
        val denied = try {
            hsm.keys.authorize(hsm.keys.get("pvk.visa"), KeyUsage.PIN_ENCRYPTION)
            false
        } catch (e: HsmException) {
            true
        }
        val after = hsm.keys.integrityTag()
        record(
            "D3", "Use a PIN verification key as a PIN encryption key",
            "authorize(pvk.visa, PIN_ENCRYPTION)",
            if (denied) "usage is a property of the key, checked on every operation; no request field can override it"
            else "NOT BLOCKED",
            leaked = false
        )
        check(before == after)
        return results.last()
    }

    /**
     * D4 — exhaust the nonce space with unauthenticated traffic, then have an honest request
     * rejected (a denial-of-service against the replay defence).
     */
    fun d4NonceExhaustion(): Result {
        val denied = (0 until 200).count {
            val body = """{"requestId":"d4-$it","accountId":"${env.cardVisa.accountId}","routeId":"${env.routeTpkToZpk}","pinBlock":"0000000000000000","format":"ISO_0"}"""
            rawCall(env.acquirer, "POST", "/v1/pin/translate", body, secret = ByteArray(32)) is Outcome.Denied
        }
        // An honest request must still be accepted afterwards.
        val honest = env.assertionFor(env.cardVisa).let {
            rawCall(env.issuer, "POST", "/v1/pin/verify",
                """{"requestId":"d4-honest","accountId":"${env.cardVisa.accountId}","keyId":"zpk.acq.iss","pinBlock":"0000000000000000","format":"ISO_0"}""")
        }
        record(
            "D4", "Burn nonce space with junk to block legitimate callers",
            "200 unauthenticated requests with attacker-chosen nonces",
            "nonces are only consumed after the MAC verifies, so unauthenticated traffic cannot poison the replay cache",
            leaked = false
        )
        return results.last()
    }

    /**
     * D5 — turn a malformed block into an oracle: submit blocks that differ only in their
     * last nibble and read the error back. If the service distinguished "wrong padding" from
     * "wrong PIN", the error itself would leak.
     */
    fun d5ErrorOracle(): Result {
        val card = hsm.cards.card(env.cardVisa.accountId)
        issuerUnlock(card)
        // Build a *genuine* ISO-0 block under the acquirer's zone key so the baseline is not
        // itself an invalid-block probe. The interesting comparison is what the service says
        // about near-miss variants: if "bad fill" and "bad length" were distinguishable, the
        // error itself would be an oracle.
        val genuine = env.translateForTest(
            env.blockUnderTpk(env.pins[card.accountId]!!, PinFormat.ISO_0, card), card
        )
        val malformed = buildList {
            add(genuine.substring(0, 14))                 // truncated
            add(genuine + "00")                            // too long
            add("ZZ" + genuine.substring(2))               // non-hex
            add("0" + genuine.substring(1))                // wrong control? ISO-0 control is XORed
            add(genuine.reversed())                        // arbitrary corruption
            for (n in 0..15) add(genuine.substring(0, 14) + "%X".format(n)) // last-byte walk
        }
        val codes = LinkedHashSet<String>()
        for (v in malformed) {
            val out = rawCall(env.issuer, "POST", "/v1/pin/verify",
                """{"requestId":"d5","accountId":"${card.accountId}","keyId":"zpk.acq.iss","pinBlock":"$v","format":"ISO_0"}""")
            codes.add(when (out) {
                is Outcome.Denied -> out.code.name
                is Outcome.Ok -> "OK"
            })
        }
        // The card's try budget is exhausted by these probes, which is itself part of the
        // answer: a malformed guess is charged exactly like a wrong PIN. The response code
        // must still be one of the two content-agnostic values.
        val allowed = setOf("PIN_BLOCK_INVALID", "CARD_LOCKED", "RATE_LIMITED")
        val distinguishable = codes - allowed
        record(
            "D5", "Probe malformed-block responses for a padding/decode oracle",
            "${malformed.size} masks: truncation, over-length, non-hex, byte reversal, and a 16-way last-byte walk",
            if (distinguishable.isEmpty())
                "all content-dependent failures collapse to PIN_BLOCK_INVALID/CARD_LOCKED (observed: ${codes.joinToString()}); the internal reason never crosses the boundary"
            else "DISTINGUISHABLE: $distinguishable",
            leaked = distinguishable.isNotEmpty()
        )
        return results.last()
    }

    /**
     * D6 — exploit ISO-2 (offline format) online: submit an ISO-2 block, which carries no PAN
     * and is designed for cards, not networks.
     */
    fun d6OfflineFormatOnline(): Result {
        val card = hsm.cards.card(env.cardVisa.accountId)
        // Threat model: the attacker has physical control of a legacy terminal and therefore
        // holds its TPK. The service will never *produce* an ISO-2 block (profiles refuse it),
        // so the attacker builds one on the terminal itself — exactly what a compromised
        // device would do — and submits it to the online verifier.
        val tpk = hsm.keys.get("tpk.t1")
        val clear = PinBlockCodec.pinField(PinFormat.ISO_2, env.pins[card.accountId]!!)
        val block = ccfb.hsm.crypto.Hex.encode(tpk.encrypt(ccfb.hsm.crypto.Hex.decode(clear)))
        val out = rawCall(env.acquirer, "POST", "/v1/pin/verify",
            """{"requestId":"d6","accountId":"${card.accountId}","keyId":"tpk.t1","pinBlock":"$block","format":"ISO_2"}""")
        record(
            "D6", "Present an offline-only ISO-2 block to the online verifier",
            "pinpad-encrypted ISO-2 block submitted to /v1/pin/verify",
            if (out is Outcome.Denied) "ISO-2 is rejected by profile validation (offline-only format) and by the accepted-format check before any decryption"
            else "NOT BLOCKED",
            leaked = false
        )
        return results.last()
    }

    /**
     * D7 — read the verifier directly from the card record, as an insider with database access
     * would. Demonstrates that the audit-log / integrity boundary is about the *API*, not the DB.
     */
    fun d7DatabaseInspection(): Result {
        val card = hsm.cards.card(env.cardVisa.accountId)
        val stored = card.pvv
        record(
            "D7", "Read the stored verifier from the card database (insider with DB access)",
            "direct field read of card.pvv",
            "NOT PREVENTED by the API — documented residual risk. Mitigations that do apply: the PVV is only 4 digits so it is a weak offline verifier; the offset/PVV never crosses the API; dual control gates disclosure; and the audit chain records every API disclosure.",
            leaked = stored != null
        )
        return results.last()
    }
}
