package ccfb.hsm.core

import ccfb.hsm.api.*

import ccfb.hsm.crypto.ConstantTime
import ccfb.hsm.crypto.Hashing
import ccfb.hsm.crypto.Hex
import ccfb.hsm.model.*
import ccfb.hsm.pin.CardVerification
import ccfb.hsm.pin.PinBlockCodec
import ccfb.hsm.pin.PinBlockFormatException
import ccfb.hsm.pin.PinVerification

/**
 * The HSM facade. Each public method is one wire operation and is documented in `docs/API.md`
 * together with the attacks it is designed to stop.
 *
 * Cross-cutting invariants:
 *
 *  I1  A PIN block is decrypted only under a key whose id is pinned by a configured route or
 *      by the caller's allow list, and whose usage is PIN_ENCRYPTION or TERMINAL_PIN.
 *  I2  Verification parameters (PVK, PVKI, decimalisation table, PAN pad char, try limits,
 *      accepted formats) come from the card profile and are integrity-tagged; they are never
 *      request fields.
 *  I3  The PAN that unbinds a block is the card record's PAN, never the request's.
 *  I4  All content-dependent PIN block failures collapse to PIN_BLOCK_INVALID.
 *  I5  Every call — accept or deny — is appended to the hash-chained audit log with the body
 *      digest, so an unlogged operation is provably not one this service performed.
 *  I6  The attempt budget is card-scoped and is charged by every endpoint that compares a
 *      guessed secret to the card's stored verifier.
 */
class Hsm(private val clock: () -> Long = System::currentTimeMillis) {

    // ------------------------------------------------------------------ state

    val keys = KeyStore(ccfb.hsm.crypto.RandomBytes.get(32))
    val cards = CardStore(ccfb.hsm.crypto.RandomBytes.get(32))
    val audit = AuditLog(clock)
    private val approvalKey = ccfb.hsm.crypto.RandomBytes.get(32)
    private val nonces = NonceStore()
    private val limiter = RateLimiter(clock)
    private val probes = ProbeDetector(300_000, distinctCardThreshold = 5, declineThreshold = 10, clock = clock)
    private val ledger = AttemptLedger(
        maxTries = { id -> profileOf(id).maxTries },
        lockoutMs = { id -> profileOf(id).lockoutSeconds * 1000 },
        clock = clock
    )

    private val clients = LinkedHashMap<String, Client>()
    private val routes = LinkedHashMap<String, Route>()
    private val sessions = HashMap<String, TerminalSession>()
    private val verificationKeyClients = HashMap<String, MutableSet<String>>()
    /** Approval tickets that have already been redeemed; makes "single use" true, not aspirational. */
    private val usedTickets = HashSet<String>()

    private var keyIntegrityTag: String = keys.integrityTag()

    // ------------------------------------------------------------------ administration

    @Synchronized
    fun addClient(client: Client) {
        clients[client.id] = client
    }

    @Synchronized
    fun client(id: String): Client = clients[id] ?: throw HsmException(ErrorCode.UNAUTHENTICATED)

    @Synchronized
    fun addRoute(route: Route) {
        val from = keys.get(route.fromKey)
        val to = keys.get(route.toKey)
        if (from.usage == KeyUsage.PIN_VERIFICATION || to.usage == KeyUsage.PIN_VERIFICATION) {
            throw IllegalArgumentException("a translation route may never name a PIN verification key")
        }
        requireCompatible(route.fromFormat, from.family)
        requireCompatible(route.toFormat, to.family)
        routes[route.id] = route
    }

    @Synchronized
    fun routeIds(): Set<String> = routes.keys.toSet()

    /** Snapshot the key-integrity tag after the key ceremony. */
    @Synchronized
    fun sealKeys() {
        keyIntegrityTag = keys.integrityTag()
    }

    /** Registers that [clientId] may use [keyId] as a verification key. */
    @Synchronized
    fun allowVerificationKey(keyId: String, clientId: String) {
        verificationKeyClients.getOrPut(keyId) { HashSet() }.add(clientId)
    }

    fun profileOf(accountId: String): ValidationProfile = cards.profile(cards.card(accountId).profileId)

    // ------------------------------------------------------------------ transport

    fun call(method: String, path: String, signed: SignedCall): Any {
        val client = clients[signed.envelope.clientId]
            ?: throw HsmException(ErrorCode.UNAUTHENTICATED, "unknown client")
        val body = signed.body.toByteArray(Charsets.UTF_8)
        RequestAuth.verify(
            client.secret,
            RequestAuth.Envelope(
                signed.envelope.clientId, signed.envelope.timestampMs,
                signed.envelope.nonce, signed.envelope.bodySha256, signed.envelope.mac
            ),
            method, path, body, clock(), nonces
        )
        val digest = RequestAuth.digestBody(body)
        val requestId = readField(signed.body, "requestId") ?: "-"
        // Exactly one audit entry per call. Operations deposit their details (key ids, formats,
        // decision, reason) here; if they do not, the entry still records the call and its body
        // digest, which is what makes "an unlogged operation is not one we performed" true.
        detail.set(null)
        return try {
            val result = dispatch(method, path, signed.body, client)
            val d = detail.get()
            audit.append(
                requestId, client.id, "$method $path", d?.accountToken ?: accountTokenOf(signed.body),
                d?.keyIds ?: emptyList(), d?.formats ?: emptyList(),
                d?.decision ?: "ACCEPT", d?.reason ?: "", digest
            )
            result
        } catch (e: HsmException) {
            val d = detail.get()
            audit.append(
                requestId, client.id, "$method $path", d?.accountToken ?: accountTokenOf(signed.body),
                d?.keyIds ?: emptyList(), d?.formats ?: emptyList(),
                "DENY", e.code.name, digest
            )
            throw e
        } catch (e: Exception) {
            // Anything else — a malformed body that Jackson refuses, or an unexpected runtime
            // fault — is still audited and still mapped to a uniform public error. An
            // exception path that skipped the log would be exactly the "plausibly the service
            // never saw it" gap the chain exists to close.
            val d = detail.get()
            audit.append(
                requestId, client.id, "$method $path", d?.accountToken ?: accountTokenOf(signed.body),
                d?.keyIds ?: emptyList(), d?.formats ?: emptyList(),
                "DENY", "INVALID_REQUEST", digest
            )
            throw HsmException(ErrorCode.INVALID_REQUEST, e.javaClass.simpleName)
        } finally {
            detail.remove()
        }
    }

    /** Per-call audit detail deposited by the operation that handled the request. */
    private class AuditDetail(
        val accountToken: String?,
        val keyIds: List<String>,
        val formats: List<String>,
        val decision: String,
        val reason: String
    )

    private val detail = ThreadLocal<AuditDetail?>()

    private fun note(accountToken: String?, keyIds: List<String>, formats: List<String>, decision: String, reason: String) {
        detail.set(AuditDetail(accountToken, keyIds, formats, decision, reason))
    }

    private fun readField(body: String, field: String): String? =
        runCatching { Wire.mapper.readTree(body)[field]?.takeIf { it.isTextual }?.asText() }.getOrNull()

    private fun accountTokenOf(body: String): String? = runCatching {
        val id = readField(body, "accountId") ?: return@runCatching null
        cards.card(id).token()
    }.getOrNull()

    private fun dispatch(method: String, path: String, body: String, client: Client): Any = when {
        method == "POST" && path == "/v1/session/begin" -> beginSession(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/pinpad/encrypt" -> pinPadEncrypt(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/pin/translate" -> translate(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/pin/verify" -> verifyPin(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/pin/set" -> setPin(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/pin/unlock" -> unlockCard(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/pvv/approve" -> approve(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/pvv/issue" -> issuePvv(Wire.fromJson(body), client)
        method == "POST" && path == "/v1/cvv/verify" -> verifyCvv(Wire.fromJson(body), client)
        method == "GET" && path == "/v1/status" -> status(client)
        method == "GET" && path == "/v1/audit" -> auditView(client)
        else -> throw HsmException(ErrorCode.INVALID_REQUEST, "unknown operation")
    }

    // ------------------------------------------------------------------ terminal operations

    /**
     * The terminal announces that card [accountId] is now in the reader.
     *
     * This is the sole source of a terminal session. A session is what authorises an
     * unbound format (ISO-1) to be produced for, or accepted on behalf of, one specific card.
     */
    fun beginSession(req: BeginSessionRequest, client: Client): SessionResponse {
        requireRole(client, Role.TERMINAL)
        requireClientKey(client, req.terminalKeyId)
        val terminalKey = keys.get(req.terminalKeyId)
        keys.authorize(terminalKey, KeyUsage.TERMINAL_PIN)
        val card = cards.card(req.accountId)
        cards.requireActive(card)
        val bindingKey = bindingKeyOf(client)

        val sessionId = "S-" + ccfb.hsm.crypto.RandomBytes.hex(16)
        val expires = clock() + SESSION_MS
        synchronized(sessions) { sessions[sessionId] = TerminalSession(client.id, req.accountId, req.terminalKeyId, expires) }
        return SessionResponse(req.requestId, sessionId, expires, sessionMac(bindingKey, sessionId, req.accountId, expires))
    }

    /**
     * Terminal-side PIN encryption (the PIN pad path).
     *
     * Not a translation: it only ever emits a block for the card named in a live session the
     * same terminal opened. Format is limited to what the card profile accepts.
     */
    fun pinPadEncrypt(req: PinPadRequest, client: Client): PinPadResponse {
        requireRole(client, Role.TERMINAL)
        requireClientKey(client, req.terminalKeyId)
        val key = keys.get(req.terminalKeyId)
        keys.authorize(key, KeyUsage.TERMINAL_PIN)
        val format = parseFormat(req.format)
        requireCompatible(format, key.family)

        val session = liveSession(req.sessionId, client, req.accountId)
        if (session.terminalKeyId != req.terminalKeyId) throw HsmException(ErrorCode.POLICY_DENIED)

        val card = cards.card(req.accountId)
        val profile = cards.profile(card.profileId)
        if (format !in profile.acceptedFormats) throw HsmException(ErrorCode.POLICY_DENIED)

        val clear = try {
            PinBlockCodec.pinField(format, req.pin)
        } catch (_: PinBlockFormatException) {
            throw HsmException(ErrorCode.PIN_BLOCK_INVALID)
        }
        val out = encryptPinField(key, format, clear, card.pan)
        note(card.token(), listOf(req.terminalKeyId), listOf(format.name), "ENCRYPT", "pinpad")
        return PinPadResponse(req.requestId, Hex.encode(out), format.name)
    }

    // ------------------------------------------------------------------ translation

    /**
     * Translate a PIN block between the two keys of a configured [Route].
     *
     * Impossible by construction here:
     *  - naming a key outside the route (the route fixes both key ids);
     *  - using a PIN verification key as source or destination (routes refuse one);
     *  - relabelling the block's format (the route fixes it, and a mismatching `format`
     *    field is rejected rather than silently trusted);
     *  - moving the block to a different PAN (the PAN always comes from the card record and
     *    `accountId` must resolve to it);
     *  - stripping PAN binding towards anything but a terminal actually holding that card
     *    (the route must require a live session, and the source format must be bound).
     */
    fun translate(req: TranslateRequest, client: Client): TranslateResponse {
        requireRate(client, "translate", client.translatePerSecond, client.translateBurst)
        val route = routes[req.routeId] ?: throw HsmException(ErrorCode.FORBIDDEN)
        if (client.id !in route.allowedClients) throw HsmException(ErrorCode.FORBIDDEN)
        requireClientKey(client, route.fromKey)
        requireClientKey(client, route.toKey)
        if (!requireRateToken("route:${route.id}", route.perHourLimit / 3600.0, maxOf(1, route.perHourLimit / 60))) {
            throw HsmException(ErrorCode.RATE_LIMITED)
        }
        if (PinFormat.parse(req.format) != route.fromFormat) {
            throw HsmException(ErrorCode.POLICY_DENIED, "format does not match route")
        }
        val card = cards.card(req.accountId)
        cards.requireActive(card)
        val profile = cards.profile(card.profileId)
        // Both ends of the route must be acceptable to this card's issuer. Checking the
        // destination too prevents a route from *downgrading* a card to a format its issuer
        // does not support (for example emitting ISO-1 for a card that only accepts ISO-0).
        if (route.fromFormat !in profile.acceptedFormats) throw HsmException(ErrorCode.POLICY_DENIED)
        if (route.toFormat !in profile.acceptedFormats) throw HsmException(ErrorCode.POLICY_DENIED)

        // An unbound source format has no PAN inside it, so the only thing that can bind it to
        // this card is a live assertion signed by the terminal that captured the PIN. This is
        // required whether or not the destination format happens to be PAN-bound: converting
        // ISO-1 -> ISO-0 is precisely how an observed ISO-1 block would otherwise be re-bound
        // to an arbitrary PAN.
        if (!route.fromFormat.boundToPan) requireBinding(req.terminalAssertion, client, card.accountId)
        if (route.requiresTerminalBinding) requireBinding(req.terminalAssertion, client, card.accountId)
        if (route.requiresTerminalSession) requireLiveSessionFor(client, card.accountId)

        val fromKey = keys.get(route.fromKey)
        val toKey = keys.get(route.toKey)
        val block = decodeBlockHex(req.pinBlock, route.fromFormat)

        val pin = try {
            val pinField = decryptToPinField(fromKey, route.fromFormat, block, card.pan)
            PinBlockCodec.decodeField(route.fromFormat, pinField, profile).pin
        } catch (_: PinBlockFormatException) {
            throw HsmException(ErrorCode.PIN_BLOCK_INVALID)
        }

        val out = try {
            val outField = PinBlockCodec.pinField(route.toFormat, pin)
            encryptPinField(toKey, route.toFormat, outField, card.pan)
        } catch (_: PinBlockFormatException) {
            throw HsmException(ErrorCode.PIN_BLOCK_INVALID)
        }

        note(card.token(), listOf(route.fromKey, route.toKey),
            listOf(route.fromFormat.name, route.toFormat.name), "TRANSLATE", route.id)
        return TranslateResponse(req.requestId, Hex.encode(out), route.toFormat.name, toKey.kcv)
    }

    // ------------------------------------------------------------------ verification

    /**
     * Verify a submitted PIN against the card's stored verifier.
     *
     * The block arrives under `req.keyId` (usage PIN_ENCRYPTION, or TERMINAL_PIN for a
     * PIN-pad block). The verification key, PVKI, decimalisation table and limits come from
     * the profile. One attempt is charged to the card *before* the PIN is checked, so N
     * concurrent guesses cannot outrun the counter, and the only thing returned is
     * MATCH/DECLINE plus the remaining budget.
     */
    fun verifyPin(req: VerifyPinRequest, client: Client): VerifyResponse {
        requireRate(client, "verify", client.verifyPerSecond, client.verifyBurst)
        requireClientKey(client, req.keyId)
        val sourceKey = keys.get(req.keyId)
        if (sourceKey.usage != KeyUsage.PIN_ENCRYPTION && sourceKey.usage != KeyUsage.TERMINAL_PIN) {
            throw HsmException(ErrorCode.KEY_USAGE_VIOLATION)
        }
        val format = parseFormat(req.format)
        requireCompatible(format, sourceKey.family)

        val card = cards.card(req.accountId)
        cards.requireActive(card)
        val profile = cards.profile(card.profileId)
        if (format !in profile.acceptedFormats) throw HsmException(ErrorCode.POLICY_DENIED)
        if (!format.boundToPan) requireBinding(req.terminalAssertion, client, card.accountId)

        val pvk = keys.get(profile.verificationKeyId)
        keys.authorize(pvk, KeyUsage.PIN_VERIFICATION)
        if (client.id !in verificationClientsFor(profile.verificationKeyId)) {
            throw HsmException(ErrorCode.FORBIDDEN)
        }
        if (probes.isProbing(client.id)) throw HsmException(ErrorCode.POLICY_DENIED, "client suspended")

        // Charge the attempt first: a malformed block must not be a free oracle for
        // "does this ciphertext decrypt to something structurally valid?".
        ledger.reserveAttempt(card.accountId)

        val pin = try {
            val block = decodeBlockHex(req.pinBlock, format)
            val pinField = decryptToPinField(sourceKey, format, block, card.pan)
            PinBlockCodec.decodeField(format, pinField, profile).pin
        } catch (_: PinBlockFormatException) {
            ledger.recordResult(card.accountId, false)
            probes.record(client.id, card.accountId, false)
            throw HsmException(ErrorCode.PIN_BLOCK_INVALID)
        } catch (e: HsmException) {
            ledger.recordResult(card.accountId, false)
            probes.record(client.id, card.accountId, false)
            throw e
        }

        val matched = PinVerification.verify(profile, pin, card.pan, verifierValue(card, profile), pvk.bytes)
        ledger.recordResult(card.accountId, matched)
        probes.record(client.id, card.accountId, matched)

        note(card.token(), listOf(req.keyId, profile.verificationKeyId), listOf(format.name),
            if (matched) "MATCH" else "DECLINE", profile.method.name)
        return VerifyResponse(req.requestId, if (matched) "MATCH" else "DECLINE", ledger.remaining(card.accountId))
    }

    /** CVV check. Same oracle economics as a 4-digit PIN, so metered and card-scoped. */
    fun verifyCvv(req: VerifyCvvRequest, client: Client): VerifyResponse {
        requireRate(client, "cvv", client.verifyPerSecond, client.verifyBurst)
        val card = cards.card(req.accountId)
        cards.requireActive(card)
        if (req.cvv.length != 3 || !req.cvv.all { it in '0'..'9' }) throw HsmException(ErrorCode.INVALID_REQUEST)
        val profile = cards.profile(card.profileId)
        val cvkId = cvkIdFor(profile)
        val cvk = keys.get(cvkId)
        keys.authorize(cvk, KeyUsage.CVV)
        requireClientKey(client, cvkId)
        if (probes.isProbing(client.id)) throw HsmException(ErrorCode.POLICY_DENIED, "client suspended")

        ledger.reserveAttempt(card.accountId)
        val expected = CardVerification.cvv(card.pan, card.expiry, card.serviceCode, cvk.bytes)
        val matched = ConstantTime.equals(expected, req.cvv)
        ledger.recordResult(card.accountId, matched)
        probes.record(client.id, card.accountId, matched)
        return VerifyResponse(req.requestId, if (matched) "MATCH" else "DECLINE", ledger.remaining(card.accountId))
    }

    /**
     * Issuer-side unlock after the cardholder has been identified out of band.
     *
     * This exists because a lockout without an unlock path is a denial-of-service against the
     * cardholder. It is ISSUER-only, audited, and it does not reset the *total* attempt
     * counter — so repeated lock/unlock cycles remain visible to the probe detector.
     */
    fun unlockCard(req: UnlockRequest, client: Client): VerifyResponse {
        requireRole(client, Role.ISSUER)
        val card = cards.card(req.accountId)
        ledger.unlock(card.accountId)
        note(card.token(), emptyList(), emptyList(), "UNLOCK", req.reason.take(80))
        return VerifyResponse(req.requestId, "UNLOCKED", ledger.remaining(card.accountId))
    }

    /** Total attempts ever recorded for a card, for the probe detector and status views. */
    fun totalAttempts(accountId: String): Long = ledger.state(accountId).totalAttempts

    // ------------------------------------------------------------------ issuance

    /**
     * Issuer provisioning: set a PIN and store the derived verifier.
     *
     * The only path that consumes a clear PIN. Restricted to ISSUER, audited, and it returns
     * no verifier value. PVV/offset stay inside the card record.
     */
    fun setPin(req: SetPinRequest, client: Client): VerifyResponse {
        requireRole(client, Role.ISSUER)
        val card = cards.card(req.accountId)
        val profile = cards.profile(card.profileId)
        requireClientKey(client, profile.verificationKeyId)
        val pvk = keys.get(profile.verificationKeyId)
        keys.authorize(pvk, KeyUsage.PIN_VERIFICATION)
        if (card.state == CardState.BLOCKED) throw HsmException(ErrorCode.CARD_LOCKED)
        try {
            PinBlockCodec.requireValidPin(req.newPin, profile)
        } catch (_: PinBlockFormatException) {
            throw HsmException(ErrorCode.INVALID_REQUEST)
        }
        val updated = when (profile.method) {
            VerifyMethod.VISA_PVV -> card.copy(
                pvv = PinVerification.visaPvv(req.newPin, card.pan, profile.pvki, pvk.bytes)
            )
            VerifyMethod.IBM_3624_OFFSET -> {
                val natural = PinVerification.ibm3624NaturalPin(
                    card.pan, req.newPin.length, pvk.bytes, profile.decimalizationTable, profile.panPadChar
                )
                card.copy(offset = PinVerification.computeOffset(req.newPin, natural))
            }
        }
        cards.updateCard(updated)
        ledger.unlock(card.accountId)
        note(card.token(), listOf(profile.verificationKeyId), emptyList(), "UPDATED", profile.method.name)
        return VerifyResponse(req.requestId, "UPDATED", ledger.remaining(card.accountId))
    }

    /**
     * SECURITY_OFFICER approval for a PVV disclosure. Returns a single-use ticket bound to
     * the account and operation, valid for five minutes.
     */
    fun approve(req: ApproveRequest, client: Client): ApprovalResponse {
        requireRole(client, Role.SECURITY_OFFICER)
        cards.card(req.accountId)
        val expires = clock() + APPROVAL_MS
        // The ticket carries the officer id and expiry in the clear so the issuer can quote
        // it back; the MAC over (officer, account, operation, expiry) is what authenticates it.
        val ticket = "${client.id}|$expires|${approvalMac(client.id, req.accountId, req.operation, expires)}"
        note(cards.card(req.accountId).token(), emptyList(), emptyList(), "APPROVE", req.operation)
        return ApprovalResponse(req.requestId, ticket, expires)
    }

    /**
     * Disclose the PVV already stored for a card.
     *
     * Why this is the sharpest edge in the service, stated plainly: a PVV is a 4-digit
     * function of the PIN. With the PAN (printed on the card) and the PVV, anyone can run the
     * published algorithm offline and recover a 4-digit PIN in 10^4 attempts — no HSM, no
     * rate limit, no audit trail. The endpoint therefore does three things and documents all
     * three: it requires an ISSUER client *and* a fresh SECURITY_OFFICER approval ticket; it
     * refuses to compute a PVV for a caller-supplied PIN (there is no chosen-PIN oracle); and
     * it logs the disclosure with the card token. In a real deployment this belongs behind a
     * key ceremony, not an API.
     */
    fun issuePvv(req: IssuePvvRequest, client: Client): PvvResponse {
        requireRole(client, Role.ISSUER)
        val card = cards.card(req.accountId)
        val profile = cards.profile(card.profileId)
        if (profile.method != VerifyMethod.VISA_PVV) throw HsmException(ErrorCode.POLICY_DENIED)
        requireClientKey(client, profile.verificationKeyId)
        val pvv = card.pvv ?: throw HsmException(ErrorCode.POLICY_DENIED, "no verifier on file")
        verifyApproval(req.approvalTicket, card.accountId, "ISSUE_PVV")
        note(card.token(), listOf(profile.verificationKeyId), emptyList(), "DISCLOSE", "pvv")
        return PvvResponse(req.requestId, pvv)
    }

    // ------------------------------------------------------------------ introspection

    fun status(client: Client): StatusResponse {
        if (client.role != Role.SECURITY_OFFICER && client.role != Role.AUDITOR) {
            throw HsmException(ErrorCode.FORBIDDEN)
        }
        return StatusResponse(
            "-",
            keys.selfCheck(keyIntegrityTag),
            cards.selfCheckAll(),
            audit.verifyChain(),
            audit.size,
            keys.all().sortedBy { it.id }.map { KeyInfo(it.id, it.usage.name, it.algorithm, it.kcv, it.owner) }
        )
    }

    fun auditView(client: Client): List<AuditEntryView> {
        if (client.role != Role.AUDITOR && client.role != Role.SECURITY_OFFICER) throw HsmException(ErrorCode.FORBIDDEN)
        return audit.all().map {
            AuditEntryView(
                it.seq, it.at, it.requestId, it.clientId, it.operation, it.accountToken,
                it.keyIds, it.formats, it.decision, it.reason, it.bodyDigest, it.hash
            )
        }
    }

    // ------------------------------------------------------------------ internals

    @Synchronized
    private fun verificationClientsFor(keyId: String): Set<String> = verificationKeyClients[keyId].orEmpty()

    private fun cvkIdFor(profile: ValidationProfile): String = "cvk.${profile.id}"

    private fun verifierValue(card: Card, profile: ValidationProfile): String? = when (profile.method) {
        VerifyMethod.VISA_PVV -> card.pvv
        VerifyMethod.IBM_3624_OFFSET -> card.offset
    }

    private fun parseFormat(s: String): PinFormat =
        PinFormat.parse(s) ?: throw HsmException(ErrorCode.INVALID_REQUEST)

    private fun decodeBlockHex(hex: String, format: PinFormat): ByteArray {
        val bytes = Hex.tryDecode(hex) ?: throw HsmException(ErrorCode.PIN_BLOCK_INVALID)
        if (bytes.size != format.ciphertextBytes) throw HsmException(ErrorCode.PIN_BLOCK_INVALID)
        return bytes
    }

    /**
     * Encrypts a plaintext PIN field, applying the format's binding construction.
     *
     * Formats 0/3: block = Enc(PINfield XOR PANfield).
     * Formats 1/2: block = Enc(PINfield) — the block carries no PAN.
     * Format 4   : A = Enc(PINfield); B = A XOR PANfield; C = Enc(B).
     */
    private fun encryptPinField(key: HsmKey, format: PinFormat, pinField: String, pan: String): ByteArray {
        if (format == PinFormat.ISO_4) {
            val panField = Hex.decode(PinBlockCodec.panField4(pan))
            val a = key.encrypt(Hex.decode(pinField))
            val b = ByteArray(16) { i -> (a[i].toInt() xor panField[i].toInt()).toByte() }
            return key.encrypt(b)
        }
        val clear = PinBlockCodec.clearBlock(format, pinField, PinBlockCodec.panFieldOf(format, pan))
        return key.encrypt(Hex.decode(clear))
    }

    /** Inverse of [encryptClear]: returns the plaintext PIN field. */
    private fun decryptToPinField(key: HsmKey, format: PinFormat, block: ByteArray, pan: String): String {
        if (format == PinFormat.ISO_4) {
            val panField = Hex.decode(PinBlockCodec.panField4(pan))
            val b = key.decrypt(block)
            val a = ByteArray(16) { i -> (b[i].toInt() xor panField[i].toInt()).toByte() }
            return Hex.encode(key.decrypt(a))
        }
        val field = Hex.encode(key.decrypt(block))
        return if (format.boundToPan) PinBlockCodec.xorHex(field, PinBlockCodec.panField12(pan)) else field
    }

    private fun requireRole(client: Client, role: Role) {
        if (client.role != role) throw HsmException(ErrorCode.FORBIDDEN)
    }

    private fun requireClientKey(client: Client, keyId: String) {
        if (keyId !in client.allowedKeyIds) throw HsmException(ErrorCode.KEY_USAGE_VIOLATION)
    }

    /**
     * Format/key compatibility. ISO-4 is AES-only; formats 0-3 are TDEA-only.
     *
     * This is a *policy* refusal (not an assertion), so a mismatched pair produces the same
     * uniform 403 rather than a 500 that would reveal the service's internal key inventory.
     */
    private fun requireCompatible(format: PinFormat, family: CipherFamily) {
        val ok = if (format == PinFormat.ISO_4) family == CipherFamily.AES else family != CipherFamily.AES
        if (!ok) throw HsmException(ErrorCode.POLICY_DENIED, "format/key family mismatch")
    }

    private fun requireRate(client: Client, op: String, rate: Double, burst: Int) {
        if (!limiter.tryAcquire("${client.id}:$op", rate, burst)) throw HsmException(ErrorCode.RATE_LIMITED)
    }

    private fun requireRateToken(key: String, rate: Double, burst: Int): Boolean =
        limiter.tryAcquire(key, rate, burst)

    private fun liveSession(sessionId: String, client: Client, accountId: String): TerminalSession {
        val s = synchronized(sessions) { sessions[sessionId] } ?: throw HsmException(ErrorCode.POLICY_DENIED)
        if (s.clientId != client.id || s.accountId != accountId) throw HsmException(ErrorCode.POLICY_DENIED)
        if (clock() > s.expiresAtMs) throw HsmException(ErrorCode.POLICY_DENIED)
        return s
    }

    private fun requireLiveSessionFor(client: Client, accountId: String) {
        val ok = synchronized(sessions) {
            sessions.values.any { it.clientId == client.id && it.accountId == accountId && clock() <= it.expiresAtMs }
        }
        if (!ok) throw HsmException(ErrorCode.POLICY_DENIED)
    }

    private fun bindingKeyOf(client: Client): HsmKey {
        val id = client.bindingKeyId ?: throw HsmException(ErrorCode.POLICY_DENIED)
        val k = keys.get(id)
        keys.authorize(k, KeyUsage.TERMINAL_BINDING)
        return k
    }

    private fun sessionMac(key: HsmKey, sessionId: String, accountId: String, expires: Long): String =
        Hashing.hmacSha256Hex(key.bytes, "session\n$sessionId\n$accountId\n$expires")

    /**
     * Validates a terminal binding assertion — the control that makes ISO-1 (no PAN inside
     * the block) survivable. The terminal signs (sessionId, accountId, expiry) with a key used
     * for nothing else. An acquirer insider cannot mint one, and the named session must be
     * live and belong to that same client and card.
     */
    private fun requireBinding(assertion: TerminalAssertion?, client: Client, accountId: String) {
        if (assertion == null) throw HsmException(ErrorCode.POLICY_DENIED)
        val bindingKey = bindingKeyOf(client)
        if (assertion.terminalId != client.id) throw HsmException(ErrorCode.POLICY_DENIED)
        if (clock() > assertion.expiresAtMs) throw HsmException(ErrorCode.POLICY_DENIED)
        val expected = sessionMac(bindingKey, assertion.sessionId, accountId, assertion.expiresAtMs)
        if (!ConstantTime.equals(expected, assertion.mac)) throw HsmException(ErrorCode.POLICY_DENIED)
        liveSession(assertion.sessionId, client, accountId)
    }

    private fun approvalMac(officerId: String, accountId: String, operation: String, expires: Long): String =
        Hashing.hmacSha256Hex(approvalKey, "approval\n$officerId\n$accountId\n$operation\n$expires")

    /**
     * Verifies and *redeems* an approval ticket.
     *
     * Redemption is recorded so a ticket really is single use: otherwise "approve once" would
     * mean "disclose as often as you like within five minutes", which is not what a second
     * person's approval is supposed to buy. Redeeming happens under the same lock as the
     * lookup, so two concurrent redemptions of one ticket cannot both succeed.
     */
    @Synchronized
    private fun verifyApproval(ticket: String, accountId: String, operation: String) {
        // Ticket format: officerId|expires|mac. The MAC covers officer, account, operation.
        val parts = ticket.split('|')
        if (parts.size != 3) throw HsmException(ErrorCode.POLICY_DENIED)
        val expires = parts[1].toLongOrNull() ?: throw HsmException(ErrorCode.POLICY_DENIED)
        if (clock() > expires) throw HsmException(ErrorCode.POLICY_DENIED)
        val expected = approvalMac(parts[0], accountId, operation, expires)
        if (!ConstantTime.equals(expected, parts[2])) throw HsmException(ErrorCode.POLICY_DENIED)
        val officer = clients[parts[0]] ?: throw HsmException(ErrorCode.POLICY_DENIED)
        if (officer.role != Role.SECURITY_OFFICER) throw HsmException(ErrorCode.POLICY_DENIED)
        if (!usedTickets.add(ticket)) throw HsmException(ErrorCode.POLICY_DENIED, "ticket already redeemed")
        // Opportunistically drop expired tickets so the set cannot grow without bound.
        usedTickets.removeIf { it.split('|').getOrNull(1)?.toLongOrNull()?.let { e -> clock() > e } ?: true }
    }

    companion object {
        const val SESSION_MS = 5 * 60 * 1000L
        const val APPROVAL_MS = 5 * 60 * 1000L
    }
}
