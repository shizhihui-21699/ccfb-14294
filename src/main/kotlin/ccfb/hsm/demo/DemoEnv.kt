package ccfb.hsm.demo

import ccfb.hsm.api.*
import ccfb.hsm.core.Hsm
import ccfb.hsm.core.RequestAuth
import ccfb.hsm.core.Route
import ccfb.hsm.crypto.Hashing
import ccfb.hsm.crypto.Hex
import ccfb.hsm.crypto.RandomBytes
import ccfb.hsm.model.*

/**
 * A realistic acquirer-side deployment, wired end to end.
 *
 * Topology (all keys held by the HSM; clients only ever see key ids and KCVs):
 *
 *   terminal T1 --(TPK: ISO-1/ISO-0)--> acquirer --(ZPK: ISO-0/ISO-3)--> issuer
 *   terminal T1 --(AES terminal key: ISO-4)--> acquirer --(AES ZPK)--> issuer
 *
 * Clients:
 *   term.t1     TERMINAL   may encrypt under its own TPK and open sessions for a card
 *   acq.host    ACQUIRER   may translate TPK->ZPK
 *   issuer.auth ISSUER     may verify, set PINs, and disclose PVVs with approval
 *   sec.officer SECURITY_OFFICER  approves PVV disclosure, can read status/audit
 *   auditor     AUDITOR    read-only audit/status
 *
 * Both a Visa-PVV card and an IBM-3624-offset card are provisioned, and one card is
 * provisioned for ISO-4/AES to exercise the 128-bit path.
 */
class DemoEnv(val clock: () -> Long = System::currentTimeMillis) {

    val hsm = Hsm(clock)

    lateinit var termT1: Client
    lateinit var acquirer: Client
    lateinit var issuer: Client
    lateinit var officer: Client
    lateinit var auditor: Client

    /** Card with a Visa PVV, ISO-0/1/3 accepted. */
    lateinit var cardVisa: Card
    /** Card verified by IBM 3624 offset. */
    lateinit var cardOffset: Card
    /** Card with AES / ISO-4. */
    lateinit var cardAes: Card

    lateinit var routeTpkToZpk: String
    lateinit var routeZpkToTpk: String
    lateinit var routeAesTpkToZpk: String
    lateinit var routeIso1ToIso0: String
    /** Acquirer -> issuer leg for AES/ISO-4. Legitimate production topology, added so the
     *  demo can exercise ISO-4 verification end to end through the same route machinery. */
    lateinit var routeAesAcqToIss: String

    val pins = HashMap<String, String>()  // accountId -> PIN, demo bookkeeping only

    fun build(): DemoEnv {
        keys()
        profiles()
        cards()
        clients()
        routes()
        hsm.sealKeys()
        return this
    }

    // ------------------------------------------------------------------ keys

    private fun keys() {
        val k = hsm.keys
        // Terminal PIN key for T1 (2-key 3DES, as most terminals use).
        k.create("tpk.t1", KeyUsage.TERMINAL_PIN, owner = "term.t1", keyBytes = mat("tpk.t1"))
        // Zone PIN key acquirer <-> issuer (3-key 3DES).
        k.create("zpk.acq.iss", KeyUsage.PIN_ENCRYPTION, owner = "acq.host", keyBytes = mat("zpk.acq.iss"))
        // AES zone key for ISO-4.
        k.create("zpk.aes.acq.iss", KeyUsage.PIN_ENCRYPTION, owner = "acq.host",
            keyBytes = RandomBytes.get(32), family = CipherFamily.AES)
        // AES terminal key.
        k.create("tpk.aes.t1", KeyUsage.TERMINAL_PIN, owner = "term.t1",
            keyBytes = RandomBytes.get(32), family = CipherFamily.AES)
        // PVKs.
        k.create("pvk.visa", KeyUsage.PIN_VERIFICATION, owner = "issuer.auth", keyBytes = mat("pvk.visa"))
        k.create("pvk.ibm", KeyUsage.PIN_VERIFICATION, owner = "issuer.auth", keyBytes = mat("pvk.ibm"))
        // CVK for CVV2.
        k.create("cvk.visa", KeyUsage.CVV, owner = "issuer.auth", keyBytes = mat("cvk.visa"))
        // Terminal binding key: signs "this card is in this terminal" assertions.
        k.create("bind.t1", KeyUsage.TERMINAL_BINDING, owner = "term.t1", keyBytes = mat("bind.t1"))
    }

    /** Deterministic demo key material. In production these come from a key ceremony. */
    private fun mat(label: String): ByteArray =
        Hashing.sha256(label.toByteArray()).copyOf(16)

    // ------------------------------------------------------------------ profiles and cards

    private fun profiles() {
        hsm.cards.putProfile(
            ValidationProfile(
                id = "prof.visa.pvv", method = VerifyMethod.VISA_PVV,
                verificationKeyId = "pvk.visa", pvki = 3,
                acceptedFormats = setOf(PinFormat.ISO_0, PinFormat.ISO_1, PinFormat.ISO_3, PinFormat.ISO_4),
                maxTries = 3, lockoutSeconds = 900
            )
        )
        hsm.cards.putProfile(
            ValidationProfile(
                id = "prof.ibm.offset", method = VerifyMethod.IBM_3624_OFFSET,
                verificationKeyId = "pvk.ibm",
                decimalizationTable = "0123456789012345",
                acceptedFormats = setOf(PinFormat.ISO_0, PinFormat.ISO_1, PinFormat.ISO_3),
                maxTries = 3, lockoutSeconds = 900
            )
        )
        hsm.cards.putProfile(
            ValidationProfile(
                id = "prof.aes.pvv", method = VerifyMethod.VISA_PVV,
                verificationKeyId = "pvk.visa", pvki = 4,
                acceptedFormats = setOf(PinFormat.ISO_4),
                maxTries = 3, lockoutSeconds = 900
            )
        )
    }

    private fun cards() {
        cardVisa = Card("acct-visa-001", "4539578763627189", profileId = "prof.visa.pvv",
            expiry = "2812", serviceCode = "201")
        cardOffset = Card("acct-ibm-002", "5425233430109903", profileId = "prof.ibm.offset",
            expiry = "2706", serviceCode = "201")
        cardAes = Card("acct-aes-003", "4000001234567890", profileId = "prof.aes.pvv",
            expiry = "2903", serviceCode = "201")
        hsm.cards.putCard(cardVisa)
        hsm.cards.putCard(cardOffset)
        hsm.cards.putCard(cardAes)
    }

    // ------------------------------------------------------------------ clients

    private fun clients() {
        termT1 = Client(
            id = "term.t1",
            secret = Hashing.sha256("secret:term.t1".toByteArray()),
            role = Role.TERMINAL,
            allowedKeyIds = setOf("tpk.t1", "tpk.aes.t1", "bind.t1"),
            bindingKeyId = "bind.t1",
            verifyPerSecond = 2.0, verifyBurst = 3,
            translatePerSecond = 2.0, translateBurst = 3
        )
        acquirer = Client(
            id = "acq.host",
            secret = Hashing.sha256("secret:acq.host".toByteArray()),
            role = Role.ACQUIRER,
            allowedKeyIds = setOf("tpk.t1", "zpk.acq.iss", "tpk.aes.t1", "zpk.aes.acq.iss"),
            // An acquirer host legitimately translates at volume; the meaningful per-card
            // controls are the route's hourly cap and the verification budget, not this.
            verifyPerSecond = 20.0, verifyBurst = 40,
            translatePerSecond = 500.0, translateBurst = 2000
        )
        issuer = Client(
            id = "issuer.auth",
            secret = Hashing.sha256("secret:issuer.auth".toByteArray()),
            role = Role.ISSUER,
            allowedKeyIds = setOf("zpk.acq.iss", "zpk.aes.acq.iss", "pvk.visa", "pvk.ibm", "cvk.visa"),
            verifyPerSecond = 50.0, verifyBurst = 50,
            translatePerSecond = 50.0, translateBurst = 50
        )
        officer = Client(
            id = "sec.officer",
            secret = Hashing.sha256("secret:sec.officer".toByteArray()),
            role = Role.SECURITY_OFFICER,
            allowedKeyIds = emptySet()
        )
        auditor = Client(
            id = "auditor",
            secret = Hashing.sha256("secret:auditor".toByteArray()),
            role = Role.AUDITOR,
            allowedKeyIds = emptySet()
        )
        listOf(termT1, acquirer, issuer, officer, auditor).forEach { hsm.addClient(it) }
        hsm.allowVerificationKey("pvk.visa", "issuer.auth")
        hsm.allowVerificationKey("pvk.ibm", "issuer.auth")
    }

    // ------------------------------------------------------------------ routes

    private fun routes() {
        // The normal terminal -> acquirer leg, and acquirer -> issuer leg.
        routeTpkToZpk = "route.tpk->zpk"
        hsm.addRoute(
            Route(
                id = routeTpkToZpk, fromKey = "tpk.t1", toKey = "zpk.acq.iss",
                fromFormat = PinFormat.ISO_0, toFormat = PinFormat.ISO_0,
                allowedClients = setOf("acq.host"), perHourLimit = 100_000
            )
        )
        routeZpkToTpk = "route.zpk->tpk"
        hsm.addRoute(
            Route(
                id = routeZpkToTpk, fromKey = "zpk.acq.iss", toKey = "tpk.t1",
                fromFormat = PinFormat.ISO_0, toFormat = PinFormat.ISO_0,
                allowedClients = setOf("acq.host"), perHourLimit = 100_000
            )
        )
        // AES / ISO-4 path.
        routeAesTpkToZpk = "route.aes.tpk->zpk"
        hsm.addRoute(
            Route(
                id = routeAesTpkToZpk, fromKey = "tpk.aes.t1", toKey = "zpk.aes.acq.iss",
                fromFormat = PinFormat.ISO_4, toFormat = PinFormat.ISO_4,
                allowedClients = setOf("acq.host")
            )
        )
        // Acquirer -> issuer AES leg. Both ends are AES, so the format stays ISO-4 throughout.
        routeAesAcqToIss = "route.aes.zpk->iss"
        hsm.addRoute(
            Route(
                id = routeAesAcqToIss, fromKey = "zpk.aes.acq.iss", toKey = "zpk.aes.acq.iss",
                fromFormat = PinFormat.ISO_4, toFormat = PinFormat.ISO_4,
                allowedClients = setOf("acq.host"), perHourLimit = 100_000
            )
        )
        // ISO-1 (no PAN inside) -> ISO-0, only towards the terminal serving that card, and
        // only with a terminal binding assertion. This is the "legitimate but dangerous" path.
        routeIso1ToIso0 = "route.iso1->iso0"
        hsm.addRoute(
            Route(
                id = routeIso1ToIso0, fromKey = "tpk.t1", toKey = "zpk.acq.iss",
                fromFormat = PinFormat.ISO_1, toFormat = PinFormat.ISO_0,
                allowedClients = setOf("acq.host"),
                requiresTerminalBinding = true,
                requiresTerminalSession = true
            )
        )
    }

    // ------------------------------------------------------------------ provisioning

    /** Seeds PINs for every demo card through the issuer path, exactly as a real issuer would. */
    fun provision(vararg entries: Pair<Card, String>) {
        for ((card, pin) in entries) {
            val call = signed(issuer, "POST", "/v1/pin/set",
                Wire.toJson(SetPinRequest("seed-${card.accountId}", card.accountId, pin)))
            hsm.call("POST", "/v1/pin/set", call)
            pins[card.accountId] = pin
        }
    }

    // ------------------------------------------------------------------ request helpers

    /** Signs a body for [client]; this is what an honest client integration does. */
    fun signed(client: Client, method: String, path: String, bodyJson: String): SignedCall {
        val ts = clock()
        val nonce = "n-" + RandomBytes.hex(24)
        val body = bodyJson.toByteArray(Charsets.UTF_8)
        val digest = Hashing.sha256Hex(body)
        val mac = RequestAuth.sign(client.secret, method, path, ts, nonce, body)
        return SignedCall(SignedEnvelope(client.id, ts, nonce, digest, mac), bodyJson)
    }

    /** Signs with explicitly chosen values, so an attacker can be modelled exactly. */
    fun signedRaw(
        clientId: String, timestampMs: Long, nonce: String, bodyJson: String,
        secretOverride: ByteArray? = null, macOverride: String? = null
    ): SignedCall {
        val body = bodyJson.toByteArray(Charsets.UTF_8)
        val digest = Hashing.sha256Hex(body)
        val secret = secretOverride ?: hsm.client(clientId).secret
        val mac = macOverride ?: Hashing.hmacSha256Hex(
            secret, RequestAuth.canonical("POST", "/v1/pin/translate", timestampMs, nonce, digest)
        )
        return SignedCall(SignedEnvelope(clientId, timestampMs, nonce, digest, mac), bodyJson)
    }

    fun call(client: Client, method: String, path: String, body: Any): Any {
        val json = Wire.toJson(body)
        return hsm.call(method, path, signed(client, method, path, json))
    }

    /** Opens a terminal session and returns its assertion, ready to attach to a request. */
    /** Remembers which terminal key each session was opened with. */
    private val sessionKeys = HashMap<String, String>()
    private fun sessionKeyIdOf(a: TerminalAssertion): String = sessionKeys[a.sessionId] ?: "tpk.t1"

    fun assertionFor(card: Card, terminalKeyId: String = "tpk.t1"): TerminalAssertion {
        val begin = Wire.toJson(BeginSessionRequest("sess-" + card.accountId, card.accountId, terminalKeyId))
        val resp = hsm.call("POST", "/v1/session/begin", signed(termT1, "POST", "/v1/session/begin", begin))
            as SessionResponse
        sessionKeys[resp.sessionId] = terminalKeyId
        return TerminalAssertion(termT1.id, resp.sessionId, resp.expiresAtMs, resp.bindingMac)
    }

    /**
     * Encrypts a block directly with the terminal's TPK, without calling the service.
     *
     * This models the actual threat the audit describes: an insider who controls a terminal
     * (or has lifted its key) can mint PIN blocks at will. The service's controls must hold
     * even though block production is outside its boundary. It is also why "the PIN pad is
     * trusted" is not a security argument.
     */
    fun blockUnderTpk(pin: String, format: PinFormat, card: Card, keyId: String = "tpk.t1"): String {
        val key = hsm.keys.get(keyId)
        val pinField = ccfb.hsm.pin.PinBlockCodec.pinField(format, pin)
        val pan = card.pan
        return if (format == PinFormat.ISO_4) {
            val panField = ccfb.hsm.crypto.Hex.decode(ccfb.hsm.pin.PinBlockCodec.panField4(pan))
            val a = key.encrypt(ccfb.hsm.crypto.Hex.decode(pinField))
            val b = ByteArray(16) { i -> (a[i].toInt() xor panField[i].toInt()).toByte() }
            ccfb.hsm.crypto.Hex.encode(key.encrypt(b))
        } else {
            val clear = ccfb.hsm.pin.PinBlockCodec.clearBlock(format, pinField, ccfb.hsm.pin.PinBlockCodec.panFieldOf(format, pan))
            ccfb.hsm.crypto.Hex.encode(key.encrypt(ccfb.hsm.crypto.Hex.decode(clear)))
        }
    }

    /**
     * Moves a terminal block to the issuer-side key through the legitimate acquirer route.
     * Used by the attack suite so that an attacker starts from a block they could really
     * observe on the wire (encrypted under the zone key), not from a key they cannot use.
     */
    fun translateForTest(terminalBlock: String, card: Card = cardVisa): String {
        val req = TranslateRequest(
            "tr-" + RandomBytes.hex(8), card.accountId, routeTpkToZpk, terminalBlock, PinFormat.ISO_0.name
        )
        val resp = hsm.call("POST", "/v1/pin/translate", signed(acquirer, "POST", "/v1/pin/translate", Wire.toJson(req)))
            as TranslateResponse
        return resp.pinBlock
    }

    /** A block encrypted under the acquirer/issuer zone key, ready for /v1/pin/verify. */
    fun issuerBlock(pin: String, format: PinFormat, card: Card): String {
        if (format == PinFormat.ISO_4) {
            // AES path: move from the AES terminal key to the AES zone key on the real route.
            val tpkBlock = blockUnderTpk(pin, format, card, "tpk.aes.t1")
            val req = TranslateRequest(
                "tr4-" + RandomBytes.hex(8), card.accountId, routeAesTpkToZpk, tpkBlock, PinFormat.ISO_4.name
            )
            return (hsm.call("POST", "/v1/pin/translate", signed(acquirer, "POST", "/v1/pin/translate", Wire.toJson(req)))
                as TranslateResponse).pinBlock
        }
        return translateForTest(blockUnderTpk(pin, format, card), card)
    }

    /** PIN-pad encryption through the terminal path, returning the encrypted block. */
    fun terminalBlock(card: Card, pin: String, format: PinFormat, session: TerminalAssertion? = null): String {
        // The session must name the same terminal key the block is encrypted under, so open
        // it with the format-appropriate key rather than reusing a TDEA session for AES.
        val keyId = if (format == PinFormat.ISO_4) "tpk.aes.t1" else "tpk.t1"
        // The session must name the same terminal key the block is encrypted under, so when no
        // session is supplied we open a fresh one with the format-appropriate key.
        val a = session ?: assertionFor(card, keyId)
        val sessionKeyId = if (a.sessionId.isEmpty()) keyId else sessionKeyIdOf(a)
        val req = PinPadRequest("pp-" + card.accountId, card.accountId, pin, format.name, sessionKeyId, a.sessionId)
        val resp = hsm.call("POST", "/v1/pinpad/encrypt", signed(termT1, "POST", "/v1/pinpad/encrypt", Wire.toJson(req)))
            as PinPadResponse
        return resp.pinBlock
    }
}
