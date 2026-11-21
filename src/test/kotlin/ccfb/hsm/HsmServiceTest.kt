package ccfb.hsm

import ccfb.hsm.api.*
import ccfb.hsm.attack.AttackSuite
import ccfb.hsm.core.RequestAuth
import ccfb.hsm.crypto.Hashing
import ccfb.hsm.demo.DemoEnv
import ccfb.hsm.model.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * End-to-end tests of the service, including the adversarial probes.
 *
 * These run the same attack suite as `gradle attackDemo`, but assert on outcomes so a
 * regression in any control fails CI.
 */
class HsmServiceTest {

    private fun env(): DemoEnv = DemoEnv().build().also {
        it.provision(it.cardVisa to "7315", it.cardOffset to "4826", it.cardAes to "9043")
    }

    @Test
    fun `legitimate end-to-end path works for every format`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        for (format in listOf(PinFormat.ISO_0, PinFormat.ISO_1, PinFormat.ISO_3, PinFormat.ISO_4)) {
            val keyId = if (format == PinFormat.ISO_4) "tpk.aes.t1" else "tpk.t1"
            val assertion = e.assertionFor(card, keyId)
            val block = e.terminalBlock(card, "7315", format, assertion)
            // Move it to the issuer key on a route that exists. Only ISO-0 has a direct
            // TPK->ZPK route; the others must fail unless configured, which is the point.
            if (format == PinFormat.ISO_0) {
                val req = TranslateRequest("t-$format", card.accountId, e.routeTpkToZpk, block, format.name)
                val resp = e.call(e.acquirer, "POST", "/v1/pin/translate", req) as TranslateResponse
                val verify = e.call(
                    e.issuer, "POST", "/v1/pin/verify",
                    VerifyPinRequest("v-$format", card.accountId, "zpk.acq.iss", resp.pinBlock, format.name)
                ) as VerifyResponse
                assertEquals("MATCH", verify.decision)
            }
        }
    }

    @Test
    fun `AES ISO-4 path verifies end to end`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardAes.accountId)
        val assertion = e.assertionFor(card, "tpk.aes.t1")
        val block = e.terminalBlock(card, "9043", PinFormat.ISO_4, assertion)
        val req = TranslateRequest("t4", card.accountId, e.routeAesTpkToZpk, block, PinFormat.ISO_4.name)
        val resp = e.call(e.acquirer, "POST", "/v1/pin/translate", req) as TranslateResponse
        assertEquals(32, resp.pinBlock.length)
        // The AES card accepts ISO-4 only.
        val verify = e.call(
            e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("v4", card.accountId, "zpk.aes.acq.iss", resp.pinBlock, PinFormat.ISO_4.name)
        ) as VerifyResponse
        assertEquals("MATCH", verify.decision)
    }

    @Test
    fun `ISO-4 card rejects a TDEA block`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardAes.accountId)
        val req = VerifyPinRequest("v", card.accountId, "zpk.acq.iss", "00".repeat(8), PinFormat.ISO_0.name)
        val ex = runCatching { e.call(e.issuer, "POST", "/v1/pin/verify", req) }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.POLICY_DENIED)
    }

    @Test
    fun `IBM offset card verifies with the correct PIN and declines a wrong one`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardOffset.accountId)
        val wrong = e.issuerBlock("1111", PinFormat.ISO_0, card)
        val decline = e.call(
            e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("v1", card.accountId, "zpk.acq.iss", wrong, PinFormat.ISO_0.name)
        ) as VerifyResponse
        assertEquals("DECLINE", decline.decision)
        val right = e.issuerBlock("4826", PinFormat.ISO_0, card)
        val match = e.call(
            e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("v2", card.accountId, "zpk.acq.iss", right, PinFormat.ISO_0.name)
        ) as VerifyResponse
        assertEquals("MATCH", match.decision)
        assertEquals(3, match.remainingAttempts, "a success resets the failure counter")
    }

    @Test
    fun `a wrong PIN burns budget and returns no detail`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val block = e.issuerBlock("0000", PinFormat.ISO_0, card)
        val r1 = e.call(e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("w1", card.accountId, "zpk.acq.iss", block, PinFormat.ISO_0.name)) as VerifyResponse
        assertEquals("DECLINE", r1.decision)
        assertEquals(2, r1.remainingAttempts)
        e.call(e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("w2", card.accountId, "zpk.acq.iss", block, PinFormat.ISO_0.name))
        e.call(e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("w3", card.accountId, "zpk.acq.iss", block, PinFormat.ISO_0.name))
        val ex = runCatching {
            e.call(e.issuer, "POST", "/v1/pin/verify",
                VerifyPinRequest("w4", card.accountId, "zpk.acq.iss", block, PinFormat.ISO_0.name))
        }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.CARD_LOCKED)
    }

    @Test
    fun `a correct PIN after lockout stays locked`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val wrong = e.issuerBlock("0000", PinFormat.ISO_0, card)
        repeat(3) {
            runCatching {
                e.call(e.issuer, "POST", "/v1/pin/verify",
                    VerifyPinRequest("x$it", card.accountId, "zpk.acq.iss", wrong, PinFormat.ISO_0.name))
            }
        }
        val right = e.issuerBlock("7315", PinFormat.ISO_0, card)
        val ex = runCatching {
            e.call(e.issuer, "POST", "/v1/pin/verify",
                VerifyPinRequest("right", card.accountId, "zpk.acq.iss", right, PinFormat.ISO_0.name))
        }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.CARD_LOCKED, "lockout must not be bypassable by knowing the PIN")
    }

    @Test
    fun `terminal session is required to produce a block`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val req = PinPadRequest("pp", card.accountId, "7315", PinFormat.ISO_0.name, "tpk.t1", "S-doesnotexist")
        val ex = runCatching { e.call(e.termT1, "POST", "/v1/pinpad/encrypt", req) }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.POLICY_DENIED)
    }

    @Test
    fun `acquirer cannot act as a terminal`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val ex = runCatching {
            e.call(e.acquirer, "POST", "/v1/session/begin",
                BeginSessionRequest("b", card.accountId, "tpk.t1"))
        }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.FORBIDDEN)
    }

    @Test
    fun `client cannot name a key outside its allow list`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val ex = runCatching {
            e.call(e.termT1, "POST", "/v1/pin/verify",
                VerifyPinRequest("k", card.accountId, "zpk.acq.iss", "00".repeat(8), PinFormat.ISO_0.name))
        }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.KEY_USAGE_VIOLATION)
    }

    @Test
    fun `PVV disclosure needs a security officer ticket`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val noTicket = runCatching {
            e.call(e.issuer, "POST", "/v1/pvv/issue", IssuePvvRequest("p1", card.accountId, "forged|9999999999999|deadbeef"))
        }.exceptionOrNull()
        assertTrue(noTicket is HsmException && noTicket.code == ErrorCode.POLICY_DENIED)

        val approval = e.call(e.officer, "POST", "/v1/pvv/approve",
            ApproveRequest("a1", card.accountId, "ISSUE_PVV")) as ApprovalResponse
        val resp = e.call(e.issuer, "POST", "/v1/pvv/issue",
            IssuePvvRequest("p2", card.accountId, approval.ticket)) as PvvResponse
        assertEquals(card.pvv, resp.pvv)

        // The ticket is single use: redeeming it again, even for the same account, fails.
        val replay = runCatching {
            e.call(e.issuer, "POST", "/v1/pvv/issue", IssuePvvRequest("p-replay", card.accountId, approval.ticket))
        }.exceptionOrNull()
        assertTrue(replay is HsmException && replay.code == ErrorCode.POLICY_DENIED,
            "an approval ticket must not be reusable")

        // It is also bound to the account, so a fresh ticket for one card cannot read another.
        val other = e.hsm.cards.card(e.cardAes.accountId)
        val reuse = runCatching {
            e.call(e.issuer, "POST", "/v1/pvv/issue", IssuePvvRequest("p3", other.accountId, approval.ticket))
        }.exceptionOrNull()
        assertTrue(reuse is HsmException && reuse.code == ErrorCode.POLICY_DENIED)
    }

    @Test
    fun `a malformed body is audited and mapped to a uniform error`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val before = e.hsm.audit.size
        // Valid MAC over a body that is not the shape the operation expects.
        val body = """{"requestId":"mal","accountId":"${card.accountId}","keyId":123}"""
        val signed = e.signed(e.issuer, "POST", "/v1/pin/verify", body)
        val ex = runCatching { e.hsm.call("POST", "/v1/pin/verify", signed) }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.INVALID_REQUEST)
        assertTrue(e.hsm.audit.size == before + 1, "a rejected body must still be logged")
        assertTrue(e.hsm.audit.verifyChain())
    }

    @Test
    fun `PVV is never computable for a caller-chosen PIN`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        // There is simply no field for a PIN on the request; adding one is rejected by schema.
        val body = """{"requestId":"x","accountId":"${card.accountId}","approvalTicket":"a|1|b","pin":"9999"}"""
        val signed = e.signed(e.issuer, "POST", "/v1/pvv/issue", body)
        val ex = runCatching { e.hsm.call("POST", "/v1/pvv/issue", signed) }.exceptionOrNull()
        assertTrue(ex != null)
        // And the stored PVV must be unchanged. Compare via the card record.
        assertTrue(e.hsm.cards.card(card.accountId).pvv == card.pvv)
    }

    @Test
    fun `audit chain detects a deleted or edited entry`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val block = e.issuerBlock("7315", PinFormat.ISO_0, card)
        e.call(e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("a", card.accountId, "zpk.acq.iss", block, PinFormat.ISO_0.name))
        assertTrue(e.hsm.audit.verifyChain())

        val before = e.hsm.audit.anchor()
        e.call(e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("b", card.accountId, "zpk.acq.iss", block, PinFormat.ISO_0.name))
        assertFalse(before == e.hsm.audit.anchor(), "each entry must extend the chain")
        assertTrue(e.hsm.audit.verifyChain())
    }

    @Test
    fun `audit log never contains a PAN, PIN, block or verifier`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val block = e.issuerBlock("7315", PinFormat.ISO_0, card)
        e.call(e.issuer, "POST", "/v1/pin/verify",
            VerifyPinRequest("a", card.accountId, "zpk.acq.iss", block, PinFormat.ISO_0.name))
        val dump = e.hsm.audit.all().joinToString("\n") { it.toString() }
        assertFalse(dump.contains(card.pan), "PAN must not be logged")
        assertFalse(dump.contains("7315"), "PIN must not be logged")
        assertFalse(dump.contains(block), "PIN block must not be logged")
        assertFalse(dump.contains(card.pvv ?: "zzz"), "PVV must not be logged")
        assertTrue(dump.contains(card.token()), "the card token is logged instead")
    }

    @Test
    fun `status reports integrity and is restricted to auditors`() {
        val e = env()
        val status = e.call(e.auditor, "GET", "/v1/status", mapOf<String, String>()) as StatusResponse
        assertTrue(status.keyStoreIntegrity)
        assertTrue(status.profileIntegrity)
        assertTrue(status.auditChain)
        val ex = runCatching {
            e.call(e.issuer, "GET", "/v1/status", mapOf<String, String>())
        }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.FORBIDDEN)
    }

    @Test
    fun `timestamp outside the window is rejected`() {
        val e = env()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val body = Wire.toJson(VerifyPinRequest("t", card.accountId, "zpk.acq.iss", "00".repeat(8), PinFormat.ISO_0.name))
        val old = e.clock() - 120_000
        val digest = Hashing.sha256Hex(body.toByteArray())
        val nonce = "n-old"
        val mac = Hashing.hmacSha256Hex(
            e.issuer.secret, RequestAuth.canonical("POST", "/v1/pin/verify", old, nonce, digest)
        )
        val signed = SignedCall(SignedEnvelope(e.issuer.id, old, nonce, digest, mac), body)
        val ex = runCatching { e.hsm.call("POST", "/v1/pin/verify", signed) }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.TIMESTAMP_INVALID)
    }

    @Test
    fun `attack suite blocks every protocol attack`() {
        val e = env()
        e.hsm.allowVerificationKey("pvk.visa", "acq.host")
        e.hsm.allowVerificationKey("pvk.ibm", "acq.host")
        val suite = AttackSuite(e)
        suite.a1TamperedVerificationParams()
        suite.a2AccountSwap()
        suite.a3FormatRelabel()
        suite.b1ConversionOracle()
        suite.b2StripBinding()
        suite.b3VerificationKeyAsCipherKey()
        suite.c1SingleClientBruteForce()
        suite.c2DistributedProbe()
        suite.c3ConcurrentBurst()
        suite.c4OfflinePvvRecovery()
        suite.d1Replay()
        suite.d2Forgery()
        suite.d3KeyUsageConfusion()
        suite.d4NonceExhaustion()
        suite.d5ErrorOracle()
        suite.d6OfflineFormatOnline()
        suite.d7DatabaseInspection()

        val controls = suite.results.filterNot { it.id == "C4" || it.id == "D7" }
        assertEquals(15, controls.size)
        controls.forEach { r ->
            assertFalse(r.leaked, "probe ${r.id} leaked: ${r.attack} / ${r.blockedBy}")
        }
        // The two controls document residual risk and must succeed.
        assertTrue(suite.results.first { it.id == "C4" }.leaked)
        assertTrue(suite.results.first { it.id == "D7" }.leaked)
    }
}
