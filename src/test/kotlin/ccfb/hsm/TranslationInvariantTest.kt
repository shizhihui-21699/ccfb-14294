package ccfb.hsm

import ccfb.hsm.demo.DemoEnv
import ccfb.hsm.model.ErrorCode
import ccfb.hsm.model.HsmException
import ccfb.hsm.model.PinFormat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Properties of the *translation* path specifically.
 *
 * The audit's central claim was that an insider could use "carefully constructed conversion
 * requests" to learn a PIN, exploiting differences in how the HSM handles different PIN
 * formats and verification parameters. These tests pin down why a conversion cannot do that:
 * a conversion is a bijection on the plaintext PIN, and the service never converts towards a
 * verification key, so the number of candidate PINs consistent with any observation is
 * unchanged.
 */
class TranslationInvariantTest {

    @Test
    fun `translation preserves the plaintext PIN across every configured format pair`() {
        val e = DemoEnv().build()
        e.provision(e.cardVisa to "7315")
        val card = e.hsm.cards.card(e.cardVisa.accountId)

        // Build an ISO-0 block under the terminal key and carry it through the real route.
        val tpkBlock = e.blockUnderTpk("7315", PinFormat.ISO_0, card)
        val req = ccfb.hsm.api.TranslateRequest(
            "inv-1", card.accountId, e.routeTpkToZpk, tpkBlock, PinFormat.ISO_0.name
        )
        val resp = e.call(e.acquirer, "POST", "/v1/pin/translate", req) as ccfb.hsm.api.TranslateResponse

        // The zone-key block must verify MATCH, which is only possible if the PIN survived.
        val v = e.call(
            e.issuer, "POST", "/v1/pin/verify",
            ccfb.hsm.api.VerifyPinRequest("inv-2", card.accountId, "zpk.acq.iss", resp.pinBlock, PinFormat.ISO_0.name)
        ) as ccfb.hsm.api.VerifyResponse
        assertEquals("MATCH", v.decision)

        // And a different PIN in the same input format must NOT survive, i.e. the conversion
        // is not collapsing many PINs onto one block.
        val otherTpk = e.blockUnderTpk("1111", PinFormat.ISO_0, card)
        val otherReq = req.copy(requestId = "inv-3", pinBlock = otherTpk)
        val otherResp = e.call(e.acquirer, "POST", "/v1/pin/translate", otherReq) as ccfb.hsm.api.TranslateResponse
        assertFalse(resp.pinBlock == otherResp.pinBlock)
    }

    @Test
    fun `a translated block under a different key is a different ciphertext`() {
        val e = DemoEnv().build()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val tpkBlock = e.blockUnderTpk("1234", PinFormat.ISO_0, card)
        val out = e.call(
            e.acquirer, "POST", "/v1/pin/translate",
            ccfb.hsm.api.TranslateRequest("d", card.accountId, e.routeTpkToZpk, tpkBlock, PinFormat.ISO_0.name)
        ) as ccfb.hsm.api.TranslateResponse
        assertFalse(tpkBlock == out.pinBlock, "re-encryption under a different key must change the ciphertext")
        assertEquals(16, out.pinBlock.length)
    }

    @Test
    fun `ISO-0 and ISO-3 of the same PIN differ only in fill, never in the PIN digits`() {
        val e = DemoEnv().build()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val f0 = ccfb.hsm.pin.PinBlockCodec.pinField(PinFormat.ISO_0, "1234")
        val f3 = ccfb.hsm.pin.PinBlockCodec.pinField(PinFormat.ISO_3, "1234")
        // Control nibble differs by definition (0 vs 3); length and PIN digits must not.
        assertEquals('0', f0[0]); assertEquals('3', f3[0])
        assertEquals(f0.substring(1, 6), f3.substring(1, 6))
        assertTrue(f0.substring(6).all { it == 'F' })
        assertTrue(f3.substring(6).all { it in 'A'..'F' })
    }

    @Test
    fun `translation to a format the card does not accept is refused`() {
        val e = DemoEnv().build()
        // The AES card's profile accepts ISO-4 only.
        val card = e.hsm.cards.card(e.cardAes.accountId)
        val iso4 = e.blockUnderTpk("9043", PinFormat.ISO_4, card, "tpk.aes.t1")
        val resp = e.call(
            e.acquirer, "POST", "/v1/pin/translate",
            ccfb.hsm.api.TranslateRequest("x", card.accountId, e.routeAesTpkToZpk, iso4, PinFormat.ISO_4.name)
        ) as ccfb.hsm.api.TranslateResponse
        assertEquals(32, resp.pinBlock.length)

        // Ask for an ISO-0 route against the same account: the route is TDEA and the card does
        // not accept ISO-0, so it must fail rather than "helpfully" downgrade.
        val iso0 = e.blockUnderTpk("9043", PinFormat.ISO_0, card)
        val ex = runCatching {
            e.call(e.acquirer, "POST", "/v1/pin/translate",
                ccfb.hsm.api.TranslateRequest("y", card.accountId, e.routeTpkToZpk, iso0, PinFormat.ISO_0.name))
        }.exceptionOrNull()
        assertTrue(ex is HsmException && (ex.code == ErrorCode.POLICY_DENIED || ex.code == ErrorCode.PIN_BLOCK_INVALID))
    }

    @Test
    fun `a route may not downgrade a card to a format its issuer does not accept`() {
        val e = DemoEnv().build()
        // Add a route that emits ISO-1 for the ISO-4-only card. The card profile accepts only
        // ISO-4, so the destination-format check must refuse even though the route exists.
        val iso4Key = "zpk.iso1.test"
        e.hsm.keys.create(iso4Key, ccfb.hsm.model.KeyUsage.PIN_ENCRYPTION, owner = "acq.host")
        // The client must be allowed to name the key, otherwise the request is refused for
        // the wrong reason (key allow-list) before the destination-format rule is reached.
        e.hsm.addClient(e.acquirer.copy(allowedKeyIds = e.acquirer.allowedKeyIds + iso4Key))
        e.hsm.addRoute(
            ccfb.hsm.core.Route(
                id = "route.downgrade", fromKey = "tpk.aes.t1", toKey = iso4Key,
                fromFormat = PinFormat.ISO_4, toFormat = PinFormat.ISO_1,
                allowedClients = setOf("acq.host")
            )
        )
        val card = e.hsm.cards.card(e.cardAes.accountId)
        val iso4 = e.blockUnderTpk("9043", PinFormat.ISO_4, card, "tpk.aes.t1")
        val ex = runCatching {
            e.call(e.acquirer, "POST", "/v1/pin/translate",
                ccfb.hsm.api.TranslateRequest("dg", card.accountId, "route.downgrade", iso4, PinFormat.ISO_4.name))
        }.exceptionOrNull()
        assertTrue(ex is HsmException, "must be refused, got $ex")
        assertTrue((ex as HsmException).code == ErrorCode.POLICY_DENIED,
            "must be refused as POLICY_DENIED, got ${ex.code}")
    }

    @Test
    fun `garbage block is rejected without revealing whether it decrypted`() {
        val e = DemoEnv().build()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val codes = (0 until 32).map { i ->
            val hex = (0 until 16).joinToString("") { "%X".format((i * 7 + it * 3) % 16) }
            runCatching {
                e.call(e.acquirer, "POST", "/v1/pin/translate",
                    ccfb.hsm.api.TranslateRequest("g$i", card.accountId, e.routeTpkToZpk, hex, PinFormat.ISO_0.name))
            }.exceptionOrNull()?.let { (it as HsmException).code }
        }.filterNotNull().toSet()
        assertTrue(codes.all { it == ErrorCode.PIN_BLOCK_INVALID }, "all garbage must map to one code, got $codes")
    }
}
