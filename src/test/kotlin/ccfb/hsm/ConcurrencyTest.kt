package ccfb.hsm

import ccfb.hsm.api.VerifyPinRequest
import ccfb.hsm.api.VerifyResponse
import ccfb.hsm.core.AttemptLedger
import ccfb.hsm.demo.DemoEnv
import ccfb.hsm.model.ErrorCode
import ccfb.hsm.model.HsmException
import ccfb.hsm.model.PinFormat
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The attempt budget must hold under concurrency. A per-request "check then compare" would
 * let N parallel guesses all pass the check; the ledger therefore *consumes* budget at
 * reservation time, counting in-flight attempts.
 */
class ConcurrencyTest {

    @Test
    fun `ledger refuses more reservations than the budget`() {
        val ledger = AttemptLedger(maxTries = { 3 }, lockoutMs = { 1000 }, clock = { 0 })
        repeat(3) { ledger.reserveAttempt("a") }
        val ex = runCatching { ledger.reserveAttempt("a") }.exceptionOrNull()
        assertTrue(ex is HsmException && ex.code == ErrorCode.CARD_LOCKED)
        assertEquals(0, ledger.remaining("a"))
    }

    @Test
    fun `a recorded success frees the reservation`() {
        val ledger = AttemptLedger(maxTries = { 3 }, lockoutMs = { 1000 }, clock = { 0 })
        repeat(3) { ledger.reserveAttempt("a") }
        repeat(3) { ledger.recordResult("a", true) }
        assertEquals(3, ledger.remaining("a"))
        ledger.reserveAttempt("a") // must not throw
    }

    @Test
    fun `a burst admits at most the budget through the real service`() {
        val e = DemoEnv().build()
        val card = e.hsm.cards.card(e.cardVisa.accountId)
        val blocks = (0 until 40).map { i -> e.issuerBlock("%04d".format(1000 + i), PinFormat.ISO_0, card) }
        val accepted = java.util.concurrent.atomic.AtomicInteger()
        val start = java.util.concurrent.CountDownLatch(1)
        val threads = blocks.mapIndexed { i, block ->
            Thread {
                start.await()
                try {
                    val r = e.call(e.issuer, "POST", "/v1/pin/verify",
                        VerifyPinRequest("c$i", card.accountId, "zpk.acq.iss", block, "ISO_0")) as VerifyResponse
                    if (r.decision == "DECLINE" || r.decision == "MATCH") accepted.incrementAndGet()
                } catch (_: HsmException) { }
            }
        }
        threads.forEach { it.start() }
        start.countDown()
        threads.forEach { it.join() }
        assertTrue(accepted.get() <= 3, "at most 3 comparisons may happen, got ${accepted.get()}")
        assertEquals(40, threads.size)
    }
}
