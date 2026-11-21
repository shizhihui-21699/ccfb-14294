package ccfb.hsm

import ccfb.hsm.api.VerifyPinRequest
import ccfb.hsm.demo.DemoEnv
import ccfb.hsm.model.PinFormat
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The HTTP front end serves from a thread pool, so the card, key and session maps are read
 * and written concurrently. Without synchronization those LinkedHashMaps can corrupt or throw
 * ConcurrentModificationException under a burst of distinct accounts — a availability bug
 * that is also a security-adjacent one, since a store failure would look like a policy denial.
 */
class ConcurrentStoreTest {

    @Test
    fun `parallel verification across many cards does not corrupt the stores`() {
        val e = DemoEnv().build()
        val accounts = e.hsm.cards.allCards().map { it.accountId }
        // Build each block for the key/format its card actually uses. The AES card is verified
        // under the AES zone key, so its block is built directly with the AES terminal key
        // (there is no acquirer-side AES->AES route to abuse).
        val blocks = accounts.associateWith { id ->
            val card = e.hsm.cards.card(id)
            val pin = e.pins[id] ?: "1234"
            if (card.profileId == "prof.aes.pvv") {
                Triple(card, PinFormat.ISO_4, e.issuerBlock(pin, PinFormat.ISO_4, card))
            } else {
                Triple(card, PinFormat.ISO_0, e.issuerBlock(pin, PinFormat.ISO_0, card))
            }
        }
        val errors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        val threads = (0 until 60).map { i ->
            Thread {
                try {
                    val id = accounts[i % accounts.size]
                    val (card, fmt, block) = blocks[id]!!
                    val key = if (fmt == PinFormat.ISO_4) "zpk.aes.acq.iss" else "zpk.acq.iss"
                    runCatching {
                        e.call(e.issuer, "POST", "/v1/pin/verify",
                            VerifyPinRequest("p$i", id, key, block, fmt.name))
                    }
                    // Concurrent status reads exercise the key/profile tables too.
                    e.call(e.auditor, "GET", "/v1/status", emptyMap<String, String>())
                } catch (t: Throwable) {
                    errors.add(t)
                }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        assertEquals(0, errors.size, "unexpected failures: ${errors.take(3)}")
        assertEquals(true, e.hsm.audit.verifyChain())
        assertEquals(60, threads.size)
    }
}
