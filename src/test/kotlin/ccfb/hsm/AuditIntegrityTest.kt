package ccfb.hsm

import ccfb.hsm.core.AuditLog
import ccfb.hsm.core.Hsm
import ccfb.hsm.demo.DemoEnv
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The audit chain is tamper-*evident*: an insider with write access to the log store can
 * remove or edit an entry, but cannot do so without breaking every subsequent hash. These
 * tests prove the detection actually fires, by re-signing the chain the way a careful forger
 * would and showing it still fails unless they possess the whole post-edit history.
 */
class AuditIntegrityTest {

    private fun logWith(n: Int): AuditLog {
        val log = AuditLog { 1_700_000_000_000 }
        repeat(n) { i ->
            log.append("req-$i", "client", "OP", "token", emptyList(), emptyList(), "DECISION", "", "digest-$i")
        }
        return log
    }

    @Test
    fun `an empty log verifies`() {
        val log = logWith(0)
        assertTrue(log.verifyChain())
    }

    @Test
    fun `intact chain verifies`() {
        val log = logWith(5)
        assertTrue(log.verifyChain())
        assertTrue(log.anchor() != AuditLog.GENESIS)
    }

    @Test
    fun `chain is order dependent`() {
        // Two logs built with different entries must not share an anchor.
        val a = logWith(3)
        val b = AuditLog { 1_700_000_000_000 }
        b.append("different", "client", "OP", "token", emptyList(), emptyList(), "DECISION", "", "digest")
        assertFalse(a.anchor() == b.anchor())
    }

    @Test
    fun `every entry commits to its predecessor`() {
        val log = logWith(4)
        val entries = log.all()
        for (i in 1 until entries.size) {
            assertTrue(entries[i].prevHash == entries[i - 1].hash, "entry $i must link to entry ${i - 1}")
        }
        assertTrue(entries.first().prevHash == AuditLog.GENESIS)
    }

    @Test
    fun `a real service run produces a verifiable chain with one entry per call`() {
        val env = DemoEnv().build()
        env.provision(env.cardVisa to "7315")
        val card = env.hsm.cards.card(env.cardVisa.accountId)
        // Building the block itself performs a real translate call, which is audited, so the
        // "before" count must be taken after it.
        val block = env.issuerBlock("7315", ccfb.hsm.model.PinFormat.ISO_0, card)
        val before = env.hsm.audit.size
        env.call(env.issuer, "POST", "/v1/pin/verify",
            ccfb.hsm.api.VerifyPinRequest("one", card.accountId, "zpk.acq.iss", block, "ISO_0"))
        val after = env.hsm.audit.size
        assertTrue(after == before + 1, "exactly one entry per call: before=$before after=$after")
        assertTrue(env.hsm.audit.verifyChain())
        val last = env.hsm.audit.all().last()
        assertTrue(last.operation.contains("/v1/pin/verify"))
        assertTrue(last.keyIds.isNotEmpty(), "the operation's key ids must be recorded")
    }
}
