package ccfb.hsm

import ccfb.hsm.core.AuditLog
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Proves that the hash chain actually detects the two realistic tampering moves an insider
 * with write access to the log store would make: delete an entry, or edit one.
 */
class ChainTamperTest {

    private fun log(n: Int = 6): AuditLog {
        val l = AuditLog { 1_700_000_000_000 }
        repeat(n) { i ->
            l.append("req-$i", "client", "OP", "token", emptyList(), emptyList(), "DECISION", "", "digest-$i")
        }
        return l
    }

    @Test
    fun `deleting an entry breaks the chain`() {
        val l = log()
        assertTrue(l.verifyChain())
        l.tamperForTest { it.removeAt(2) }
        assertFalse(l.verifyChain(), "a gap must break the prevHash links")
    }

    @Test
    fun `editing an entry breaks the chain`() {
        val l = log()
        assertTrue(l.verifyChain())
        l.tamperForTest { entries ->
            val e = entries[3]
            entries[3] = e.copy(decision = "MATCH")
        }
        assertFalse(l.verifyChain(), "changing a field without re-hashing must fail")
    }

    @Test
    fun `re-hashing the tail still breaks the chain at the edit point`() {
        // A sophisticated forger edits entry 2 and recomputes hashes forward. They can only
        // do that if they can reproduce the chain function, which needs every subsequent
        // field unchanged — but the link *into* entry 2 is already wrong, so verification
        // fails before their recomputation is even reached.
        val l = log()
        l.tamperForTest { entries ->
            val e = entries[2]
            // Forge a new hash for the edited entry.
            val forgedHash = ccfb.hsm.crypto.Hashing.sha256Hex(
                listOf(
                    e.prevHash, e.seq.toString(), e.at.toString(), e.requestId, e.clientId, e.operation,
                    e.accountToken ?: "-", e.keyIds.joinToString(","), e.formats.joinToString(","),
                    "MATCH", e.reason, e.bodyDigest
                ).joinToString("\n")
            )
            entries[2] = e.copy(decision = "MATCH", hash = forgedHash)
        }
        assertFalse(l.verifyChain(), "entry 3 still commits to the original hash of entry 2")
    }

    @Test
    fun `dropping the whole tail is not detectable by the chain alone`() {
        // This is the honest limitation: truncation leaves a shorter *valid* chain.
        val l = log()
        l.tamperForTest { entries -> while (entries.size > 3) entries.removeAt(entries.size - 1) }
        assertTrue(l.verifyChain(), "truncation is why the head hash must be anchored externally")
    }
}
