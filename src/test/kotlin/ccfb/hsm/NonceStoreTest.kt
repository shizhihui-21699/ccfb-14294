package ccfb.hsm

import ccfb.hsm.core.NonceStore
import ccfb.hsm.core.RequestAuth
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Replay defence. The interesting cases are the two ways a nonce cache is usually defeated:
 * expiry driven by a client-chosen timestamp, and cache eviction by a flooding client.
 */
class NonceStoreTest {

    @Test
    fun `a nonce is single use per client`() {
        var now = 1_000_000L
        val store = NonceStore(clock = { now })
        val ts = now
        assertTrue(store.claim("c1", "nonce-aaaaaaaa", ts))
        assertFalse(store.claim("c1", "nonce-aaaaaaaa", ts))
    }

    @Test
    fun `the same nonce from a different client is independent`() {
        val now = 1_000_000L
        val store = NonceStore(clock = { now })
        assertTrue(store.claim("c1", "nonce-aaaaaaaa", now))
        assertTrue(store.claim("c2", "nonce-aaaaaaaa", now))
    }

    @Test
    fun `expiry is measured against the server clock, not the client timestamp`() {
        var now = 1_000_000L
        val store = NonceStore(clock = { now })
        // The client claims a timestamp at the far edge of the allowed skew window.
        val clientTs = now + RequestAuth.MAX_SKEW_MS
        assertTrue(store.claim("c1", "nonce-bbbbbbbb", clientTs))
        // Move past the expiry, measured from server time.
        now += RequestAuth.MAX_SKEW_MS * 2 + 1
        // Even though the client timestamp would still look "recent", the entry is gone.
        assertTrue(store.claim("c1", "nonce-bbbbbbbb", clientTs), "expired entries may be reused")
    }

    @Test
    fun `a client cannot evict another clients nonces by flooding`() {
        var now = 1_000_000L
        val store = NonceStore(perClientCapacity = 10, clock = { now })
        assertTrue(store.claim("victim", "victim-nonce-01", now))
        // Attacker floods its own bucket far past its cap.
        for (i in 0 until 50) {
            store.claim("attacker", "atk-nonce-%08d".format(i), now)
        }
        // The victim's nonce must still be known, so its request cannot be replayed.
        assertFalse(store.claim("victim", "victim-nonce-01", now))
    }

    @Test
    fun `flooding clients cannot grow memory without bound`() {
        val now = 1_000_000L
        val store = NonceStore(perClientCapacity = 10, clock = { now })
        for (i in 0 until 500) {
            store.claim("attacker", "atk-nonce-%08d".format(i), now)
        }
        assertTrue(store.size() <= 10, "per-client cap must bound total entries, got ${store.size()}")
    }

    @Test
    fun `malformed nonces are refused`() {
        val store = NonceStore(clock = { 0 })
        assertFalse(store.claim("c1", "short", 0))
        assertFalse(store.claim("c1", "bad char!", 0))
        assertFalse(store.claim("c1", "x".repeat(65), 0))
    }
}
