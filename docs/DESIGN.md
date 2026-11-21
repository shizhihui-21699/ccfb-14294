# Design notes

Why the service is shaped the way it is. Each section records a decision, the alternative
that was rejected, and the failure mode the decision removes.

---

## 1. Verification parameters live in the profile, not in the request

**Decision.** `VerifyPinRequest` has `accountId`, `keyId`, `pinBlock`, `format`. It has no
field for PVK, PVKI, decimalisation table, PAN pad character, accepted formats or try limits.
Those come from `ValidationProfile`, which is HMAC-tagged with a key held outside the profile
table and re-verified on every lookup.

**Rejected.** Passing them as request fields, with an allow-list or range check. Every such
field is a knob an insider can turn, and the difference between "validated" and "not present"
is the difference between a policy bug and an impossible request.

**What it removes.** The entire "tamper with the validation parameters" attack class. There
is nothing to tamper with. A direct write to the profile table produces `POLICY_DENIED`, not a
quietly weakened verifier (probe A1; `CardStore.profile`).

---

## 2. The PAN always comes from the card record

**Decision.** Every operation resolves `accountId` → `Card` and uses `card.pan` to build the
PAN field. `TranslateRequest` has no PAN field.

**Rejected.** Accepting a PAN and checking it "matches" the card. That is an equality oracle:
a mismatch tells the attacker their guess about the block's binding is wrong.

**What it removes.** Account swapping (A2), because the recovered block fails to decode; and
format relabelling (A3), because a block relabelled from ISO-1 to ISO-0 gets a PAN XORed into
it and the resulting field is garbage.

---

## 3. Translation routes are enumerated data, never inferred

**Decision.** `Route` declares `(fromKey, toKey, fromFormat, toFormat, allowedClients,
requiresTerminalBinding, requiresTerminalSession, perHourLimit)`. `Hsm.addRoute` refuses any
route naming a `PIN_VERIFICATION` key; `translate` refuses any route id that is not in the
table and any `clientId` not in `allowedClients`.

**Rejected.** Deriving the route from the key ids in the request. That makes the request
surface equal to the key space, and the only thing between an insider and the PVK is a check
someone can forget to write.

**What it removes.** Converting *towards* a verification key (B3) — the operation whose output
is literally `PAN[11] ‖ PVKI ‖ PIN[4]` under the PVK — and any "helpful" path that nobody
reviewed (B2).

---

## 4. Unbound formats require a terminal assertion

**Decision.** ISO-1 and ISO-2 carry no PAN, so a block in those formats proves nothing about
which card it belongs to. Any operation that accepts one (`translate` with `fromFormat` in
{ISO-1, ISO-2}, or `verifyPin` with such a format) requires a `TerminalAssertion`:
`{terminalId, sessionId, expiresAtMs, mac}` where `mac = HMAC(bindingKey, sessionId‖accountId‖
expires)`, the named session is live, belongs to the same client, and names the same account.

**Rejected.** Accepting an unbound block and re-binding it to whatever `accountId` the caller
supplies. That is the classic "one ISO-1 block, many PANs" oracle: the attacker learns whether
the block is a valid PIN for an account they choose, and can search the estate for an account
whose verifier it satisfies.

**What it removes.** B1. It does not remove the *format* — ISO-1 remains available for the
legitimate use it exists for (a PIN pad that has no PAN at entry time) — it removes the
ambiguity about which card the block belongs to.

**Residual.** A compromised terminal that holds both its TPK and its binding key can mint
assertions. That is equivalent to it holding the card's PIN-pad session, which is the trust
already placed in a terminal; the service's claim is that an *acquirer-side* insider cannot
forge one.

---

## 5. The attempt budget is card-scoped and consumed at reservation time

**Decision.** `AttemptLedger` is keyed by account. `reserveAttempt` increments `pending` under
a lock and refuses once `failures + pending ≥ maxTries`. The result is recorded afterwards.
`remaining()` reports `maxTries − failures − pending`.

**Rejected (twice).** (a) A per-client counter — defeated by distributing across credentials
(C2). (b) A "check remaining, then compare" counter — defeated by concurrency, because every
thread sees the same pre-failure value (C3).

**What it removes.** Batch probing from one client (C1), distributed probing across credentials
(C2), and concurrent bursts (C3). The budget is a property of the *card*, which is the thing
being protected, not of the caller, which is the thing being varied.

**Why "pending" matters.** Without it, reservation is a no-op check and 24 parallel guesses all
get compared before any failure is recorded. With it, at most `maxTries` comparisons can ever
be in flight for a card.

---

## 6. Uniform errors, including for malformed blocks

**Decision.** Every content-dependent PIN failure is `PIN_BLOCK_INVALID`. Every verification
outcome is `DECLINE`. Internal detail (`PinBlockFormatException.message`) never leaves the
service. A malformed block is *charged an attempt* just like a wrong PIN.

**Rejected.** Distinct messages ("bad fill", "bad length", "PAN mismatch"). They read better to
an integrator and are a padding oracle to an attacker.

**What it removes.** D5. A malformed guess is not free: without charging it, "does this
ciphertext decrypt to something structurally valid?" is answerable at zero cost.

---

## 7. Nonces are per-client, bounded per client, and expire on the server clock

**Decision.** `NonceStore` keeps one bucket per client; a bucket holds at most
`perClientCapacity` entries and, when full, refuses further claims for *that client* rather
than evicting. Expiry is measured from the server clock at claim time.

**Rejected.** A single global LRU. Two defects follow from it: (a) the client-supplied
timestamp, which is attacker-chosen within the ±30 s window, would extend an entry's life to
nearly twice the lease; (b) one authenticated client flooding the cache could evict another
client's nonce and then replay that request.

**What it removes.** Both are covered by `NonceStoreTest`, including the explicit
"attacker floods, victim's nonce survives" case.

## 8. Signed envelopes bind the body, and nonces are claimed after the MAC

**Decision.** `mac = HMAC-SHA256(secret, METHOD ‖ PATH ‖ timestampMs ‖ nonce ‖ sha256(body))`,
checked in the order body-digest → timestamp → MAC → claim nonce.

**Rejected.** Signing only the URL or selected fields (a swapped `pinBlock` or `format` then
survives), and claiming the nonce before verifying the MAC (which lets unauthenticated junk
exhaust an honest client's nonce space).

**What it removes.** Forgery and post-signing mutation (D2), replay across two observations of
one plaintext (D1), and nonce-cache poisoning (D4).

---

## 9. One audit entry per call, hash-chained

**Decision.** `call()` writes exactly one entry per call. The operation deposits its detail
(key ids, formats, decision, reason) in a per-thread holder. Each entry commits to its
predecessor's hash.

**Rejected.** Per-operation logging (duplicates and inconsistent fields) and unchained logging
(an insider with write access can delete a probe).

**What it removes.** Silent removal of a probe, and silent editing of a decision — the chain
breaks at the edit point even if the attacker re-hashes forward (`ChainTamperTest`).

**Residual, stated plainly.** Truncating the tail leaves a shorter *valid* chain. Only external
anchoring of the head hash closes that, and the test that documents it
(`dropping the whole tail is not detectable by the chain alone`) is deliberately kept.

---

## 10. The PVV endpoint is an inventory lookup, never an oracle

**Decision.** `POST /v1/pvv/issue` requires `ISSUER` + a fresh `SECURITY_OFFICER` ticket whose
MAC covers `officerId‖accountId‖operation‖expiry`. It returns the PVV that provisioning
already computed. There is no field for a PIN.

**Rejected.** Computing a PVV on demand "for testing". That turns the endpoint into a
chosen-PIN oracle, and one call per guessed PIN is a complete break.

**Residual.** A disclosed PVV is an offline 10⁴-guess verifier — probe C4 demonstrates the
recovery succeeding, on purpose. Nothing at the API layer can fix a 4-digit verifier; the
mitigations are dual control, audit, and keeping the verifier out of the API's mouth.

---

## 11. ISO-4 is implemented as two passes, from fields, not from a clear block

**Decision.** `PinBlockCodec` works in nibble *fields*: `pinField(format, pin)` and
`panField4(pan)`. Format 4 is `A = Enc(PINfield); B = A XOR PANfield; C = Enc(B)`.

**Rejected.** Treating an ISO-4 block as "a 16-byte version of ISO-0" and XORing a PAN into the
ciphertext. That both breaks interop and creates a mental model in which an AES block could be
fed to a TDEA path.

**What it removes.** A whole bug class: key/format mismatch is a policy refusal
(`requireCompatible`), and the PIN field is only ever reconstructed by the format's own
inverse.

**Verified.** The PAN field for an 18-digit PAN legitimately runs past the first 16 nibbles;
the earlier 15-digit truncation was a real bug caught by the PCI supplement figure
(`AlgorithmVectorsTest > ISO-4 field layout follows the PCI supplement`).

---

## 12. Shared state is synchronized

**Decision.** `CardStore`, `KeyStore`, the session map, the verification-key allow list and the
HSM's own registries are all guarded by their instance monitor; `NonceStore` and the ledger
have their own.

**Why.** The HTTP front end serves from a thread pool. An unsynchronized `LinkedHashMap` read
concurrently with a write can throw `ConcurrentModificationException` or corrupt internally —
and a store failure inside a verification path is indistinguishable from a policy denial, so
it would be both an availability bug and a source of misleading audit entries.
`ConcurrentStoreTest` drives 60 threads across every card and asserts zero failures.

## 13. What is deliberately not defended

| Threat | Why not |
|--------|---------|
| Insider reads the card DB | The verifier is stored there; an API cannot protect what it does not exclusively hold (D7) |
| Insider holds the PVK | PVVs become computable offline; key custody is a ceremony problem |
| Compromised PIN pad | It holds its TPK and can mint blocks; the service limits what blocks buy, not who can make them |
| Someone else's client secret | Credentials are the boundary |
| JVM/host timing and memory | `MessageDigest.isEqual` everywhere, but this is not a constant-time cryptographic implementation |
| A 4-digit PIN | 10⁴ is small; the design bounds *online* guessing only |
