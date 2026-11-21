# API — and why each operation is safe

Every operation is reachable through `Hsm.call(method, path, signed)` and, over HTTP, through
`--serve`. The security reasoning below is about the *service*, so it holds identically for
both paths.

## 0. Common controls (apply to every operation)

### 0.1 Transport envelope

```
X-Client-Id       which provisioned client is calling
X-Timestamp-Ms    caller clock, milliseconds since epoch
X-Nonce           8–64 chars from [A-Za-z0-9_-], single use per client
X-Body-SHA256     uppercase hex SHA-256 of the exact request body bytes
X-MAC             uppercase hex HMAC-SHA256(clientSecret,
                    METHOD ‖ "\n" ‖ PATH ‖ "\n" ‖ timestampMs ‖ "\n" ‖ nonce ‖ "\n" ‖ bodySha256)
```

Verification order is deliberate:

1. recompute `sha256(body)` and compare with `X-Body-SHA256` (constant time);
2. check `|now − timestampMs| ≤ 30 s`;
3. recompute the MAC and compare (constant time);
4. **only now** claim the nonce.

**Why this is safe.** The MAC covers the body *digest*, so no field can be altered after
signing — swapping `pinBlock`, `format`, `accountId` or `routeId` breaks the MAC. The nonce is
claimed only after the MAC verifies, so an unauthenticated flood cannot exhaust an honest
client's nonce space. A request that the client did not produce cannot be made to look like
one it did.

### 0.2 Strict schema

Jackson is configured with `FAIL_ON_UNKNOWN_PROPERTIES`. A request carrying `pvki`,
`verificationKeyId`, `decimalizationTable`, `maxTries`, `pan` — any field the operation does
not declare — is rejected at parse time with `INVALID_REQUEST`, before any decryption.

**Why this is safe.** It is the difference between "the field was ignored" (which looks safe
but trains integrators to send it) and "the field does not exist". It also makes the audit
statement "no caller can choose verification parameters" mechanically true rather than a
convention.

### 0.3 Uniform errors

`ErrorResponse.message` is a fixed string per `ErrorCode`. Internal detail — "bad fill
nibble", "PIN digit above 9", "length outside profile", "PAN mismatch" — never crosses the
boundary. Every content-dependent PIN block failure is `PIN_BLOCK_INVALID`; every independent
failure is `DECLINE`.

**Why this is safe.** A distinguishable error for "decrypted fine but padding is wrong" versus
"decrypted fine and padding is right" is a padding oracle. Collapsing them removes the signal
an attacker would use to walk a ciphertext byte by byte.

### 0.4 Audit

Every call appends an entry with request id, client, operation, key *ids*, formats, account
**token** (`sha256("pan:"+pan)[0..16]`), decision, reason and body digest. Entries are
hash-chained; `verifyChain()` recomputes every link. PAN, PIN, PIN block, PVV, offset and key
material are never logged.

**Why this is safe.** Conversion attacks need many probes; probes produce audit entries. The
chain makes silent deletion or editing of an entry detectable by an auditor, and the body
digest ties an entry to the exact request. It does not prevent an insider with write access
from dropping the tail — anchoring the head hash externally is what would close that, and the
docs say so.

---

## 1. `POST /v1/session/begin`

```json
{"requestId":"...","accountId":"acct-visa-001","terminalKeyId":"tpk.t1"}
→ {"requestId":"...","sessionId":"S-...","expiresAtMs":...,"bindingMac":"..."}
```

Declares "this card is in this terminal now". Requires `TERMINAL` role, a key in the client's
allow list with usage `TERMINAL_PIN`, and an active card. TTL is 5 minutes.

**Why it is safe.** This is the *only* way to obtain a session, and a session is the only
thing that can bind a PAN-unbound format to a card. The returned `bindingMac` is
`HMAC(bindingKey, "session"‖sessionId‖accountId‖expires)` using a key whose usage is
`TERMINAL_BINDING` — a key that can never encrypt a PIN block, and which is held to the same
client allow-list rule as every other key. Live sessions are capped per client and expired
sessions are swept, so a terminal credential cannot exhaust memory by opening them.

---

## 2. `POST /v1/pinpad/encrypt`

```json
{"requestId":"...","accountId":"...","pin":"7315","format":"ISO_0",
 "terminalKeyId":"tpk.t1","sessionId":"S-..."}
→ {"requestId":"...","pinBlock":"85AD6917C0F11836","format":"ISO_0"}
```

Models the PIN pad. Requires `TERMINAL`, the same key named in a **live session owned by the
same client for the same account**, and a format the card profile accepts.

**Why it is safe.** It cannot be used as a translation: it only ever emits a block for the
card its own live session names, under the terminal's own key. It is not a security boundary
against a compromised terminal (that terminal holds the key, and can build blocks offline
anyway) — which is precisely why every *other* control must hold even though block production
is outside the service's boundary.

---

## 3. `POST /v1/pin/translate` — the operation the audit was about

```json
{"requestId":"...","accountId":"...","routeId":"route.tpk->zpk",
 "pinBlock":"...","format":"ISO_0","terminalAssertion": null}
→ {"requestId":"...","pinBlock":"...","format":"ISO_0","destinationKeyKcv":"CFA44A"}
```

The route fixes: source key, destination key, source format, destination format, allowed
clients, and whether a terminal binding/session is required. Everything else is checked
against the card record.

Controls, in order:

1. **Route allow list.** `clientId ∈ route.allowedClients`, and both key ids must be in the
   client's `allowedKeyIds`. An unconfigured path does not exist — there is no "infer the
   route from the key ids" branch to abuse.
2. **No verification key ever.** `addRoute` refuses a route whose source or destination has
   usage `PIN_VERIFICATION`. Re-checked at use.
3. **Format is the route's.** The request's `format` must equal `route.fromFormat`; a
   mismatch is `POLICY_DENIED`, not a silent reinterpretation. The block must then decode
   under that format: correct control nibble, length nibble in `4..12`, decimal PIN digits,
   correct fill. An ISO-1 block claiming to be ISO-0 fails because ISO-0's first nibble is
   consumed by the XOR and the recovered field is garbage.
4. **PAN is the card's.** `accountId` resolves to a card; the PAN field is rebuilt from that
   record. Account swapping therefore produces a block that fails to decode, and there is no
   request field in which to supply a different PAN.
5. **Unbound source formats need a terminal assertion.** If `fromFormat` has no PAN inside it
   (ISO-1, ISO-2), the caller must present `{terminalId, sessionId, expiresAtMs, mac}` where
   `mac` is the terminal's binding-key HMAC over `sessionId‖accountId‖expires`. The named
   session must be live, belong to that same client, and be for that same account. ISO-2 is
   additionally refused by profile validation.
6. **Destination formats must be accepted by the card's profile**, so a route cannot downgrade
   a card to a format its issuer does not support.

**Why it is safe against the audit's attack.** The attack needs the HSM to answer "does this
ciphertext decrypt to a valid PIN block, for *this* PAN?" for attacker-chosen PANs. Without
the terminal's binding key, the attacker cannot assert a card for an unbound block, and with a
bound block the PAN is inside the ciphertext, so the only PAN it can be valid for is its own.
The conversion is a bijection on the plaintext PIN: it changes the ciphertext, never the
search space. `TranslationInvariantTest` asserts both directions.

**What is *not* prevented, stated plainly.** A caller who legitimately holds the source key
and is allowed by the route can move a block between formats as often as the route's hourly
cap allows. That is the business function. It is safe only because the output never describes
the PIN and never approaches a verification key.

---

## 4. `POST /v1/pin/verify`

```json
{"requestId":"...","accountId":"...","keyId":"zpk.acq.iss","pinBlock":"...",
 "format":"ISO_0","terminalAssertion": null}
→ {"requestId":"...","decision":"MATCH|DECLINE","remainingAttempts":3}
```

The submitted block arrives under `keyId` (usage `PIN_ENCRYPTION` or `TERMINAL_PIN`) from the
client's allow list. The **verification** key, PVKI, decimalisation table, PAN pad character
and try limits come from the integrity-tagged profile. The attempt is reserved *before* the
PIN is compared and the result recorded after.

**Why it is safe.**

- *No parameter substitution.* There are no request fields for PVK/PVKI/table (see 0.2), and
  the profile's HMAC tag is re-verified on every lookup, so even a direct write to the profile
  table produces `POLICY_DENIED` rather than a silently weakened verifier.
- *Metered.* The ledger is keyed by **account**, so N compromised clients share one budget;
  the attempt is reserved under a lock, so concurrent requests cannot outrun it; the 4th
  failure locks the card for the profile's `lockoutSeconds`.
- *No free probes.* A malformed block is charged an attempt too, otherwise "did this decrypt
  to something structurally valid?" would be free.
- *No output.* Only `MATCH`/`DECLINE` and a remaining count. Never a PVV, offset, natural PIN
  or intermediate.

**Residual risk.** A correct `MATCH` is one bit of information, and 3 of them per lockout
window against a 10⁴ space is fine online; the risk moves entirely to *offline* verifiers
(a leaked PVV, or an offset plus the PVK). See C4/D7 in `ATTACKS.md`.

---

## 5. `POST /v1/pin/set`

```json
{"requestId":"...","accountId":"...","newPin":"7315"}
→ {"requestId":"...","decision":"UPDATED","remainingAttempts":3}
```

Issuer provisioning. `ISSUER` role, the profile's verification key in the allow list, card not
blocked. Computes and stores the PVV or offset; returns neither. Resets the failure counter.

**Why it is safe.** It is the only path that consumes a clear PIN, so it is the most tightly
scoped: one role, one account, no verifier in the response. It is audited with the account
token and the method name.

---

## 6. `POST /v1/pvv/approve` and `POST /v1/pvv/issue`

```
approve: {"requestId":"...","accountId":"...","operation":"ISSUE_PVV"}
      → {"requestId":"...","ticket":"sec.officer|<expires>|<mac>","expiresAtMs":...}

issue:   {"requestId":"...","accountId":"...","approvalTicket":"sec.officer|<expires>|<mac>"}
      → {"requestId":"...","pvv":"0200"}
```

Two-person control: a `SECURITY_OFFICER` mints a 5-minute, single-use ticket whose MAC covers
`officerId‖accountId‖operation‖expiry`; the `ISSUER` redeems it to read the **already stored**
PVV. Redemption is recorded, so "single use" is enforced rather than merely documented —
otherwise one approval would mean "disclose as often as you like for five minutes", which is
not what a second person's approval buys.

**Why it is safe — and why it is still the sharpest edge in the service.** There is no field
for a PIN, so the endpoint cannot be used as a chosen-PIN oracle: it can only return the PVV
that provisioning already computed. But a PVV is a 4-digit function of the PIN; with the PAN
(printed on the card) and the PVV, anyone can run the published algorithm offline and recover
the PIN in 10⁴ steps, with no HSM and no rate limit (C4 demonstrates exactly this, and it
succeeds by design). That is why disclosure needs dual control, why it is audited with the
card token, and why production deployments put this behind a key ceremony rather than an API.

---

## 7. `POST /v1/cvv/verify`

```json
{"requestId":"...","accountId":"...","cvv":"204"}
→ {"requestId":"...","decision":"MATCH|DECLINE","remainingAttempts":3}
```

Same economics as a 3-digit CVV: metered with the *same* card-scoped ledger, so a CVV guess
spends PIN budget. The CVK never leaves the key store, and CVVs are never returned.

---

## 8. `POST /v1/pin/unlock`

```json
{"requestId":"...","accountId":"...","reason":"cardholder identified by phone"}
→ {"requestId":"...","decision":"UNLOCKED","remainingAttempts":3}
```

`ISSUER`-only, audited. Exists because a lockout with no unlock path is a denial of service
against the cardholder. It does not reset the lifetime attempt counter, so lock/unlock cycling
remains visible to the probe detector.

---

## 9. `GET /v1/status`, `GET /v1/audit`

`AUDITOR` or `SECURITY_OFFICER` only. Status reports key-store integrity, profile integrity
and audit-chain validity, plus key metadata (id, usage, algorithm, KCV, owner) — never key
material. Audit returns the chain; a verifier can recompute every hash.

**Why it is safe.** Read-only, role-gated, and it is what makes every other guarantee
*checkable*: if the key store or a profile were tampered with out of band, the integrity flags
go false and the operator sees it.

---

## 10. Threat model and what is out of scope

**In scope** (the audit's concern): an authenticated insider with a legitimate client
credential, the ability to observe traffic, the ability to craft any well-formed request, and
the ability to call every endpoint their role allows.

**Out of scope, and must be stated as such:**

- An attacker with the client secret of a role they should not have. Credentials are the
  boundary; the service enforces roles, not intentions.
- An attacker who can read the card database. The PVV/offset is stored there; the API cannot
  protect a value it does not exclusively hold (D7).
- An attacker with the PVK. With it, PVVs are computable for any PIN, offline.
- Side channels in the JVM or the host (timing, memory). `MessageDigest.isEqual` is used for
  every comparison, but this is not a constant-time cryptographic implementation.
- A compromised PIN pad. It holds its TPK and can mint blocks; the service's job is to ensure
  that this alone does not yield the PIN.
