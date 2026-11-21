# PIN HSM Simulator & PIN Processing Service

A Kotlin simulator of a payment HSM's PIN-handling commands, plus the PIN processing service
built on top of it. It exists to answer one question concretely:

> If an insider can issue *any* conversion request they like, can they walk a PIN out of the
> HSM one probe at a time?

The answer implemented here is **no**, and the repository contains a runnable attack suite
that demonstrates it probe by probe (`gradle attackDemo`), alongside a control experiment that
shows exactly which residual risk remains (a leaked PVV is an offline 10⁴-guess oracle).

---

## 1. What is implemented

### PIN block formats (ISO 9564)

| Format | Bits | PAN binding | Fill | Keys | Notes |
|--------|------|-------------|------|------|-------|
| ISO-0  | 64   | yes (`0000` + 12 rightmost PAN digits excl. check digit, XOR) | `F` | DES / 3DES | ANSI X9.8 / Visa-1 |
| ISO-1  | 64   | **no** | `F` | DES / 3DES | ECI-4; transaction field left empty |
| ISO-2  | 64   | **no** | `F` | DES / 3DES | offline only — refused online by profile validation |
| ISO-3  | 64   | yes (same field as ISO-0) | random `A`–`F` | DES / 3DES | |
| ISO-4  | 128  | yes (`M` + PAN, 128-bit field) | `A` then random | AES-128/192/256 | ISO 9564-1:2017; two-pass AES |

ISO-4 implements the standard's construction literally: `A = Enc(PINfield)`, `B = A XOR
PANfield`, `C = Enc(B)`. The codec works in **nibble fields**, not whole blocks, so the
service can never mistake the XOR of a Format 4 block for a plaintext PIN field.

### Verification methods

| Method | Verifier | Key | Notes |
|--------|----------|-----|-------|
| Visa PVV | 4 decimal digits | PVK (DES / 2-key 3DES) | `PAN[11 excl. check] ‖ PVKI ‖ PIN[0..3]`, decimalised |
| IBM 3624 offset | per-digit offset | PVK | natural PIN from PAN padded to 16, offset = (PIN − natural) mod 10 |
| CVV / CVV2 | 3 decimal digits | CVK (≥ 2-key 3DES) | `PAN ‖ YYMM ‖ service code`, UDK-A then CVK |

**Visa decimalisation is implemented as Visa specifies it**, not as a positional hex
substitution: emit the decimal characters in order, *then* append `A`–`F` mapped to `0`–`5`.
This is the single most commonly mis-implemented step in PVV/CVV code, and a positional
implementation silently produces wrong-but-plausible values. It is pinned by the public jPOS
vectors (`PVV 1226`, `CVV 204` and `453`) in `AlgorithmVectorsTest`.

### Supporting machinery

Key store with usage separation and an HMAC'd integrity tag; card/profile store with
integrity-tagged verification profiles; signed request envelopes (HMAC-SHA256 over
method‖path‖timestamp‖nonce‖sha256(body)); single-use nonce registry; card-scoped attempt
ledger; per-client token buckets; a cross-card probe detector; a hash-chained audit log; and a
small HTTP front end (`--serve`) whose only job is transport.

---

## 2. Why each interface is safe

Full reasoning is in [`docs/API.md`](docs/API.md). The short form:

| Endpoint | Primary control |
|----------|-----------------|
| `POST /v1/session/begin` | TERMINAL-only; the session is the *only* thing that can bind an unbound format to a card |
| `POST /v1/pinpad/encrypt` | TERMINAL-only; must present a live session for that exact card, opened by the same client |
| `POST /v1/pin/translate` | route-pinned key pair and formats (both ends must be accepted by the card profile); PAN from the card record; unbound formats require a signed terminal assertion; PIN verification keys can never be a route endpoint |
| `POST /v1/pin/verify` | verification parameters from the integrity-tagged profile; card-scoped attempt budget charged *before* comparison; uniform decline |
| `POST /v1/pin/set` | ISSUER-only provisioning; returns no verifier |
| `POST /v1/pvv/approve` | SECURITY_OFFICER mints a single-use ticket bound to account+operation |
| `POST /v1/pvv/issue` | ISSUER + officer ticket; returns only a *stored* PVV — there is no chosen-PIN oracle |
| `POST /v1/cvv/verify` | same metering as the PIN itself |
| `POST /v1/pin/unlock` | ISSUER-only, audited; needed so lockout is not a DoS, and total attempts stay visible |
| `GET /v1/status`, `GET /v1/audit` | AUDITOR / SECURITY_OFFICER only |

Four invariants carry most of the weight:

1. **Verification parameters are never request data.** A request names an account; the PVK,
   PVKI, decimalisation table, PAN pad character, accepted formats and try limits all come
   from the integrity-tagged card profile. This closes the audit's "tamper with the validation
   parameters" class outright, because there is no field to tamper with.
2. **The PAN always comes from the card record.** Format relabelling, account swapping and
   re-binding all fail because the HSM rebuilds the PAN field itself.
3. **Translation routes are data, not API surface.** A path that is not configured does not
   exist, and a route may never name a `PIN_VERIFICATION` key — so no request can ask the HSM
   to encrypt or decrypt *towards* a key whose output is a PIN verifier. Both ends of a route
   must also be formats the card's issuer accepts, so a route cannot downgrade a card.
4. **The attempt budget belongs to the card.** It is consumed at reservation time, under a
   lock, before the PIN is compared — so neither a second credential nor 24 parallel requests
   buys extra guesses.

---

## 3. The attack suite

```bash
gradle attackDemo          # prints the report
gradle test                # 60 tests, incl. the same suite as assertions
```

Results are reproduced verbatim in [`docs/ATTACKS.md`](docs/ATTACKS.md). Summary:

| ID | Attack class | Verdict |
|----|--------------|---------|
| A1 | Inject PVKI / PVK / decimalisation table / try limit into the request | BLOCKED (strict schema) |
| A2 | Rebind a captured block to another account | BLOCKED |
| A3 | Relabel a block's format to skip the PAN check | BLOCKED |
| B1 | Re-target an unbound ISO-1 block at many accounts | BLOCKED (terminal binding) |
| B2 | Strip PAN binding (ISO-0 → ISO-1) | BLOCKED (no route) |
| B3 | Use the PVK as a block cipher key | BLOCKED (route/usage rules) |
| C1 | Brute force from one client | BLOCKED (4 attempts, then lockout) |
| C2 | Distribute across three credentials | BLOCKED (card-scoped counter) |
| C3 | Race the counter with 24 threads | BLOCKED (reserve-before-compare) |
| C4 | Recover the PIN offline from a leaked PVV | **CONTROL — succeeds**, by design |
| D1 | Replay a signed request | BLOCKED (single-use nonce) |
| D2 | Forge a request / swap a field after signing | BLOCKED (body-bound MAC) |
| D3 | Use a PVK as a PIN encryption key | BLOCKED (usage separation) |
| D4 | Poison the nonce cache with unauthenticated traffic | BLOCKED (claim after MAC) |
| D5 | Probe malformed blocks for a padding oracle | BLOCKED (uniform error) |
| D6 | Present an offline ISO-2 block online | BLOCKED (profile rule) |
| D7 | Read the verifier from the database | **CONTROL — succeeds**, documented residual risk |

The two controls are not failures. They state the residual risk honestly: an API cannot stop
an insider who can read the verifier table, and a 4-digit PVV is fundamentally a weak offline
verifier. That is why disclosure is gated by dual control, never offered as an oracle, and
logged.

---

## 4. Build and run

Requires JDK 21+ (built and tested on JDK 27) and Gradle. Kotlin 2.4.21.

```bash
gradle build installDist
build/install/pin-hsm-sim/bin/pin-hsm-sim --demo      # attack report
build/install/pin-hsm-sim/bin/pin-hsm-sim --serve 8443
```

`--serve` binds to loopback only. Send the signed envelope in headers:

```
X-Client-Id, X-Timestamp-Ms, X-Nonce, X-Body-SHA256, X-MAC
```

where `X-MAC = HMAC-SHA256(secret, METHOD ‖ PATH ‖ timestampMs ‖ nonce ‖ sha256(body))`.
[`tools/http_client.py`](tools/http_client.py) is a working client.

---

## 5. Layout

```
src/main/kotlin/ccfb/hsm/
  crypto/     DES, 3DES (incl. 2-key EDE), AES, hex, decimalisation, hashing
  pin/        ISO 9564 field codec, PVV, IBM 3624, CVV
  model/      formats, profiles, cards, clients, error taxonomy
  core/       key store, card store, policy (routes/ledger/limiter/audit), request auth, Hsm
  api/        strict JSON wire types
  demo/       wired deployment: terminal, acquirer, issuer, officer, auditor
  attack/     the adversarial probe suite and its report
  cli/        HTTP front end
src/test/kotlin/ccfb/hsm/   vectors, codec, service, translation invariants
docs/                       API rationale, attack report, design notes
tools/                      example HTTP client
```

---

## 6. Deliberate simplifications

This is a simulator, and the following are knowingly not production-grade:

- Keys live in process memory; there is no tamper-responsive hardware, no key ceremony, and
  no split-knowledge loading.
- The HMAC secret for client requests is configured in the demo, not provisioned over TLS
  with mutual authentication. In production the transport would be mutually authenticated
  TLS and the MAC would be an additional, optional layer.
- The attempt ledger is in memory and is not replicated. A real deployment needs a durable,
  shared counter, or a restart becomes an attempt-budget reset.
- The audit chain is tamper-*evident*, not tamper-proof: someone with write access can drop
  the tail. Anchoring the head hash externally is what closes that.
- The 4-digit PIN itself is never made stronger by any of this. The design limits *online*
  guessing; it cannot make a 10⁴ secretspace large.
