#!/usr/bin/env python3
"""Example client for the PIN HSM simulator's HTTP front end.

Start the service first:

    build/install/pin-hsm-sim/bin/pin-hsm-sim --serve 8443

Then:

    python3 tools/http_client.py            # runs a legitimate end-to-end flow
    python3 tools/http_client.py --attack   # runs a few probes that must be refused

The client secrets here are the demo secrets from DemoEnv; a real integration would
provision them out of band and use mutually authenticated TLS in addition to the MAC.
"""
import argparse
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request
import uuid

BASE = "http://127.0.0.1:8443"

SECRETS = {
    "term.t1": hashlib.sha256(b"secret:term.t1").digest(),
    "acq.host": hashlib.sha256(b"secret:acq.host").digest(),
    "issuer.auth": hashlib.sha256(b"secret:issuer.auth").digest(),
    "auditor": hashlib.sha256(b"secret:auditor").digest(),
}


def canonical(method, path, ts, nonce, body_digest):
    return "\n".join([method.upper(), path, str(ts), nonce, body_digest])


def call(client, method, path, obj):
    body = json.dumps(obj, separators=(",", ":")).encode()
    ts = int(time.time() * 1000)
    nonce = "n-" + uuid.uuid4().hex
    digest = hashlib.sha256(body).hexdigest().upper()
    mac = hmac.new(
        SECRETS[client],
        canonical(method, path, ts, nonce, digest).encode(),
        hashlib.sha256,
    ).hexdigest().upper()
    req = urllib.request.Request(
        BASE + path,
        data=body,
        method=method,
        headers={
            "Content-Type": "application/json",
            "X-Client-Id": client,
            "X-Timestamp-Ms": str(ts),
            "X-Nonce": nonce,
            "X-Body-SHA256": digest,
            "X-MAC": mac,
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def show(label, status, body):
    flag = "ok " if status == 200 else "err"
    print(f"[{flag}] {label:<28} HTTP {status}  {body}")


def legitimate():
    acct = "acct-visa-001"
    st, sess = call("term.t1", "POST", "/v1/session/begin",
                    {"requestId": "c1", "accountId": acct, "terminalKeyId": "tpk.t1"})
    show("begin session", st, sess)
    if st != 200:
        return

    st, pad = call("term.t1", "POST", "/v1/pinpad/encrypt",
                   {"requestId": "c2", "accountId": acct, "pin": "7315", "format": "ISO_0",
                    "terminalKeyId": "tpk.t1", "sessionId": sess["sessionId"]})
    show("pinpad encrypt", st, pad)
    if st != 200:
        return

    st, tr = call("acq.host", "POST", "/v1/pin/translate",
                  {"requestId": "c3", "accountId": acct, "routeId": "route.tpk->zpk",
                   "pinBlock": pad["pinBlock"], "format": "ISO_0"})
    show("translate TPK->ZPK", st, tr)
    if st != 200:
        return

    st, v = call("issuer.auth", "POST", "/v1/pin/verify",
                 {"requestId": "c4", "accountId": acct, "keyId": "zpk.acq.iss",
                  "pinBlock": tr["pinBlock"], "format": "ISO_0"})
    show("verify correct PIN", st, v)

    st, v2 = call("issuer.auth", "POST", "/v1/pin/verify",
                  {"requestId": "c5", "accountId": acct, "keyId": "zpk.acq.iss",
                   "pinBlock": tr["pinBlock"], "format": "ISO_1"})
    show("verify mislabelled block", st, v2)

    st, a = call("auditor", "GET", "/v1/status", {})
    show("status", st, a)


def attack():
    acct = "acct-visa-001"
    st, sess = call("term.t1", "POST", "/v1/session/begin",
                    {"requestId": "a1", "accountId": acct, "terminalKeyId": "tpk.t1"})
    st, pad = call("term.t1", "POST", "/v1/pinpad/encrypt",
                   {"requestId": "a2", "accountId": acct, "pin": "7315", "format": "ISO_0",
                    "terminalKeyId": "tpk.t1", "sessionId": sess.get("sessionId", "x")})
    block = pad.get("pinBlock", "00" * 8)

    print("Probes below must all be refused.\n")

    st, r = call("issuer.auth", "POST", "/v1/pin/verify",
                 {"requestId": "at1", "accountId": acct, "keyId": "zpk.acq.iss",
                  "pinBlock": block, "format": "ISO_0", "pvki": 9})
    show("inject PVKI", st, r)

    st, r = call("issuer.auth", "POST", "/v1/pin/verify",
                 {"requestId": "at2", "accountId": acct, "keyId": "zpk.acq.iss",
                  "pinBlock": block, "format": "ISO_0"})
    show("use TPK block as ZPK", st, r)

    st, r = call("acq.host", "POST", "/v1/pin/translate",
                 {"requestId": "at3", "accountId": acct, "routeId": "route.tpk->pvk",
                  "pinBlock": block, "format": "ISO_0"})
    show("translate to PVK", st, r)

    st, r = call("acq.host", "POST", "/v1/pin/translate",
                 {"requestId": "at4", "accountId": acct, "routeId": "route.tpk->zpk",
                  "pinBlock": block, "format": "ISO_1"})
    show("relabel ISO-0 as ISO-1", st, r)

    st, r = call("issuer.auth", "GET", "/v1/status", {})
    show("issuer reads status", st, r)

    print("\nThe last probe is a role check, not a resource check.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--attack", action="store_true")
    ap.add_argument("--base", default=None)
    args = ap.parse_args()
    if args.base:
        BASE = args.base.rstrip("/")
    try:
        attack() if args.attack else legitimate()
    except urllib.error.URLError as e:
        print(f"cannot reach {BASE}: {e}", file=sys.stderr)
        sys.exit(1)
