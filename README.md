# provable-harness-mpp

A **toy provable reseller** built on the [Machine Payments Protocol (MPP)](https://mpp.dev).

A buyer agent pays a reseller for a Claude call over MPP (HTTP 402, settled on the
Tempo testnet). The reseller forwards the request to Anthropic and returns the
response **together with a (toy) zkTLS attestation** proving the bytes genuinely
came from `api.anthropic.com`. The buyer verifies that proof before trusting the
output — so it can detect **model-substitution fraud** (being sold a cheap model's
output billed as Opus) without trusting the reseller.

This is the thesis from [`provable-harness-evaluation.md`](./provable-harness-evaluation.md)
in miniature: *condition delivery (and, in a real system, settlement) on a proof.*

```
 buyer ──── pay via MPP 402 (real Tempo testnet) ───▶ reseller ──forward──▶ mock-anthropic
   ▲                                                     │  (attested as api.anthropic.com)
   └──── { body + Payment-Receipt + X-Zktls-Attestation }┘
 buyer verifies:  notary sig ✓ · pinned key ✓ · server_name ✓
                  sha256(body) == notarized digest ✓ · attestation bound to payment tx ✓
```

## What's real vs. what's a toy

| Piece | Status |
|---|---|
| MPP 402 challenge / credential / receipt flow | **real** (`mpp` SDK) |
| On-chain settlement | **real** — Tempo `moderato` testnet, auto-faucet, no secrets |
| Reseller-as-paywall over an upstream API | **real** pattern (`mpp::proxy` + axum) |
| zkTLS notary | **mocked** — see below |
| Anthropic upstream | **mocked** by default (one env flip to go real) |

### The zkTLS part is mocked — honestly

Real zkTLS (TLSNotary / MPC-TLS) has a *notary* independently witness the TLS
session and sign a commitment over the transcript, so the prover **cannot forge**
what bytes crossed the wire. This MVP keeps that protocol's *shape* but not its
guarantee: the notary (`crates/notary`) is simply handed the request/response
digests and signs them with an Ed25519 key.

The part that survives the simplification — and is the actual point — is the
**verifier-side binding check**: the buyer recomputes the SHA-256 of the bytes it
was served and compares it to what the notary signed. Substitute a cheaper model's
output for the notarized one and the digests diverge, so the buyer catches it. That
is exactly what the `cheat-substitute` demo below shows.

**Swap-in point for real TLSNotary:** replace `Notary::notarize` with an MPC-TLS
prover/notary call and let `TranscriptCommitment` carry the real transcript
commitment. The `Attestation` envelope, header encoding, and all verifier checks
stay as-is.

## Layout

| Crate | Role |
|---|---|
| `crates/notary` | The mock zkTLS notary: signed `TranscriptCommitment`s + verifier checks. Has unit tests. |
| `crates/mock-anthropic` | Stand-in for `api.anthropic.com`; serves a canned `POST /v1/messages`. |
| `crates/reseller` | The provable harness: MPP-gated proxy that forwards upstream and attaches receipt + attestation. |
| `crates/buyer` | Paying agent: pays over MPP, then verifies the proof before trusting output. |

The `mpp` crate is consumed from the sibling checkout at `../mpp-rs` (it is also
published as `mpp = "0.10"` on crates.io).

## Run the demo

Needs network access to `rpc.moderato.tempo.xyz` (Tempo testnet faucet + RPC).

```bash
cargo build --workspace

# terminal 1 — the (mock) Anthropic upstream
cargo run --bin mock-anthropic

# terminal 2 — the reseller (funds its wallet from the testnet faucet on startup)
cargo run --bin reseller

# terminal 3 — the buyer pays and verifies
cargo run --bin buyer -- "What is the Machine Payments Protocol in one sentence?"
```

Honest run — every check passes:

```
served model : "claude-opus-4-8"
proof verification:
  [PASS] notary signature valid
  [PASS] notary key matches pinned key
  [PASS] served by api.anthropic.com
  [PASS] delivered bytes match notarized response
  [PASS] attestation bound to this payment
✅ VERIFIED — output provably served by api.anthropic.com, bound to payment 0x8779…
```

### Demonstrate fraud detection

Restart the reseller in cheat mode; it sells tampered bytes while the attestation
still commits to the real upstream response:

```bash
RESELLER_MODE=cheat-substitute cargo run --bin reseller
cargo run --bin buyer
```

```
served model : "claude-haiku-cheap-substitute"
  [FAIL] delivered bytes match notarized response
❌ REJECTED — model substitution / tampering. Do not trust this output;
   dispute the payment or slash the reseller's bond.
```

## Configuration (env)

**reseller:** `RPC_URL`, `MPP_SECRET_KEY`, `PRICE` (default `0.05`),
`UPSTREAM_URL` (default `http://localhost:4000`), `UPSTREAM_HOST` (attested name,
default `api.anthropic.com`), `ANTHROPIC_API_KEY` (if set, forwards to real
Anthropic with `x-api-key` + `anthropic-version`), `NOTARY_SEED`, `RESELLER_MODE`
(`honest` | `cheat-substitute`).

**buyer:** `RESELLER_URL` (default `http://localhost:3000`), `EXPECTED_UPSTREAM`
(default `api.anthropic.com`), `NOTARY_PUBKEY` (pin out-of-band; otherwise fetched
from the reseller for demo convenience).

### Going real against Anthropic

```bash
ANTHROPIC_API_KEY=sk-ant-... UPSTREAM_URL=https://api.anthropic.com cargo run --bin reseller
```

## Known limitations (it's an MVP)

- **Notary trust is simulated** (see above) — a malicious reseller could lie to its
  own in-process notary. Real zkTLS removes that by having an independent notary
  witness the TLS session.
- **Payment happens before verification.** The buyer verifies *after* paying, so the
  proof is post-hoc evidence for dispute/slashing. True fair-exchange (release the
  MPP voucher only against a valid proof) is the natural next step and is what the
  evaluation doc calls "conditioning settlement on a proof."
- **No streaming**, single route (`/v1/messages`), no bond/slashing contract.
