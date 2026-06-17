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

It ships over **two MPP settlement rails** — one-shot `charge` and a payment-channel
`session` (vouchers) — sharing one rail-agnostic attestation layer (see
[Two payment rails](#two-payment-rails)).

**Docs:** [`PITCH.md`](./PITCH.md) (vision/strategy) ·
[`provable-harness-evaluation.md`](./provable-harness-evaluation.md) (long-form analysis) ·
[`fair-exchange-voucher-conditioning.md`](./fair-exchange-voucher-conditioning.md)
(design sketch for proof-gated voucher release).

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

## Two payment rails

The same provable-harness idea runs over **two MPP settlement rails**, because they
suit different regimes (see `provable-harness-evaluation.md` for the thesis):

| Rail | Crates | Best for |
|---|---|---|
| **charge** (one-shot 402, one tx/call) | `reseller` / `buyer` | one-off, ephemeral / cross-counterparty calls, high value per call. No capital lock-up, stateless. |
| **session** (payment channel + vouchers) | `reseller-session` / `buyer-session` | repeated calls to the *same* reseller, high-frequency / micro-amounts. Open once, pay per call with off-chain vouchers (no gas), close once. |

The **zkTLS attestation is rail-agnostic**: it binds to `receipt.reference` —
whether that's a charge tx hash or a payment-channel id — so `crates/notary` and the
verifier checks are identical for both. (Downsides of the session rail: deposit
lock-up, channel lifecycle/state, and a one-off call is *worse* than charge because
open + close = two txs for one unit of work.)

## Layout

| Crate | Role |
|---|---|
| `crates/notary` | The mock zkTLS notary: signed `TranscriptCommitment`s + verifier checks. Has unit tests. Shared by both rails. |
| `crates/mock-anthropic` | Stand-in for `api.anthropic.com`; serves a canned `POST /v1/messages`. |
| `crates/reseller` | **charge rail** — MPP-gated proxy: forwards upstream, attaches receipt + attestation. |
| `crates/buyer` | **charge rail** — pays one-shot, then verifies the proof before trusting output. |
| `crates/reseller-session` | **session rail** — payment-channel-gated proxy; per-message vouchers; same attestation. |
| `crates/buyer-session` | **session rail** — opens a channel, pays per message via vouchers, verifies each response, cuts off on fraud, closes once. |

The `mpp` crate is consumed from the sibling checkout at `../mpp-rs` (it is also
published as `mpp = "0.10"` on crates.io).

## Run the demo

Needs network access to `rpc.moderato.tempo.xyz` (Tempo testnet faucet + RPC).

### Charge rail (one-shot)

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

### Session rail (payment channel + vouchers)

Same mock upstream; swap the reseller/buyer for the session pair. The buyer opens
one channel, pays each message with an off-chain voucher, verifies every response,
and closes once.

```bash
cargo run --bin mock-anthropic          # terminal 1
cargo run --bin reseller-session        # terminal 2
cargo run --bin buyer-session           # terminal 3 (or pass your own prompts)
```

Honest run — one on-chain open, vouchers off-chain, one on-chain close:

```
  channel opened (id 0x6401…)
message 1 (model "claude-opus-4-8") — voucher cumulative 0.10 pathUSD
  [PASS] notary signature valid
  [PASS] notary key matches pinned key
  [PASS] served by api.anthropic.com
  [PASS] delivered bytes match notarized response
  [PASS] attestation bound to this payment
  ✅ verified
... (message 2, 3) ...
  channel settled: https://explore.moderato.tempo.xyz/tx/0x147b…
  result : ✅ all messages provably served by api.anthropic.com, settled in a single on-chain close.
```

Fraud run (`RESELLER_MODE=cheat-substitute cargo run --bin reseller-session`) — the
buyer detects substitution on message 1's binding check and **cuts the session off**,
so the reseller earns only the disputed tick, not the rest:

```
message 1 (model "claude-haiku-cheap-substitute") ...
  [FAIL] delivered bytes match notarized response
  ❌ proof failed — Cutting off the session: no further vouchers released to this reseller.
  result : ❌ fraud detected — session cut off after the bad message.
```

> Fair-exchange note: the discrete session pays voucher-up-front, so this is
> **bounded-loss + early-cutoff** fair exchange (the buyer loses at most the one bad
> tick and refuses the rest), not atomic deliver-then-pay. The first round-trip is
> the channel *open* (a management response, no content), so it consumes one voucher
> tick before content begins. The stronger streaming "deliver → verify → release
> voucher" interleave is Tier-1 in `fair-exchange-voucher-conditioning.md`.

## Configuration (env)

**reseller:** `RPC_URL`, `MPP_SECRET_KEY`, `PRICE` (default `0.05`),
`UPSTREAM_URL` (default `http://localhost:4000`), `UPSTREAM_HOST` (attested name,
default `api.anthropic.com`), `ANTHROPIC_API_KEY` (if set, forwards to real
Anthropic with `x-api-key` + `anthropic-version`), `NOTARY_SEED`, `RESELLER_MODE`
(`honest` | `cheat-substitute`).

**buyer:** `RESELLER_URL` (default `http://localhost:3000`), `EXPECTED_UPSTREAM`
(default `api.anthropic.com`), `NOTARY_PUBKEY` (pin out-of-band; otherwise fetched
from the reseller for demo convenience).

**reseller-session / buyer-session:** same vars as above (session reseller has no
`PRICE` — it uses a fixed per-message base-unit amount). `buyer-session` takes its
prompts as CLI args (defaults to three) and runs them all over one channel.

### Going real against Anthropic

```bash
ANTHROPIC_API_KEY=sk-ant-... UPSTREAM_URL=https://api.anthropic.com cargo run --bin reseller
```

## Known limitations (it's an MVP)

- **Notary trust is simulated** (see above) — a malicious reseller could lie to its
  own in-process notary. Real zkTLS removes that by having an independent notary
  witness the TLS session.
- **Payment happens before verification.** On the **charge** rail the buyer verifies
  *after* paying, so the proof is post-hoc evidence for dispute/slashing. The
  **session** rail improves this to *bounded-loss + early-cutoff* (lose at most one
  bad tick, then refuse the rest), but vouchers are still up-front. True
  deliver-then-pay fair exchange — release the voucher *only* against a valid proof —
  is the streaming Tier-1 in [`fair-exchange-voucher-conditioning.md`](./fair-exchange-voucher-conditioning.md).
- **No streaming**, single route (`/v1/messages`), no bond/slashing contract.
