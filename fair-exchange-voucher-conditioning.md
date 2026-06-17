# Fair Exchange: Conditioning MPP Voucher Release on a zkTLS Proof

> Design sketch — a follow-on to the MVP in this repo and to
> [`provable-harness-evaluation.md`](./provable-harness-evaluation.md). No code here,
> just the protocol, the wire shapes, and exactly where it hooks into the `mpp` SDK.
>
> **Status:** the repo now has a **discrete session rail** (`crates/reseller-session`
> / `crates/buyer-session`) — channel open, per-message vouchers, verify-each-response,
> cut-off-on-fraud, close. That delivers the *bounded-loss + early-cutoff* property
> below, but vouchers are paid **up-front** per message (the SDK's `send_with_payment`
> auto-advances the voucher before content returns). This doc describes the stronger,
> still-unbuilt version: **streaming, deliver-then-pay** — release each voucher *only
> after* verifying the proof for the bytes just delivered.

## 1. The gap this closes

The original charge MVP (`crates/reseller` + `crates/buyer`) uses the **charge**
intent: the buyer pays *once*, up front, then verifies the zkTLS attestation *after*
it has the bytes. The proof is therefore **post-hoc evidence** — useful for a dispute
or a slash, but the buyer's money is already gone. A cheating reseller still gets
paid; the buyer only learns it was cheated afterward.

The session rail (`crates/reseller-session` / `crates/buyer-session`) already improves
on this: over one channel the buyer verifies each response and **cuts the session off
on the first bad proof**, so a caught reseller earns only the disputed tick. But
because the SDK pays the voucher up-front per message, the buyer still pays for that
one bad tick — it's *bounded loss*, not *no loss*. Closing that last gap is what the
rest of this doc is about.

Fair exchange flips this: **the buyer releases value only against a valid proof, in
small increments, so neither party is ever more than one chunk out of pocket.** This
is the "condition settlement on a proof" line from the evaluation doc, made concrete.

Perfectly *atomic* fair exchange of a digital good for money is impossible without a
trusted third party (the well-known fair-exchange impossibility result). We don't
need atomicity — we need **bounded exposure**. MPP's payment channels already give us
the lever: settlement is incremental and **the buyer decides when to release each
increment**.

## 2. Why this rides on sessions, not charge

MPP session payments are Tempo payment channels (`src/protocol/methods/tempo/`):

- The buyer opens a channel once, locking a **deposit** in the escrow contract.
- Spending is a sequence of **vouchers**, each an EIP-712 signed struct:

  ```solidity
  struct Voucher { bytes32 channelId; uint128 cumulativeAmount; }
  // domain: name "Tempo Stream Channel", version "1", verifyingContract = escrow
  ```

- `cumulativeAmount` is **monotonic**: voucher #2 says "you may now claim 150 total",
  superseding #1's "100 total". The **payer (buyer) signs**; the **payee (seller)
  redeems** the highest cumulative voucher on-chain at close. The escrow enforces
  `redeemed ≤ deposit`.

The load-bearing fact: **only the buyer can produce the next voucher.** The seller
cannot advance `cumulativeAmount` itself. So if the buyer refuses to sign the next
voucher, the seller's claim is capped at the last voucher the buyer already released.

The SDK's metered SSE flow already exposes this as an explicit handshake
(`examples/session/sse`):

```
server (sse::serve)                          buyer (TempoSessionProvider)
  stream token … token …
  cost crosses accepted cumulative
  ── SseEvent::PaymentNeedVoucher ──────────▶ decides whether to pay
                                              send_voucher(channel, required_cumulative)
  ◀───────────── voucher (signed) ───────────
  resume streaming …
```

Fair exchange is one rule added to that handshake: **the buyer verifies a proof for
the bytes received so far before it signs the voucher.**

## 3. The core idea — interleave delivery, proof, and voucher

```
   reseller (payee)                                   buyer (payer)
 ───────────────────────────────────────────────────────────────────────
   stream chunk_k bytes
   notarize cumulative bytes  ──── chunk_k + attestation_k ───▶  verify attestation_k:
                                                                   • notary sig ok
                                                                   • server_name == api.anthropic.com
                                                                   • H(bytes 0..k) == committed digest
                                                                   • channelId matches
                                                                 if OK:
   redeem cap rises to A_k  ◀──── voucher(channelId, A_k) ──────   sign & send voucher for A_k
   stream chunk_{k+1} …                                          else: STOP. withhold voucher. close.
```

Set the chunk size with the channel's **`min_voucher_delta`** (the existing
`SessionMethodConfig` knob). Per chunk:

- **Buyer's max loss** = one chunk it paid for but whose proof later looks wrong → 0
  in the honest path, because it verifies *before* signing. The buyer never pays for
  an unverified chunk.
- **Seller's max loss** = one chunk it streamed before the covering voucher arrived
  = `min_voucher_delta` of value. It stops streaming the moment a voucher is overdue.

Exposure is symmetric and bounded by one tick. That is the whole game.

## 4. What the proof must bind (anti-replay)

A voucher only signs `(channelId, cumulativeAmount)` — it says nothing about *which
bytes* or *which proof*. So the binding lives in the **attestation commitment**, and
the buyer's verification policy is what couples them. Generalize the MVP's
`TranscriptCommitment` (in `crates/notary`) to a streaming, hash-chained form:

| Field | Purpose |
|---|---|
| `server_name` | origin to check (`api.anthropic.com`) |
| `channel_id` | binds the proof to *this* payment channel — no cross-channel replay |
| `tick_index` | monotonic chunk counter |
| `cumulative_response_digest` | rolling hash `H(bytes[0..k])` — binds *all* bytes so far, so an old proof can't justify a new voucher |
| `cumulative_amount` | the voucher cumulative this proof authorizes — binds price to bytes |
| `request_digest` | the prompt that was actually sent upstream |
| `timestamp` / `nonce` | freshness |

Buyer's gate before signing voucher for `required_cumulative`:

1. `attestation.verify_signature()` under the **pinned** notary key.
2. `commitment.server_name == expected_upstream`.
3. `commitment.channel_id == my_channel_id`.
4. `commitment.cumulative_response_digest == H(bytes I have actually received)`.
5. `commitment.cumulative_amount == required_cumulative`.

Only if all pass does it call `send_voucher(channel, required_cumulative)`. The
monotonic `cumulative_response_digest` + `cumulative_amount` pairing means a proof for
tick *k* can never be replayed to unlock the voucher for tick *k+1*.

## 5. Tier 1 — off-chain enforcement (no contract change)

Everything above works **today**, with only SDK-level changes. The escrow contract is
untouched; enforcement is the buyer's "don't sign unless verified" policy.

> **What's already built vs. what this section adds.** The discrete session rail in
> the repo (`reseller-session` / `buyer-session`) does the channel + per-message
> voucher + verify + cut-off loop, but pays voucher-up-front (bounded loss). The delta
> below is the *streaming, reactive-voucher* form — deliver tokens, prove, and only
> then have the buyer release the voucher — which removes even the one-tick loss.

**Reseller** (switch from `charge` to the session method — the structural change):

- Build `Mpp::create(tempo(...)).with_session_method(TempoSessionMethod::new(provider,
  store, SessionMethodConfig { escrow_contract, chain_id, min_voucher_delta }))`,
  exactly as `examples/session/sse/src/server.rs`.
- Drive streaming with `mpp::server::sse::serve(ServeOptions { store, channel_id,
  challenge_id, tick_cost, generate, poll_interval_ms })`, where `generate` is the
  upstream Anthropic SSE stream.
- **New:** wrap `generate` so that at each voucher boundary it folds the bytes into
  the rolling digest, calls `Notary::notarize(StreamTickCommitment { … })`, and emits
  the attestation **alongside** the `PaymentNeedVoucher` event (a new SSE event, e.g.
  `payment.need-voucher.proof`, or an extra field on the existing one).

**Buyer** (replace the blind `send_voucher` with a gated one):

- Same `TempoSessionProvider` open/stream loop as the SSE client.
- On the need-voucher-with-proof event, run the §4 gate. Pass → `send_voucher(...)`.
  Fail → do **not** sign; `provider.close(...)` to settle at the last verified
  cumulative and walk away. The reseller can only redeem up to that point.

**Trust model:** Tier 1 *prevents the buyer from overpaying* for unverified bytes. It
does **not** stop a buyer who signs anyway, and the notary is still trusted (and, in
this toy, co-located with the reseller — see §8). It is strictly stronger than the
MVP: loss is bounded to one tick and is refused in advance, not disputed afterward.

## 6. Tier 2 — on-chain proof-gated redemption (the oracle endgame)

Tier 1 enforces the rule on the honest buyer's side. To make it **trustless** — the
seller cannot redeem value *at all* without a valid proof — push the check into
settlement. This is the "self-verifying oracle report a contract can check" from the
evaluation doc.

Change the redeem path so the escrow (or a wrapping verifier contract) accepts a
voucher **only with a proof bound to that exact `(channelId, cumulativeAmount)`**:

```
redeem(voucher, proof):
    require verifyVoucherSig(voucher)                      // existing ECDSA check
    require proof.channelId        == voucher.channelId
    require proof.cumulativeAmount == voucher.cumulativeAmount
    require VERIFY(proof)                                  // see options below
    payout(min(voucher.cumulativeAmount, deposit))
```

`VERIFY(proof)` options, cheapest → strongest, straight from the evaluation doc's
"TEE vs zk" fork:

- **Notary-signature check** — contract holds the notary's pubkey and checks an
  ECDSA/EdDSA signature over the commitment. Cheap gas. Trust = the notary key. (Our
  toy notary maps directly onto this.)
- **TEE attestation** — verify a remote-attestation quote rooted in a hardware
  vendor. Cheap-ish, pragmatic 80/20; trust = the vendor's attestation root.
- **zk verifier** — an on-chain SNARK verifier for a real zkTLS/zkVM proof. Most
  expensive gas, smallest trust surface; reserve for high-stakes / regulated flows.

Now redemption is *itself* the verification event: an unproven (or substituted)
response yields a voucher the contract refuses to honor. The MPP receipt becomes a
report a downstream contract (a DeFi action, an insurance payout) can consume
directly. This is the maximal version and the one worth building toward where the
output triggers on-chain value.

## 7. Failure modes

| Event | Outcome |
|---|---|
| Reseller serves a substituted/cheaper model | Buyer's digest check (§4.4) fails → withholds voucher → reseller capped at last verified tick. Tier 2: voucher un-redeemable. |
| Reseller stops streaming after a voucher | Buyer simply stops; it already has the bytes it paid for. Reseller got its tick; no further claim. |
| Buyer takes a chunk then withholds the voucher | Reseller stops at one tick of exposure (`min_voucher_delta`) and closes. Same bound as any payment channel. |
| Proof for tick *k* replayed for tick *k+1* | Rejected: `cumulative_response_digest` / `cumulative_amount` differ (§4). |
| Partial/final tick | Settle at the last *fully* verified cumulative; never sign for a tick whose proof didn't cover its bytes. |

## 8. Honest limits (carried over from the evaluation doc)

- **Execution, not quality.** A passing proof shows the committed bytes really came
  from Anthropic, bound to this payment. It says nothing about whether the *answer is
  good* or the *prompt was well-formed*. Quality stays a spec/reputation problem.
- **Notary trust.** At Tier 1 (and in this repo's toy) the notary is trusted and
  co-located with the reseller, so a malicious reseller could lie to its own notary.
  Real TLSNotary fixes this with an independent MPC-TLS witness; Tier 2 moves the
  check on-chain. Note this is the same swap-in point flagged in the MVP README.
- **Proof economics gate granularity.** Per-tick proofs are the finest exposure but
  the highest overhead. Coarsen by proving every *N* ticks, or once per session, and
  accept *N* ticks of exposure. Below some stakes threshold the proof costs more than
  it protects — prove per-session or fall back to the bond-and-slash complement (§9).
- **Streaming proofs are the hard part.** Real zkTLS over SSE means committing to
  *ranges* of an ongoing transcript; TLSNotary supports range commitments, which maps
  onto the per-tick `cumulative_response_digest` here, but it is the genuinely
  load-bearing engineering, not the voucher plumbing.

## 9. Single-shot complement (when you can't interleave)

For the plain `charge` intent (no channel, one response), interleaving isn't
available, so fair exchange degrades to **bond + slash**: the reseller posts a bond;
the buyer pays; if the returned bytes fail verification the buyer submits the signed
attestation as fraud proof and slashes the bond. This is **recovery, not prevention**
— weaker than Tier 1/2, but it restores a deterrent for one-shot calls. Sessions are
preferred precisely because they make prevention possible.

## 10. Concrete delta against this repo

| File | Status / change |
|---|---|
| `crates/reseller-session`, `crates/buyer-session` | **Built** — discrete session rail: channel open → per-message vouchers → verify each response → cut off on fraud → close. Voucher-up-front (bounded loss). |
| `crates/notary` | **Pending** — add `StreamTickCommitment` (§4) + a rolling-digest helper for the streaming form; the current `TranscriptCommitment` / `Attestation` / `verify` are reused as-is by both rails. |
| reseller-session (streaming variant) | **Pending** — drive with `mpp::server::sse::serve`; wrap `generate` to notarize per voucher boundary and emit the attestation with `PaymentNeedVoucher`. |
| buyer-session (streaming variant) | **Pending** — replace the up-front voucher with the reactive §4 gate: verify, *then* `send_voucher`; `close()` on any failed check. |
| escrow/verifier contract | **Tier 2 only** — add proof-gated `redeem` (§6). Out of scope for an SDK-only change. |

Net: the discrete session rail is built and gives bounded-loss + early-cutoff. The
streaming deliver-then-pay variant (rows marked *pending*) is the honest next
milestone — still SDK-level, no chain changes. Tier 2 is the on-chain endgame, where
the proof stops being evidence and becomes the settlement condition itself.
