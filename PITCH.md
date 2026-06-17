# Provable Harness for MPP — Pitch

**Proof-carrying payments for the agent economy.**

A proxy "harness" that turns every paid AI call into a *provable* one — it does the work (querying Anthropic/OpenAI, RAG, orchestration), then bundles a cryptographic proof of **how the answer was produced** into the [MPP](https://mpp.dev) payment receipt. Agents can buy from agents without trusting them, and a smart contract can verify the result without trusting anyone.

> This is the strategy/vision doc. For the runnable MVP, see [`README.md`](./README.md). For the long-form analysis, see [`provable-harness-evaluation.md`](./provable-harness-evaluation.md).

---

## TL;DR

Machine-to-machine payment rails (MPP / HTTP 402) let agents pay agents with no signup. But **payment ≠ trust**: the buyer can't verify what it bought. We add the missing primitive — *verifiable provenance of the work itself* — by binding a `zkTLS + TEE/zkVM` proof to the payment receipt, settled atomically on-chain. The end state is **recursive**: provable harnesses sub-contract provable harnesses, and proofs fold into a single constant-size proof for the whole tree.

---

## 1 · The Problem

The agent economy is arriving: autonomous agents discovering and paying for each other's services over open payment rails, no humans in the loop. MPP makes the *payment* trustless. Nothing makes the *work* trustless.

When agent **A** pays agent **B** for a result, A has no cheap way to know B didn't:

- quietly swap in a cheap model while billing for Claude Opus — **model-substitution fraud**, the #1 fraud in model reselling;
- fabricate, cache, or staleness-serve the result;
- skip the work it claims to do (the retrieval, the multi-step reasoning).

In human markets we patch this with brands, reputation, and lawsuits. **You can't sue a wallet address.** With ephemeral counterparties and micropayments, reputation is Sybil-cheap and cold-start-broken. The result is Akerlof's *market for lemons*: buyers can't verify quality → honest providers get undercut by fakery → the market degrades to the cheapest convincing lie.

**The missing primitive is verifiable provenance of the work — not just proof of payment.**

---

## 2 · The Solution — How it works

A harness that sits inline between the buyer-agent and the AI provider, and emits a **proof bundle** alongside the answer:

```
buyer-agent ──pay via MPP──►  PROVABLE HARNESS  ──zkTLS'd call──►  api.anthropic.com
            ◄── answer + ─────                  ◄────────────────
                proof-receipt
```

The proof bundle has three parts, mapping exactly onto the structure of the work:

| Layer | Proves | Tool |
|---|---|---|
| **Boundary edges** | "These exact bytes really came from `api.anthropic.com` over TLS" | **zkTLS** (TLSNotary / Reclaim / DECO-style web proofs) |
| **Interior nodes** | "My own glue — RAG, orchestration, post-processing — ran *this exact code* on *this input*" | **TEE** (attested confidential VM) or **zkVM** |
| **Output binding** | "The bytes I sold you = a committed function of the attested upstream bytes" | hash commitments inside the interior proof |

The bundle is attached to MPP's existing `Receipt`, and **settlement is conditioned on a valid proof** (fair exchange): the session voucher only finalizes against a verifiable bundle. The buyer runs a small verifier; on-chain, a verifier contract can do the same.

**Why the binding is load-bearing:** zkTLS alone only proves you *pinged* Anthropic with *some* prompt — a dishonest harness can still sabotage the prompt or return a different answer than Claude gave. The output binding (interior proof) is what makes the proof worth money. *That's the whole game; the zkTLS leg is the easy half.*

---

## 3 · Why now

- **Payment rails exist:** MPP / x402 give agents native, signup-free settlement, on-chain (Tempo).
- **Web proofs are maturing:** zkTLS lets you prove an *uncooperative* server's response — Anthropic never has to lift a finger.
- **TEEs are everywhere:** Intel TDX, AMD SEV-SNP, NVIDIA confidential compute give cheap remote attestation today.
- **On-chain verification is live:** an MPP receipt already settles on-chain, so a proof attached to it is one step from being a smart-contract-checkable oracle report.

The pieces just became composable. Nobody has wired payment + provenance + on-chain settlement into one receipt.

---

## 4 · The MVP — *built, in this repo*

The demo in [`README.md`](./README.md) already implements the core loop end-to-end:

- **Real MPP 402 + on-chain settlement** on the Tempo `moderato` testnet (auto-faucet, no secrets).
- **Reseller-as-paywall** over an upstream API (`crates/reseller`, `mpp::proxy` + axum), forwarding to a stand-in Anthropic (`crates/mock-anthropic`, one env flip to go real).
- **An attestation bound to the payment** (`crates/notary`): the response carries a signed commitment over the upstream bytes, and the buyer (`crates/buyer`) **recomputes the digest and rejects on mismatch** — catching model-substitution fraud (`RESELLER_MODE=cheat-substitute`).
- **Two settlement rails, one rail-agnostic proof:** the same attestation runs over one-shot `charge` (`crates/reseller` / `crates/buyer`) *and* a payment-channel `session` (`crates/reseller-session` / `crates/buyer-session`) — open once, pay per message with off-chain vouchers, verify each response, close once. The proof binds to `receipt.reference` either way (charge tx hash or channel id).

This proves the thesis in miniature: *condition delivery on a proof.* It is **deliberately TEE-first / mock-notary** to be shippable — honesty about that is in the README's "real vs. toy" table. The hardening roadmap:

- **v1 — real zkTLS:** swap the in-process mock notary for an MPC-TLS prover/notary so the reseller *cannot* lie about what crossed the wire (independent witness, not self-reported digests).
- **v1 — interior proof:** run the harness in an attested confidential VM (TEE) so the *glue* — not just the boundary call — is covered, with the receipt committing `commit(req) · commit(upstream_resp) · commit(output) · attestation_quote`.
- **v2 — fair exchange:** the session rail already gives *bounded-loss + early-cutoff* (a caught reseller earns only the disputed tick); the endgame is releasing the MPP voucher *only* against a valid proof, turning post-hoc dispute evidence into atomic settlement. Design in [`fair-exchange-voucher-conditioning.md`](./fair-exchange-voucher-conditioning.md).

---

## 5 · What remains unsolved

The credibility is in naming these, not hiding them:

- **Notary trust (today).** The MVP notary is in-process and self-reported — a malicious reseller could lie to it. Real zkTLS removes that with an independent witness. *(This is the headline gap between the demo and the thesis.)*
- **Payment-before-verification.** The buyer verifies *after* paying. The session rail narrows this to bounded-loss + early-cutoff (lose one tick, refuse the rest), but vouchers are still up-front; settlement conditioned *on* the proof (deliver-then-pay) is the next step.
- **Streaming.** zkTLS over token-by-token SSE is genuinely awkward; pay-per-token + proof needs design work.
- **Proof economics.** MPC-TLS adds seconds + bandwidth; zkVM is heavier. Proofs only pencil out **above a stakes threshold** — useless on a $0.05 call, trivial on a $50 decision-grade one.
- **Trust-base trade-off.** TEE = cheap but trusts a hardware vendor's root + side-channel posture. zkVM = pure crypto but expensive. No free lunch.
- **Non-determinism.** LLM calls at temperature > 0 aren't reproducible — you can bind *this run's* bytes, but there's no canonical answer to "re-execute and check." Proof is of provenance, not of a unique correct output.
- **Execution ≠ quality.** A perfect proof shows you ran the committed pipeline honestly; whether that pipeline is *good* is still a spec/reputation problem.

---

## 6 · Further directions

- **A receipt standard.** Proof-carrying receipts as a first-class extension to MPP / x402.
- **Economic security via staking/slashing.** Providers post a bond; ship a missing/invalid proof → slashed. Turns "trust me" into skin-in-the-game.
- **Honest reputation on top of proofs.** Reputation becomes portable and Sybil-resistant when every claim is proof-backed.
- **AI outputs as on-chain oracles.** A verifier contract makes a harness's answer a first-class input to DeFi, parametric insurance, and prediction-market resolution.
- **Confidential inputs.** Buyer's private data goes through the TEE/zk so the harness never sees plaintext — verifiable *and* private.
- **Comparative proofs.** Prove "I routed to the cheapest/best of N providers," not just "I called one."

---

## 7 · The North Star — Expanding with Recursion

This is where the system stops being a proxy and becomes a fabric. The key observation:

> **The economic structure and the cryptographic structure are the same shape.** Recursion isn't an add-on — it's the native form of the system at scale.

**Economic recursion (self-similarity).** Every node in an agent market is *simultaneously* a buyer and a seller. A research agent hires a retrieval agent, which hires a summarizer agent, which hires... — each one pays its sub-contractors via MPP and is paid by its parent. The protocol is **identical at every level**: receive payment + spec → do work + verify children → emit answer + proof. A provable-harness call can be built out of provable-harness calls, arbitrarily deep.

**Cryptographic recursion (proofs verifying proofs).** This is exactly **Proof-Carrying Data (PCD)** / **Incrementally Verifiable Computation (IVC)** — a proof that attests to a distributed computation in which each node *verifies its predecessors' proofs inside its own*. Instead of the end buyer checking a linear bundle that grows with the tree, each harness **folds its children's proofs into its own** (recursive SNARKs, accumulation/folding schemes — Nova / Halo2 / Plonky2-style). The final receipt is a **single, constant-size proof attesting the entire tree** — verification cost O(1) regardless of depth or breadth.

```
                 ┌─────────────────────────────────────────┐
   end buyer  ◄──│  π_root  (one constant-size proof for    │
   pays once     │          the WHOLE tree)                 │
   verifies once └───────────────▲─────────────────────────┘
                                  │ folds children's proofs
                      ┌───────────┴───────────┐
                   π_A (research)          π_B (synthesis)
                    ▲        ▲                  ▲
                 π_A1      π_A2              π_B1
               (retrieval)(rerank)        (summarize)
                                            ▲
                                         zkTLS(Anthropic)
   ── proofs fold UPWARD ─────────────────────────────────
   ── MPP vouchers settle EACH edge, atomically ──────────
```

The two structures lock together: **MPP's receipt/voucher is the recursive settlement unit; the proof bundle is the recursive trust unit.** Recursive proofs are precisely what keep the economic vision from exploding in verification cost. The payoff is **deep, dynamic agent supply chains** where the end buyer pays once, verifies once, gets one proof covering the whole tree — and every participant down the tree is paid atomically against their slice.

**The frontier (and the honest caveat):** PCD over a *heterogeneous* trust base — folding zkTLS web-proofs, TEE quotes, and zkVM proofs into one recursive accumulator — is research-grade. Composing different trust assumptions recursively, and keeping per-hop proving cheap enough for micropayments, is the open problem that decides whether this is a product or a paper.

---

## In one line

**MPP made machines able to pay each other. This makes them able to *trust* each other — recursively, and all the way down.**
