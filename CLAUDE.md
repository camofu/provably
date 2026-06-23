# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Proof-carrying receipts for the agent economy: a reseller proxies a buyer's paid LLM call
upstream and attaches a verifiable proof of *how the result was produced*. The buyer verifies
that proof before trusting the output, catching model-substitution fraud without trusting the
seller. Settlement is real MPP on the Tempo `moderato` testnet; the transport proof is real
[TLSNotary](https://tlsnotary.org) in **proxy mode**. Read `README.md` for the full thesis.

## Build / test / run

The **core workspace** is fast and tlsn-free:

```bash
cargo build --workspace
cargo test --workspace          # the only unit tests live in provably-transport (notary.rs)
cargo test -p provably-transport attest_then_verify_roundtrips   # single test
```

The TLSNotary integration lives in **one isolated workspace** `tlsn/` (members `notary`
and `reseller`), `exclude`d from the core workspace because it pulls the alpha `tlsn`/`mpz`
MPC tree (and needs rustc ≥ 1.95, pinned to 1.96 via `tlsn/rust-toolchain.toml`). Both
members share the workspace, so `tlsn` compiles once. Build from that dir so the pin applies:

```bash
cd tlsn && cargo build            # NOT `cargo build --manifest-path …` from the root
# or a single member: cargo run -p notary   /   cargo run -p reseller
```

**The `mpp` dependency:** the workspace depends on the published `mpp = "0.10"` from
crates.io (in both the root `workspace.dependencies` and `tlsn/reseller`), so a fresh
clone builds with no sibling checkout. Maintainers developing `mpp` locally override it
with a gitignored `.cargo/config.toml` containing `paths = ["../mpp-rs"]` (cargo's
package-source override) — never commit that, or fresh clones break.

The charge-rail demo (three processes; needs a real TLS upstream + `UPSTREAM_API_KEY`, and
network to `rpc.moderato.tempo.xyz` for the testnet faucet/RPC — wallets self-fund via
`tempo_fundAddress`). Anthropic is just the example upstream:

```bash
cd tlsn/notary && UPSTREAM_HOST=api.anthropic.com cargo run   # :7047
cd tlsn/reseller && cargo run          # :3000, UPSTREAM_* from repo .env (see .env.example)
cargo run --bin buyer -- "your prompt" # core workspace
```

To demo fraud detection, restart the reseller with `RESELLER_MODE=cheat-substitute` — it sells
tampered bytes while the receipt still commits to the real upstream output, and the buyer's
verifier rejects it. (A real Anthropic API key lives in the gitignored `.env`.)

## Architecture

Two halves: a **payment/backend-agnostic proof framework** (`crates/`) and the **TLSNotary
integration + a demo buyer** that wire it to MPP settlement. The framework is split so each
axis (transport proof, interior proof, payment binding) evolves independently.

### The proof model (`provably-core`)

A harness's output is a **`HarnessReceipt`** — a DAG of `Node`s wired by `inputs` edges.
Every node carries an `output_digest` (SHA-256 hex) and a `NodeProof`:

- **`NodeProof::Leg`** = an external call, transport-attested (`LegClaim` + `LegProof`). The
  only leg proof today is `LegProof::Notary` (Ed25519 over `LegClaim::signing_message()`),
  signed by the `tlsn/notary` service after it witnesses the TLS session.
- **`NodeProof::Interior`** = the harness's own computation. The only interior proof today is
  `InteriorProof::Recompute { fn_id }` — no proof is shipped; the verifier re-runs the public
  transform and matches the digest.

`verify(receipt, expectation)` (in `provably-verifier`) returns a `Vec<Check>` (one named
pass/fail per assertion). **Everything binds by digest-equality:** delivered bytes == output
node's digest, output node's digest == attested leg response digest, recomputed digest == node
digest, plus manifest match, host allow-list, pinned notary key, and payment binding. A buyer
pins a `Manifest` (allowed hosts + manifest id) out-of-band and checks against it.

### How the TLS leg is attested (interactive-verify + re-sign)

The seller is the TLSNotary **Prover** and cannot attest a leg alone. It routes its upstream
TLS call **through the separate `tlsn/notary` process** (proxy mode): the notary proxies the
ciphertext, verifies the session + server cert, then signs the witnessed `LegClaim` with a key
the seller does not hold. The buyer pins that key and verifies `LegProof::Notary`.

This is deliberately **not** a portable zk presentation: the on-wire proof stays
`LegProof::Notary` (Ed25519), so the **buyer never depends on `tlsn`** and the verifier is
unchanged. Trade-offs, all intentional for the PoC:

- The notary is **trusted for privacy** — proxy-mode disclosure means it sees the request
  (api-key redacted) and response in plaintext. End-game: independent operator or a **TEE**.
- The buyer trusts the notary's signature (no re-checkable crypto proof). A blind notary +
  presentation would need MPC mode and a heavier buyer; that's a future fork, not the PoC.
- **Body-digest contract:** the notary digests the HTTP *body*; this only matches the bytes
  the reseller delivers when the response is identity-encoded and non-chunked. The prover
  forces `Accept-Encoding: identity`; chunked/compressed upstreams would need de-chunking.

Heavier interior backends (zkVM/inference, TEE legs, recursion) are **un-declared new enum
variants when implemented** — a non-breaking addition. Do *not* pre-declare them; design their
shape against the real backend. A sketch lives on the **`node-dag-full`** branch.

### Crate roles

| Crate | Role |
|---|---|
| `provably-core` | The IP. Types only (`LegClaim`/`LegAttestation`, `Node`/`HarnessReceipt`, `Manifest`) + `sha256_hex`. The cheap signature self-check (`LegAttestation::verify_proof`) stays here as a method on the type. |
| `provably-verifier` | The verifier: `verify(receipt, expectation) -> Vec<Check>` + `Expectation`/`Check`. Ed25519 + digest checks; heavier backend verifiers grow here so `core` stays a pure type crate. |
| `provably-transport` | The notary's Ed25519 signing identity (`Notary`). The verification side lives in `provably-verifier`. |
| `provably-prover` | Interior provers behind the `Prover` trait. `Recompute` today; zkVM/inference/TEE next. |
| `provably-mpp` | Binds a receipt to MPP settlement — three seams: `advertise()` (manifest in the 402 challenge), the `x-provably-receipt` sidecar header, and `gate()` (deliver/settle iff every check passes). Does **not** re-implement the payment flow; the `mpp` SDK owns that. |
| `tlsn/notary` (isolated) | The third-party notary: TLSNotary proxy-mode verifier that signs the witnessed `LegClaim`. |
| `tlsn/reseller` (isolated) | The seller, as the TLSNotary Prover: axum payment gate (HTTP 402) + drives the upstream call through the notary, builds the single-leg passthrough `HarnessReceipt`, returns it in `x-provably-receipt`. |
| `examples/buyer` | The paying agent / verifier. Pins the manifest + notary key, hashes the bytes served, runs `verify()`. The one kept demo. |

The node DAG is built but barely exercised: today's harness is always the 1-node passthrough.
The same types model multi-leg / multi-interior harnesses — intentional headroom, not dead code.

## Conventions

- `sha256_hex()` in `provably-core` is the one canonical digest used everywhere — don't
  introduce a second hashing convention.
- The canonical MPP `Receipt` is spec-locked, so the proof rides in the separate
  `x-provably-receipt` header and binds via `payment_reference` rather than living inside it.
- Demo wallets are ephemeral (`PrivateKeySigner::random()` + faucet) and the notary key is
  seed-derived (`Notary::from_seed`) so buyers can pin a known pubkey — both are demo
  conveniences a real deployment would replace (the notary would hold a hardware-protected key).
- Keep `tlsn` out of the core workspace. Anything depending on it goes in an isolated workspace
  (`exclude`d, own `rust-toolchain.toml`); the buyer and the proof types must stay tlsn-free.
- Payment happens *before* verification: on the charge rail the proof is post-hoc
  dispute/slashing evidence. True deliver-then-pay fair exchange is a streaming follow-up.
- The verifier replaces trust for *execution* (these bytes came from this host, unmodified,
  bound to this payment) — **not** for answer *quality*, and it can't stop indirect prompt
  injection in upstream data (only make it attributable).

## In flight

- **Next:** a `reseller-session-tlsn` prover — the session rail (one payment channel,
  per-message vouchers, close once) over the same proof layer. Its working end-to-end run
  (against real Anthropic via the notary) is the integration test for the whole stack.
