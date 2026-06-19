# Provably

> Proof-carrying receipts for the agent economy.

Machine payments ([MPP](https://mpp.dev) / HTTP 402) let agents pay agents with no
signup. But **payment ≠ trust**: when agent A pays agent B for a result, A can't
verify *what it bought* — B could quietly swap a cheap model for the premium one it
billed for (model-substitution fraud), fabricate the answer, or skip the work.

**Provably** attaches a verifiable **proof of how the result was produced** to the MPP
payment receipt. The seller's harness proves the response genuinely came from the
upstream it claims (e.g. `api.anthropic.com`, unmodified); the buyer **verifies that
proof before trusting the output** — catching fraud without trusting the seller.

The transport proof is real **[TLSNotary](https://tlsnotary.org)** (proxy mode): a
separate notary process witnesses the seller's TLS session to the upstream and signs
what crossed the wire. Settlement is real MPP on the Tempo `moderato` testnet.

## Architecture

A harness's output is described by a **`HarnessReceipt`** — a DAG of nodes:

- **leg** nodes = external calls, transport-attested by the notary,
- **interior** nodes = the harness's own computation (`Recompute` today — the verifier
  re-runs a public transform; zkVM / proof-of-inference / TEE later),

wired by `inputs` (edges) and bound together by **digest-equality**. The receipt is
bound to the MPP payment via the payment reference, and the buyer checks it against a
pinned **`Manifest`** (which hosts are allowed, which harness spec). Today's harness is a
two-node DAG: a notarized upstream call (`leg0`) feeding an interior **`verdict`** node —
`1` if the answer starts with "yes", else `0` — which the buyer re-runs to verify. The
sold output is the verdict; the seller ships `leg0`'s bytes alongside it so the buyer can
recompute the transform and tie the result back to the notarized digest.

### How the leg proof works (interactive-verify + re-sign)

The seller is the TLSNotary **Prover**; it cannot attest a leg alone. It routes its
upstream TLS call **through a separate `notary` process** (the `tlsn/notary` crate), which:

1. proxies the encrypted traffic to the real server (**proxy mode** — no MPC, so it's
   fast and works against TLS 1.3 servers),
2. cryptographically verifies the TLS session and the server certificate,
3. signs the witnessed `LegClaim` (Ed25519) with a key the seller does **not** hold.

The buyer pins that notary key and verifies the signature + digests. Because the seller
never holds the key and the notary really observed the bytes, the seller can't forge the
leg. The notary is *trusted for privacy* (proxy mode discloses the request/response to
it); the end-game is to run it as an independent third party or inside a **TEE**.

The framework is split so the proof layer is payment- and backend-agnostic:

| Crate | Role |
|---|---|
| `provably-core` | The IP: `LegClaim`/`LegAttestation`, `Node`/`HarnessReceipt`, `Manifest`, `sha256_hex`. Types only — no payment, transport, proving, or verification backend. |
| `provably-verifier` | The verifier: `verify()` + the `Expectation`/`Check` types (Ed25519 + digest checks). |
| `provably-transport` | The notary's Ed25519 signing identity (`Notary`); the signature is verified in `provably-verifier`. |
| `provably-prover` | Interior provers behind a `Prover` trait — `Recompute` today; zkVM/inference/TEE next. |
| `provably-mpp` | Binds a `HarnessReceipt` to MPP settlement: advertise the manifest in the 402 challenge, attach the bundle (`X-Provably-Receipt`), and `gate()` delivery on `verify()`. |

The TLSNotary integration lives in one **isolated workspace** `tlsn/` (it pulls the
alpha `tlsn`/`mpz` MPC tree, kept out of the core `cargo build --workspace` and pinned
to rustc 1.96 via `rust-toolchain.toml`; both members share it, so `tlsn` builds once):

| Crate | Role |
|---|---|
| `tlsn/notary` | The third-party notary: proxies + verifies the TLS session, then signs the `LegClaim`. |
| `tlsn/reseller` | The seller, as the TLSNotary Prover: payment gate + drives the upstream call through the notary, then runs the interior transform. |
| `examples/harness` | This seller's product logic: the public interior transform (`starts_with_yes`) both the reseller and buyer run — seller-specific, not framework. |
| `examples/buyer` | The paying agent / verifier. Pays the reseller, re-runs the interior transform, then runs `verify()` before trusting the output. |

The `mpp` crate is the published [crates.io release](https://crates.io/crates/mpp), so
a fresh clone builds with no extra checkout.

## Getting started

**Prerequisites:** Rust via [rustup](https://rustup.rs) (the `tlsn/` workspace pins
rustc 1.96 and rustup auto-installs it on first build there); an Anthropic API key; and
network access (to `api.anthropic.com` and the Tempo `moderato` testnet RPC).

```bash
git clone https://github.com/camofu/provably && cd provably

# the core framework — fast, no TLSNotary deps
cargo build --workspace

# the TLSNotary side — heavy & one-time (pulls the tlsn/mpz tree from GitHub;
# rustup auto-installs the pinned rustc 1.96)
cd tlsn && cargo build && cd ..

# configure the upstream — copy the template, then put your key in UPSTREAM_API_KEY
cp .env.example .env
```

No `mpp-rs` checkout is needed — `mpp` resolves from crates.io. (Maintainers developing
`mpp` locally can override it with a gitignored `.cargo/config.toml` containing
`paths = ["../mpp-rs"]`.)

## Run the demo

Three processes against a real TLS upstream (Anthropic here). The `tlsn/` crates run
from their own dir so the rustc-1.96 pin applies:

```bash
# 1. the notary — proxies + witnesses + signs (listens :7047)
cd tlsn/notary && UPSTREAM_HOST=api.anthropic.com cargo run

# 2. the reseller-prover — payment gate + TLSNotary Prover (listens :3000)
#    reads UPSTREAM_* from the repo's .env (copy .env.example → .env, add your key)
cd tlsn/reseller && cargo run

# 3. the buyer — pays, then verifies the proof (core workspace)
cargo run --bin buyer -- "Is the Eiffel Tower in Paris? Answer Yes or No."
```

An honest run passes every check; the buyer prints the verdict (`1`/`0`), the upstream
answer it re-ran the transform over, and `✅ VERIFIED — verdict provably computed by
\`starts_with_yes\` over the notarized api.anthropic.com answer, bound to payment 0x…`.

### Fraud detection

Restart the reseller in cheat mode — it feeds its computation a *substituted* upstream
answer (and ships those bytes), while `leg0` still commits to the **notarized** digest of
the real answer:

```bash
cd tlsn/reseller && RESELLER_MODE=cheat-substitute cargo run   # UPSTREAM_* from .env
cargo run --bin buyer
```

The verdict and receipt are internally consistent with the *fake* answer, but the buyer
catches it: the shipped leg bytes don't hash to the notary-pinned digest, so it can't
trust them as the recompute input.

```
verdict      : 0
upstream ans : "[SUBSTITUTED cheaper output — not the notarized bytes]"
  [FAIL] material leg0 matches committed digest
  [FAIL] node verdict recompute NOT re-verified (no recomputer)
❌ REJECTED — model substitution / tampering. Do not trust this output;
   dispute the payment or slash the reseller's bond.
```

## Configuration (env)

**tlsn/reseller:** `RPC_URL`, `MPP_SECRET_KEY`, `PRICE`, `NOTARY_ADDR` (default
`127.0.0.1:7047`), `UPSTREAM_HOST` (required, the attested name — e.g.
`api.anthropic.com`), `UPSTREAM_API_KEY` (held by the reseller, redacted from the
disclosed transcript), `UPSTREAM_HEADERS` (extra request headers, `"Name: Value; …"`),
`NOTARY_SEED` (only to expose `/notary/pubkey`), `RESELLER_MODE` (`honest` |
`cheat-substitute`). These are loaded from a `.env` file at the repo root (see
`.env.example`) or the process environment.

**tlsn/notary:** `NOTARY_LISTEN` (default `0.0.0.0:7047`), `UPSTREAM_HOST` (required,
e.g. `api.anthropic.com`), `UPSTREAM_PORT` (default `443`), `NOTARY_SEED`.

**buyer:** `RPC_URL`, `RESELLER_URL` (default `http://localhost:3000`),
`EXPECTED_UPSTREAM` (default `api.anthropic.com`), `NOTARY_PUBKEY` (pin out-of-band;
otherwise fetched from the reseller for demo convenience).

## Status

The charge rail (notary + reseller-prover + buyer) is built; full end-to-end validation
against real Anthropic through TLSNotary proxy mode is the current milestone. The
**session rail** (payment channel + per-message vouchers) is next — a `reseller-session-tlsn`
prover over the same proof layer.

## License

TBD.
