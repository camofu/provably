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

This repo is a working **toy** of that idea, end-to-end on the Tempo `moderato`
testnet. The zkTLS layer is a mock notary (see [what's real vs. toy](#whats-real-vs-toy)).

```
 buyer ──── pay via MPP 402 (real Tempo testnet) ───▶ reseller ──forward──▶ upstream LLM
   ▲                                                     │  (attested as api.anthropic.com)
   └──── { response · Payment-Receipt · X-Provably-Receipt } ──┘
 buyer verifies:  notary proof ✓ · pinned key ✓ · allowed host ✓
                  delivered bytes == notarized output ✓ · bound to this payment ✓
```

## Architecture

A harness's output is described by a **`HarnessReceipt`** — a DAG of nodes:

- **leg** nodes = external calls (transport-attested: the toy notary today; zkTLS/TEE
  later),
- **interior** nodes = the harness's own computation (`Recompute` today — the verifier
  re-runs a public transform; zkVM / proof-of-inference / TEE later),

wired by `inputs` (edges) and bound together by **digest-equality**. The receipt is
bound to the MPP payment via the payment reference, and the buyer checks it against a
pinned **`Manifest`** (which hosts are allowed, which harness spec). Today's toy
harness is the simplest DAG: a **single-leg passthrough** (forward one upstream call,
prove it).

The framework is split so the proof layer is payment- and backend-agnostic:

| Crate | Role |
|---|---|
| `provably-core` | The IP: `LegClaim`/`LegAttestation`, `Node`/`HarnessReceipt`, `Manifest`, and `verify()`. No payment, no transport, no proving backend. |
| `provably-transport` | Leg attesters behind an `Attester` trait — `notary` (toy) today; `zktls`/`tee` next. |
| `provably-prover` | Interior provers behind a `Prover` trait — `Recompute` today; zkVM/inference/TEE next. |
| `provably-mpp` | Binds a `HarnessReceipt` to MPP settlement: advertise the manifest in the 402 challenge, attach the bundle (`X-Provably-Receipt`), and `gate()` delivery on `verify()`. |

Examples (runnable demos, in `examples/`):

| Bin | Role |
|---|---|
| `mock-llm-api` | Stand-in for `api.anthropic.com`; serves a canned `POST /v1/messages`. |
| `reseller` / `buyer` | **charge rail** — pay one-shot, attach + verify the receipt. |
| `reseller-session` / `buyer-session` | **session rail** — one payment channel, per-message vouchers, verify each response, close once. |

The `mpp` crate is consumed from a sibling checkout at `../mpp-rs` (also published as
`mpp = "0.10"` on crates.io).

## Run the demo

Needs Rust and network access to `rpc.moderato.tempo.xyz` (testnet faucet + RPC).

```bash
cargo build --workspace
```

### Charge rail (one-shot)

```bash
cargo run --bin mock-llm-api                                   # terminal 1
cargo run --bin reseller                                       # terminal 2 (auto-funds from faucet)
cargo run --bin buyer -- "What is the Machine Payments Protocol?"   # terminal 3
```

Honest run — every check passes:

```
proof verification:
  [PASS] manifest matches
  [PASS] delivered bytes match output node
  [PASS] bound to this payment
  [PASS] node leg0 leg proof valid
  [PASS] node leg0 host allowed (api.anthropic.com)
  [PASS] node leg0 output == leg response
  [PASS] node leg0 notary key matches pinned
✅ VERIFIED — output provably served by api.anthropic.com, bound to payment 0x…
```

### Fraud detection

Restart the reseller in cheat mode — it sells tampered bytes while the receipt still
commits to the real upstream output:

```bash
RESELLER_MODE=cheat-substitute cargo run --bin reseller
cargo run --bin buyer
```

```
served model : "claude-haiku-cheap-substitute"
  [FAIL] delivered bytes match output node
❌ REJECTED — model substitution / tampering. Do not trust this output;
   dispute the payment or slash the reseller's bond.
```

### Session rail (payment channel + vouchers)

Same mock upstream; swap in the session pair. The buyer opens one channel, pays each
message with an off-chain voucher (no per-call gas), verifies every response, and
closes once.

```bash
cargo run --bin mock-llm-api          # terminal 1
cargo run --bin reseller-session      # terminal 2
cargo run --bin buyer-session         # terminal 3  (or pass your own prompts)
```

Fraud on the session rail is *bounded-loss + early-cutoff*: the buyer detects the bad
message and **stops the session**, so the reseller earns only the one disputed tick,
not the rest.

## Configuration (env)

**reseller / reseller-session:** `RPC_URL`, `MPP_SECRET_KEY`, `PRICE` (charge only),
`UPSTREAM_URL` (default `http://localhost:4000`), `UPSTREAM_HOST` (the attested name,
default `api.anthropic.com`), `ANTHROPIC_API_KEY`, `NOTARY_SEED`, `RESELLER_MODE`
(`honest` | `cheat-substitute`).

**buyer / buyer-session:** `RPC_URL`, `RESELLER_URL` (default `http://localhost:3000`),
`EXPECTED_UPSTREAM` (default `api.anthropic.com`), `NOTARY_PUBKEY` (pin out-of-band;
otherwise fetched from the reseller for demo convenience).

### Going real against Anthropic

```bash
ANTHROPIC_API_KEY=sk-ant-... UPSTREAM_URL=https://api.anthropic.com cargo run --bin reseller
```

## License

TBD.
