# tls-notary

The **third-party TLSNotary notary**, running in **proxy mode** — the separate
witnessing party that makes a leg proof trustless.

In the toy (`crates/provably-transport/src/notary.rs`) the reseller signed its own
`LegClaim` with a key it controlled, so "verify the proof" really meant "trust the
reseller." Here the reseller becomes the TLSNotary **Prover** and must route its
upstream TLS call **through this process**, which:

1. proxies the encrypted traffic between the prover and the real server
   (**proxy mode**: no MPC, so it's fast and works against TLS 1.3 servers),
2. cryptographically verifies the TLS session and the server certificate,
3. signs the witnessed `LegClaim` with a key the reseller does **not** hold.

The buyer pins *this* notary's public key. Because the prover never holds the key
and this process actually observed the bytes on the wire, the reseller can no
longer forge a leg.

## Architecture & trust model

This is **interactive-verify + re-sign**, not a portable zk presentation. The
notary verifies the TLS session live and signs a `LegClaim`; the buyer then trusts
that signature and never pulls in `tlsn`/`mpz`. The cost is explicit: the buyer
holds **no re-checkable cryptographic proof** — TLS/cert verification happens once,
here, and cannot be re-run by the buyer or a smart contract. That's the classic
notary trust model; fine for a PoC, a genuine downgrade from a presentation.

**What the notary sees:** during live proxying, only **ciphertext** (no session
keys, can't decrypt). But in the disclosure phase the prover opens selected
plaintext to the verifier, and because this notary digests the request/response
**bodies**, the prover must disclose them — so the notary **does see the prompt and
the LLM response in plaintext**. It is therefore *trusted for privacy*, not blind.
A notary that stays blind to plaintext (signing over commitments it cannot read)
is specifically what MPC + presentation buys.

The end-game is to run this as an **independent third party** or inside a **TEE**;
for the PoC we operate it ourselves, but always as a **separate process with its
own key**, which is what preserves the guarantee against the reseller. Co-locating
it inside the reseller would rebuild the toy.

## Build & run

It depends on the alpha `tlsn` crate (the whole MPC/`mpz` tree), so it is an
**isolated workspace**, excluded from the parent `cargo build --workspace`. It also
requires rustc ≥ 1.95 (alpha `mpz`), pinned via `rust-toolchain.toml` — which
`rustup` only honors from this directory, so **`cd` in first** (a `--manifest-path`
build from the repo root would use the parent's older default toolchain and fail):

```bash
cd tls-notary
cargo run
```

Env knobs:

| var | default | meaning |
|---|---|---|
| `NOTARY_LISTEN` | `0.0.0.0:7047` | address the prover (reseller) connects to |
| `UPSTREAM_HOST` | `api.anthropic.com` | server to proxy to and attest |
| `UPSTREAM_PORT` | `443` | server port |
| `NOTARY_SEED` | `demo-notary-key` | deterministic notary key seed (buyer pins the derived pubkey) |

## Status

The notary side is complete: it verifies a proxy-mode session and returns a
signed `LegAttestation`. The **prover** side (adapting the reseller to drive its
upstream call through this notary) and the buyer-side verification of the new
backend are the next integration steps.
