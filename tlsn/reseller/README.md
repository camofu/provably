# reseller

The seller, as the **TLSNotary Prover** (proxy mode): a payment-gated proxy in front
of the LLM whose leg is attested by the separate `notary` process rather than
self-signed. Member of the isolated `tlsn/` workspace.

## How it works

Per paid request it acts as the TLSNotary Prover: it connects to the `notary`, drives
the upstream `POST /v1/messages` through it, selectively discloses the transcript
(redacting the api-key value, and **failing closed** if it can't be located so the
key never leaks), and relays the notary-signed `LegAttestation` in `x-provably-receipt`,
bound to the MPP payment.

Because the on-the-wire proof type is just `LegProof::Notary` + Ed25519, the **buyer is
unchanged** — it pins the notary pubkey + manifest and runs the same `verify()`, never
depending on `tlsn`. The upstream **must be a real TLS server** — a plain-HTTP server
can't be notarized (no TLS handshake to witness). It is upstream-agnostic; Anthropic is
just the example below.

## Run

Needs the notary running and a real TLS upstream. Config (`UPSTREAM_*`) is read from
a `.env` file at the repo root — copy `.env.example` to `.env` and fill in your key.

```bash
# terminal 1: the notary (UPSTREAM_HOST is required; the notary does not read .env)
cd tlsn/notary && UPSTREAM_HOST=api.anthropic.com cargo run

# terminal 2: the reseller-prover (UPSTREAM_* loaded from the repo .env)
cd tlsn/reseller && cargo run

# terminal 3: the unchanged buyer (from the core workspace)
cargo run --bin buyer -- "your prompt"
```

The `UPSTREAM_API_KEY` is held only by this process and is **redacted** from the
disclosed transcript (the notary never sees it). To demo fraud detection, add
`RESELLER_MODE=cheat-substitute cargo run`.

Env knobs (from `.env` or the environment): `UPSTREAM_HOST` (required),
`UPSTREAM_API_KEY`, `UPSTREAM_HEADERS` ("Name: Value; …"), `NOTARY_ADDR` (default
`127.0.0.1:7047`), `PRICE`, `NOTARY_SEED` (only to expose `/notary/pubkey`),
`RPC_URL`, `MPP_SECRET_KEY`, `RESELLER_MODE`.

## Status

Compiles and serves; the end-to-end notarized path requires a running notary and a
real TLS upstream with a valid API key. The body-digest contract (identity encoding,
non-chunked) is assumed — see the `notary`'s note.
