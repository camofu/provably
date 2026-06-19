# reseller-tlsn

The reseller from `examples/reseller`, **adapted into the TLSNotary Prover**
(proxy mode). Same payment-gated proxy in front of the LLM, but the leg is now
attested by the separate `tls-notary` process instead of self-signed.

## What changed vs. the toy reseller

| | `examples/reseller` (toy) | `reseller-tlsn` (this) |
|---|---|---|
| upstream call | reqwest | TLSNotary Prover → through `tls-notary` |
| who signs the leg | the reseller (own key) | the **notary** (key the reseller lacks) |
| forgeable by reseller | yes | no |
| upstream | any (incl. plain-HTTP mock) | **must be TLS** (no mock) |
| build | core workspace, fast | isolated, pulls `tlsn`/`mpz` |

The on-the-wire proof type is unchanged (`LegProof::Notary` + Ed25519), so the
**buyer is unchanged** — it pins the same notary pubkey + manifest and runs the
same `verify()`.

## Run

Needs the notary running and a real TLS upstream (the plain-HTTP `mock-llm-api`
cannot be notarized — there is no TLS handshake to witness).

```bash
# terminal 1: the notary
cd tls-notary && cargo run

# terminal 2: the reseller-prover (real Anthropic)
cd reseller-tlsn
ANTHROPIC_API_KEY=sk-ant-... cargo run

# terminal 3: the unchanged buyer (from the core workspace)
cargo run --bin buyer -- "your prompt"
```

The `ANTHROPIC_API_KEY` is held only by this process and is **redacted** from the
disclosed transcript (the notary never sees it). To demo fraud detection, start
this with `RESELLER_MODE=cheat-substitute`.

Env knobs: `NOTARY_ADDR` (default `127.0.0.1:7047`), `UPSTREAM_HOST` (default
`api.anthropic.com`), `PRICE`, `NOTARY_SEED` (only to expose `/notary/pubkey`),
`RPC_URL`, `MPP_SECRET_KEY`, `RESELLER_MODE`.

## Status

Compiles and serves; the end-to-end notarized path requires a running notary and
a real TLS upstream with a valid API key. The body-digest contract (identity
encoding, non-chunked) is assumed — see `tls-notary`'s note.
