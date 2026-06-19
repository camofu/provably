//! `provably-mpp` — the thin convention layer binding a [`HarnessReceipt`] to MPP
//! settlement. It deliberately does *not* re-implement the payment flow (the `mpp`
//! SDK owns that); it provides the three seams we verified against `mpp-rs`:
//!
//! 1. [`advertise`] — a `methodDetails` blob announcing, in the 402 challenge, that
//!    this endpoint returns a proof-carrying receipt (MPP's blessed extension point).
//! 2. [`PROVABLY_RECEIPT_HEADER`] — the sidecar header the bundle rides in, beside
//!    the standard `Payment-Receipt` (the canonical `Receipt` is spec-locked, so the
//!    proof can't live inside it — it's bound to it via `payment_reference`).
//! 3. [`gate`] — condition delivery/settlement on `provably_verifier::verify` passing.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use provably_core::{HarnessReceipt, Manifest, VerifyError};
use provably_verifier::{verify, Expectation};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Response header carrying the base64url-encoded [`HarnessReceipt`] bundle.
pub const PROVABLY_RECEIPT_HEADER: &str = "x-provably-receipt";

/// Response header carrying the intermediate node outputs the buyer needs to *re-run*
/// interior (`Recompute`) nodes. A notary leg attests only the response *digest*, so the
/// actual leg bytes must travel here for the buyer to recompute the transform over them
/// and tie the result back to the notarized digest. (A real zk/TEE interior proof would
/// not need this — the prover would ship a proof instead of the inputs.)
pub const PROVABLY_MATERIALS_HEADER: &str = "x-provably-materials";

/// Encode `node_id -> output bytes` for [`PROVABLY_MATERIALS_HEADER`]
/// (base64url(JSON{ id: base64url(bytes) })).
pub fn materials_to_header(materials: &BTreeMap<String, Vec<u8>>) -> String {
    let encoded: BTreeMap<&String, String> = materials
        .iter()
        .map(|(id, bytes)| (id, URL_SAFE_NO_PAD.encode(bytes)))
        .collect();
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&encoded).expect("materials serialize"))
}

/// Decode the materials header produced by [`materials_to_header`].
pub fn materials_from_header(value: &str) -> Result<BTreeMap<String, Vec<u8>>, VerifyError> {
    let json = URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|_| VerifyError::Malformed("base64"))?;
    let encoded: BTreeMap<String, String> =
        serde_json::from_slice(&json).map_err(|_| VerifyError::Malformed("json"))?;
    encoded
        .into_iter()
        .map(|(id, b)| {
            URL_SAFE_NO_PAD
                .decode(b.trim())
                .map(|bytes| (id, bytes))
                .map_err(|_| VerifyError::Malformed("base64"))
        })
        .collect()
}

/// `methodDetails` value advertising the proof requirement in the 402 challenge.
/// Merge this into the intent's `methodDetails` so clients/contracts learn the
/// manifest to pin and verify against.
pub fn advertise(manifest: &Manifest) -> Value {
    json!({
        "provably": {
            "manifestId": manifest.id,
            "hosts": manifest.hosts,
        }
    })
}

/// Encode a bundle for the response header.
pub fn receipt_header(receipt: &HarnessReceipt) -> String {
    receipt.to_header()
}

/// Decode a bundle from the response header.
pub fn read_receipt_header(value: &str) -> Result<HarnessReceipt, VerifyError> {
    HarnessReceipt::from_header(value)
}

/// Settlement gate: `true` iff every verifier check passes. Conditioning delivery
/// (or, on-chain, voucher release) on this is the "settle only against a proof" rule.
pub fn gate(receipt: &HarnessReceipt, expect: &Expectation) -> bool {
    verify(receipt, expect).iter().all(|c| c.passed)
}
