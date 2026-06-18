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

use provably_core::{HarnessReceipt, Manifest, VerifyError};
use provably_verifier::{verify, Expectation};
use serde_json::{json, Value};

/// Response header carrying the base64url-encoded [`HarnessReceipt`] bundle.
pub const PROVABLY_RECEIPT_HEADER: &str = "x-provably-receipt";

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
