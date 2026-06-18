//! `provably-transport` — leg attesters.
//!
//! An attester turns a completed external call (a [`LegClaim`]) into a
//! [`LegAttestation`]. Today there is one backend, the toy [`notary`] (Ed25519);
//! the real `zktls` and `tee` backends slot in behind the same [`Attester`] trait.
//!
//! For the toy, the harness performs the HTTP call itself and hands the claim to
//! the attester. When zkTLS lands this trait grows an
//! `attest_call(request) -> (Response, LegAttestation)` method that owns the call.

use provably_core::{LegAttestation, LegClaim};

pub mod notary;
pub use notary::Notary;

/// Produces a [`LegAttestation`] for an (already-performed) call's claim.
pub trait Attester {
    fn attest(&self, claim: LegClaim) -> LegAttestation;
}
