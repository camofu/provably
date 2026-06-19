//! `provably-transport` — the notary's signing identity.
//!
//! [`Notary`] is the Ed25519 signing half of the notary: it turns a [`LegClaim`]
//! into a signed [`LegAttestation`]. The TLS session itself is witnessed by the
//! notary service (`tlsn/notary`, TLSNotary proxy mode), which calls this to sign
//! what it verified; the reseller prover (`tlsn/reseller`) drives the upstream call
//! through that service. The verification side is orchestrated by `provably-verifier`.

use provably_core::{LegAttestation, LegClaim};

pub mod notary;
pub use notary::Notary;

/// Produces a [`LegAttestation`] for an (already-performed) call's claim.
pub trait Attester {
    fn attest(&self, claim: LegClaim) -> LegAttestation;
}
