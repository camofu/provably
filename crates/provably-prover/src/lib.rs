//! `provably-prover` — interior node provers.
//!
//! A prover describes how the interior transform is attested, producing an
//! [`Interior`] for the [`HarnessReceipt`](provably_core::HarnessReceipt). Today
//! only [`Recompute`] (the cheapest: no proof — the verifier re-runs the public
//! transform). The expensive backends — a zkVM (RISC Zero / SP1), a proof-of-
//! inference scheme (CommitLLM / zkML), or a TEE — slot in behind the same
//! [`Prover`] trait, each emitting its own `Interior` variant and committing the
//! leg digests + output so `provably-core::verify` can bind them.

use provably_core::InteriorProof;

/// Describes the interior attestation a harness node produces.
pub trait Prover {
    fn interior(&self) -> InteriorProof;
}

/// A publicly-recomputable transform. No proof is produced; the verifier re-runs
/// the function identified by `fn_id` over the attested leg responses and matches
/// the digest. Right for cheap, public interiors (median, containment, extraction).
pub struct Recompute {
    pub fn_id: String,
}

impl Recompute {
    pub fn new(fn_id: impl Into<String>) -> Self {
        Self {
            fn_id: fn_id.into(),
        }
    }
}

impl Prover for Recompute {
    fn interior(&self) -> InteriorProof {
        InteriorProof::Recompute {
            fn_id: self.fn_id.clone(),
        }
    }
}
