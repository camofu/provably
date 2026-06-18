//! Toy zkTLS notary backend (Ed25519).
//!
//! Stands in for a real zkTLS prover/notary: it signs the [`LegClaim`] rather than
//! independently witnessing the TLS session. The verifier side lives in
//! `provably-core` ([`LegAttestation::verify_proof`]); this is only the signer.

use ed25519_dalek::{Signer, SigningKey};
use provably_core::{LegAttestation, LegClaim, LegProof};
use sha2::{Digest, Sha256};

/// A notary signing identity.
pub struct Notary {
    signing_key: SigningKey,
}

impl Notary {
    /// Derive a deterministic key from a seed (so buyers can pin a known pubkey in
    /// the demo). A real notary uses a hardware-protected random key.
    pub fn from_seed(seed: &str) -> Self {
        let secret: [u8; 32] = Sha256::digest(seed.as_bytes()).into();
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    /// Notary public key, hex — hand this to buyers to pin.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    /// Sign a claim and wrap it as an attested leg.
    pub fn attest(&self, claim: LegClaim) -> LegAttestation {
        let sig = self.signing_key.sign(&claim.signing_message());
        LegAttestation {
            claim,
            proof: LegProof::Notary {
                pubkey: self.public_key_hex(),
                signature: hex::encode(sig.to_bytes()),
            },
        }
    }
}

impl super::Attester for Notary {
    fn attest(&self, claim: LegClaim) -> LegAttestation {
        Notary::attest(self, claim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use provably_core::sha256_hex;

    fn claim() -> LegClaim {
        LegClaim {
            host: "api.anthropic.com".into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            request_digest: sha256_hex(b"req"),
            response_digest: sha256_hex(b"resp"),
            response_status: 200,
            timestamp: "2026-06-18T00:00:00Z".into(),
        }
    }

    #[test]
    fn attest_then_verify_roundtrips() {
        let n = Notary::from_seed("demo");
        let leg = n.attest(claim());
        assert!(leg.verify_proof().is_ok());
        assert_eq!(leg.notary_pubkey(), Some(n.public_key_hex().as_str()));
    }

    #[test]
    fn tampered_claim_breaks_proof() {
        let n = Notary::from_seed("demo");
        let mut leg = n.attest(claim());
        leg.claim.response_status = 500;
        assert!(leg.verify_proof().is_err());
    }
}
