//! `provably-core` — the API-agnostic proof interface, as a **node DAG**.
//!
//! A harness is a directed acyclic graph of [`Node`]s wired by `inputs` (edges).
//! Each node's output is justified by a [`NodeProof`]:
//!
//! - [`NodeProof::Leg`] — an external call (transport-attested).
//! - [`NodeProof::Interior`] — the harness's own computation ([`InteriorProof`]).
//!
//! Today the only leg proof is the notary's Ed25519 signature (a [`LegClaim`] signed
//! by the TLSNotary service after it witnesses the TLS session), and the only
//! interior proof is [`InteriorProof::Recompute`] (the verifier re-runs a public
//! transform). The bigger backends — zkVM/inference interior proofs, TEE leg proofs,
//! folding a leg's proof into a zkVM (one-proof / verify-in-circuit), and recursive
//! agent-to-agent sub-receipts — are **new enum variants when implemented**, which
//! is a non-breaking addition. They're deliberately *not* pre-declared here: their
//! shape should be designed against the real backend, not guessed.
//!
//! The binding everywhere is digest-equality, enforced by the verifier in the
//! separate `provably-verifier` crate.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"provably/leg-attestation/v1";

/// SHA-256 of `bytes`, lowercase hex. The one canonical digest used everywhere.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// A node identifier, unique within one [`HarnessReceipt`].
pub type NodeId = String;

// ===================== legs (external calls) =====================

/// The facts attested about one external call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegClaim {
    pub host: String,
    pub method: String,
    pub path: String,
    pub request_digest: String,
    pub response_digest: String,
    pub response_status: u16,
    pub timestamp: String,
}

impl LegClaim {
    /// Deterministic bytes that get signed: `DOMAIN || 0x00 || canonical_json`.
    pub fn signing_message(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).expect("LegClaim serializes");
        let mut m = Vec::with_capacity(DOMAIN.len() + 1 + json.len());
        m.extend_from_slice(DOMAIN);
        m.push(0x00);
        m.extend_from_slice(&json);
        m
    }
}

/// How a [`LegClaim`] is proven. New variants (zkTLS, TEE) extend this.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LegProof {
    Notary { pubkey: String, signature: String },
}

/// An attested leg: claim + proof. Produced by `provably-transport`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegAttestation {
    pub claim: LegClaim,
    pub proof: LegProof,
}

impl LegAttestation {
    /// Check the leg proof is internally valid (e.g. the notary signature verifies).
    pub fn verify_proof(&self) -> Result<(), VerifyError> {
        match &self.proof {
            LegProof::Notary { pubkey, signature } => {
                let pk: [u8; 32] = decode_fixed(pubkey)?;
                let vk = VerifyingKey::from_bytes(&pk).map_err(|_| VerifyError::BadKey)?;
                let sig: [u8; 64] = decode_fixed(signature)?;
                vk.verify(&self.claim.signing_message(), &Signature::from_bytes(&sig))
                    .map_err(|_| VerifyError::BadSignature)
            }
        }
    }

    pub fn notary_pubkey(&self) -> Option<&str> {
        match &self.proof {
            LegProof::Notary { pubkey, .. } => Some(pubkey),
        }
    }
}

// ===================== interior (own computation) =====================

/// How an interior node's computation is justified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InteriorProof {
    /// Public, cheap transform: no proof — the verifier re-runs `fn_id`.
    Recompute { fn_id: String },
    // zk / TEE / inference proofs extend this as new variants when implemented.
}

// ===================== the node DAG =====================

/// How a node's output is justified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeProof {
    /// External call.
    Leg(LegAttestation),
    /// The harness's own computation.
    Interior(InteriorProof),
    // Recursion (an agent-to-agent sub-receipt) and folded-into-another-proof nodes
    // extend the node model here when implemented.
}

/// One node of the harness DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    /// Node ids whose outputs feed this node (DAG edges).
    pub inputs: Vec<NodeId>,
    /// SHA-256 (hex) of this node's output.
    pub output_digest: String,
    pub proof: NodeProof,
}

/// The proof-carrying bundle: the whole node DAG, the node that's sold, and the
/// payment it's bound to.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessReceipt {
    pub manifest_id: String,
    pub nodes: Vec<Node>,
    pub output_node: NodeId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
}

impl HarnessReceipt {
    pub fn to_header(&self) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("receipt serializes"))
    }

    pub fn from_header(value: &str) -> Result<Self, VerifyError> {
        let json = URL_SAFE_NO_PAD
            .decode(value.trim())
            .map_err(|_| VerifyError::Malformed("base64"))?;
        serde_json::from_slice(&json).map_err(|_| VerifyError::Malformed("json"))
    }
}

// ===================== manifest (pinned commitment) =====================

/// The public commitment a buyer/contract pins out-of-band. The verifier
/// (`provably-verifier`) checks a receipt against this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    /// Hosts the leg nodes are allowed to come from.
    pub hosts: Vec<String>,
}

// ===================== errors =====================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Malformed(&'static str),
    BadKey,
    BadSignature,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Malformed(what) => write!(f, "malformed receipt ({what})"),
            VerifyError::BadKey => write!(f, "invalid notary public key"),
            VerifyError::BadSignature => write!(f, "leg proof did not verify"),
        }
    }
}

impl std::error::Error for VerifyError {}

fn decode_fixed<const N: usize>(hex_str: &str) -> Result<[u8; N], VerifyError> {
    hex::decode(hex_str)
        .map_err(|_| VerifyError::Malformed("hex"))?
        .try_into()
        .map_err(|_| VerifyError::Malformed("length"))
}
