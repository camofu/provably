//! `provably-core` — the API-agnostic proof interface, as a **node DAG**.
//!
//! A harness is a directed acyclic graph of [`Node`]s wired by `inputs` (edges).
//! Each node's output is justified by a [`NodeProof`]:
//!
//! - [`NodeProof::Leg`] — an external call (transport-attested: notary today;
//!   zkTLS/TEE next).
//! - [`NodeProof::Interior`] — the harness's own computation
//!   ([`InteriorProof`]: recompute today; zk/TEE/inference next).
//! - [`NodeProof::SubReceipt`] — **recursion / agent-to-agent**: the node's output
//!   is *another agent's whole [`HarnessReceipt`]*.
//!
//! North-star hooks baked into the types (not yet exercised by the toy):
//! - **One-proof / fold zkTLS into the zkVM:** a node can be
//!   [`NodeAttestation::Folded`] into another node whose proof *subsumes* it (see
//!   `subsumes` on [`InteriorProof::Zk`]/[`InteriorProof::Tee`]). The verifier then
//!   skips the folded node's standalone check and relies on the covering proof.
//! - **Recursion:** [`NodeProof::SubReceipt`] lets a verified sub-agent receipt be a
//!   node here, so receipts compose (Proof-Carrying Data).
//!
//! The binding everywhere is digest-equality, enforced in [`verify`].

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

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

/// How a [`LegClaim`] is proven. Extensible (zkTLS/TEE become variants).
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
    /// zkVM proof of `output = f(inputs)`. `subsumes` lists node ids whose proofs
    /// were folded into this one (e.g. a zkTLS leg verified in-circuit) — those
    /// nodes are marked [`NodeAttestation::Folded`] and skipped standalone.
    Zk {
        vk: String,
        proof: String,
        #[serde(default)]
        subsumes: Vec<NodeId>,
    },
    /// TEE-attested computation (handles nondeterminism / whole-program); also may
    /// `subsumes` folded nodes.
    Tee {
        measurement: String,
        quote: String,
        #[serde(default)]
        subsumes: Vec<NodeId>,
    },
    // Inference { model, proof, subsumes } — self-hosted LLM, later.
}

impl InteriorProof {
    fn subsumes(&self) -> &[NodeId] {
        match self {
            InteriorProof::Zk { subsumes, .. } | InteriorProof::Tee { subsumes, .. } => subsumes,
            InteriorProof::Recompute { .. } => &[],
        }
    }
}

// ===================== the node DAG =====================

/// How a node's output is justified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeProof {
    /// External call.
    Leg(LegAttestation),
    /// The harness's own computation.
    Interior(InteriorProof),
    /// Recursion / agent-to-agent: another agent's whole receipt stands in for this
    /// node's output.
    SubReceipt(Box<HarnessReceipt>),
}

/// Whether a node is checked on its own, or folded into another node's proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeAttestation {
    /// Verified directly by [`verify`].
    Standalone(NodeProof),
    /// Subsumed by node `into`'s proof (one-proof / zkTLS-in-zkVM / recursion fold).
    /// Not checked standalone; the covering proof must list this node in `subsumes`.
    Folded { into: NodeId },
}

/// One node of the harness DAG.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    /// Node ids whose outputs feed this node (DAG edges).
    pub inputs: Vec<NodeId>,
    /// SHA-256 (hex) of this node's output.
    pub output_digest: String,
    pub attestation: NodeAttestation,
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

// ===================== verification =====================

/// The public commitment a buyer/contract pins out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    /// Hosts the leg nodes are allowed to come from.
    pub hosts: Vec<String>,
}

/// What the verifier expects.
pub struct Expectation<'a> {
    pub manifest: &'a Manifest,
    /// Pinned trusted notary key for notary-proven legs (`None` = don't pin).
    pub notary_pubkey: Option<&'a str>,
    /// SHA-256 (hex) of the bytes the buyer was actually served.
    pub served_output_digest: &'a str,
    /// The MPP receipt reference the bundle must be bound to.
    pub payment_reference: &'a str,
    /// For `Recompute` interior nodes: `(node_id, digest)` the buyer obtained by
    /// re-running the transform.
    pub recomputed: &'a [(NodeId, String)],
}

/// One named verifier check.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub passed: bool,
}

impl Check {
    fn new(name: impl Into<String>, passed: bool) -> Self {
        Self {
            name: name.into(),
            passed,
        }
    }
}

/// Verify a harness receipt against the pinned manifest + per-call expectation.
/// Returns a [`Check`] per assertion so callers can show their work.
pub fn verify(receipt: &HarnessReceipt, expect: &Expectation) -> Vec<Check> {
    let mut checks = vec![Check::new(
        "manifest matches",
        receipt.manifest_id == expect.manifest.id,
    )];

    let map: HashMap<&str, &Node> = receipt.nodes.iter().map(|n| (n.id.as_str(), n)).collect();

    // Delivered-output binding: the sold node's output == what the buyer received.
    match map.get(receipt.output_node.as_str()) {
        Some(out) => checks.push(Check::new(
            "delivered bytes match output node",
            out.output_digest == expect.served_output_digest,
        )),
        None => checks.push(Check::new("output node exists", false)),
    }

    // Payment binding.
    checks.push(Check::new(
        "bound to this payment",
        receipt.payment_reference.as_deref() == Some(expect.payment_reference),
    ));

    // Walk every node.
    for node in &receipt.nodes {
        // Edges resolve.
        for inp in &node.inputs {
            checks.push(Check::new(
                format!("node {} input {inp} resolves", node.id),
                map.contains_key(inp.as_str()),
            ));
        }

        match &node.attestation {
            // Folded: covered by `into`'s proof — verify the fold is consistent and
            // skip the standalone proof (the zkTLS-in-zkVM / recursion hook).
            NodeAttestation::Folded { into } => {
                let ok = map
                    .get(into.as_str())
                    .map(|t| node_subsumes(t, &node.id))
                    .unwrap_or(false);
                checks.push(Check::new(
                    format!("node {} folded into {into} (consistent)", node.id),
                    ok,
                ));
            }
            NodeAttestation::Standalone(proof) => match proof {
                NodeProof::Leg(att) => {
                    checks.push(Check::new(
                        format!("node {} leg proof valid", node.id),
                        att.verify_proof().is_ok(),
                    ));
                    checks.push(Check::new(
                        format!("node {} host allowed ({})", node.id, att.claim.host),
                        expect.manifest.hosts.iter().any(|h| h == &att.claim.host),
                    ));
                    checks.push(Check::new(
                        format!("node {} output == leg response", node.id),
                        node.output_digest == att.claim.response_digest,
                    ));
                    if let Some(pin) = expect.notary_pubkey {
                        checks.push(Check::new(
                            format!("node {} notary key matches pinned", node.id),
                            att.notary_pubkey() == Some(pin),
                        ));
                    }
                }
                NodeProof::Interior(ip) => match ip {
                    InteriorProof::Recompute { .. } => {
                        match expect
                            .recomputed
                            .iter()
                            .find(|(id, _)| id == &node.id)
                            .map(|(_, d)| d.as_str())
                        {
                            Some(d) => checks.push(Check::new(
                                format!("node {} recompute matches", node.id),
                                d == node.output_digest,
                            )),
                            None => checks.push(Check::new(
                                format!("node {} recompute NOT re-verified (no recomputer)", node.id),
                                false,
                            )),
                        }
                    }
                    // Reserved north-star backends — fail closed until a verifier is
                    // wired, so an unproven node can never pass.
                    InteriorProof::Zk { .. } | InteriorProof::Tee { .. } => {
                        checks.push(Check::new(
                            format!("node {} interior proof requires a wired verifier", node.id),
                            false,
                        ));
                    }
                },
                NodeProof::SubReceipt(child) => {
                    // Recursion: the child's sold output must equal this node's output.
                    let child_out = child
                        .nodes
                        .iter()
                        .find(|n| n.id == child.output_node)
                        .map(|n| n.output_digest.as_str());
                    checks.push(Check::new(
                        format!("node {} sub-receipt output binds", node.id),
                        child_out == Some(node.output_digest.as_str()),
                    ));
                    // Full recursive policy verification (child manifest/key) is a
                    // north-star step — fail closed for now.
                    checks.push(Check::new(
                        format!("node {} sub-receipt full verification (pending)", node.id),
                        false,
                    ));
                }
            },
        }
    }

    checks
}

/// Does `target`'s interior proof declare that it subsumes node `id`?
fn node_subsumes(target: &Node, id: &str) -> bool {
    matches!(
        &target.attestation,
        NodeAttestation::Standalone(NodeProof::Interior(ip)) if ip.subsumes().iter().any(|s| s == id)
    )
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
