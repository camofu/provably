//! `provably-verifier` — the receipt verifier.
//!
//! [`verify`] takes a [`HarnessReceipt`] and an [`Expectation`] (the manifest a
//! buyer pinned out-of-band, the bytes it was served, the payment it expects, and
//! any digests it recomputed) and returns one [`Check`] per assertion, so callers
//! can show their work. Everything binds by digest-equality.
//!
//! This lives outside [`provably_core`] so the IP (the receipt/leg/node types) stays
//! free of verification logic, and heavier backend verifiers (zkTLS/TEE leg proofs,
//! zkVM/inference interior proofs) can grow here without touching the type crate.
//! The cheap signature self-check is still a method on the attestation type
//! ([`LegAttestation::verify_proof`](provably_core::LegAttestation::verify_proof));
//! this crate orchestrates it together with the cross-node bindings.

use provably_core::{HarnessReceipt, InteriorProof, LegAttestation, Manifest, Node, NodeId, NodeProof};
use std::collections::{HashMap, HashSet};

/// What the verifier expects.
pub struct Expectation<'a> {
    pub manifest: &'a Manifest,
    /// Pinned trusted notary key for notary-proven legs (`None` = don't pin).
    pub notary_pubkey: Option<&'a str>,
    /// SHA-256 (hex) of the bytes the buyer was actually served.
    pub served_output_digest: &'a str,
    /// The MPP receipt reference the bundle must be bound to.
    pub payment_reference: &'a str,
    /// SHA-256 (hex) of the request the buyer sent. When set, the verifier checks
    /// the output leg answered *this* request — catching a reseller that asked the
    /// upstream a different (e.g. cheaper) question. `None` = don't bind the request.
    pub served_request_digest: Option<&'a str>,
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

    // Request binding: the leg that produced the sold output answered THE BUYER's
    // request — not a different (e.g. cheaper) one the reseller swapped in upstream.
    // The sold output may be an interior node computed *from* a leg, so bind against the
    // leg(s) it transitively depends on (for the single-leg chain that's just the
    // upstream call feeding the verdict). Only checked when the buyer supplies the
    // digest of the request it actually sent.
    if let Some(expected_req) = expect.served_request_digest {
        let legs = leg_ancestors(&map, receipt.output_node.as_str());
        let bound = !legs.is_empty()
            && legs
                .iter()
                .all(|att| att.claim.request_digest.as_str() == expected_req);
        checks.push(Check::new("output answers the buyer's request", bound));
    }

    // Walk every node.
    for node in &receipt.nodes {
        // Edges resolve.
        for inp in &node.inputs {
            checks.push(Check::new(
                format!("node {} input {inp} resolves", node.id),
                map.contains_key(inp.as_str()),
            ));
        }

        match &node.proof {
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
            },
        }
    }

    checks
}

/// The leg attestations the `start` node's output transitively depends on (walking
/// `inputs` edges; recursion stops at leg nodes). For the demo's `leg0 -> verdict` chain
/// this returns `[leg0]`.
fn leg_ancestors<'a>(map: &HashMap<&str, &'a Node>, start: &str) -> Vec<&'a LegAttestation> {
    let mut legs = Vec::new();
    let mut stack = vec![start.to_string()];
    let mut seen = HashSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        if let Some(&node) = map.get(id.as_str()) {
            match &node.proof {
                NodeProof::Leg(att) => legs.push(att),
                NodeProof::Interior(_) => stack.extend(node.inputs.iter().cloned()),
            }
        }
    }
    legs
}
