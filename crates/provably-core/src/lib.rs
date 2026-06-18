//! `provably-core` — the API-agnostic proof interface.
//!
//! This is the part you own. It knows nothing about payments, transports, or
//! proving backends — only the data shapes and how to check them:
//!
//! - [`LegClaim`] / [`LegProof`] / [`LegAttestation`] — one attested external call
//!   (an edge). Generalizes the old single-leg `TranscriptCommitment`.
//! - [`Interior`] — how the sold output is bound to the legs (passthrough today;
//!   `Recompute` / zk / inference / TEE later).
//! - [`HarnessReceipt`] — the bundle: legs + interior + output, bound to a payment.
//! - [`Manifest`] — the public commitment a buyer/contract pins.
//! - [`verify`] — the verifier; returns a [`Check`] per assertion so a CLI/contract
//!   can show its work.
//!
//! Proof backends (notary signatures today; zkTLS/TEE next) plug in behind
//! [`LegProof`]; node provers (recompute today; zkVM/inference next) plug in behind
//! [`Interior`]. The binding across both is a digest equality, enforced here.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator mixed into every signed leg claim.
const DOMAIN: &[u8] = b"provably/leg-attestation/v1";

/// SHA-256 of `bytes`, lowercase hex. Every digest in the protocol is computed
/// this way so producer and verifier agree byte-for-byte.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The facts attested about one external call (an edge in the harness DAG).
///
/// Field order is fixed and there are no maps, so `serde_json::to_vec` is a stable
/// canonicalization — signer and verifier hash identical bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LegClaim {
    /// TLS server name the bytes came from (e.g. `api.anthropic.com`).
    pub host: String,
    pub method: String,
    pub path: String,
    /// SHA-256 (hex) of the request body sent to `host`.
    pub request_digest: String,
    /// SHA-256 (hex) of the response body received from `host`.
    pub response_digest: String,
    pub response_status: u16,
    pub timestamp: String,
}

impl LegClaim {
    /// Deterministic bytes that get signed/attested: `DOMAIN || 0x00 || canonical_json`.
    pub fn signing_message(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).expect("LegClaim serializes");
        let mut m = Vec::with_capacity(DOMAIN.len() + 1 + json.len());
        m.extend_from_slice(DOMAIN);
        m.push(0x00);
        m.extend_from_slice(&json);
        m
    }
}

/// How a [`LegClaim`] is proven. Extensible — today only the toy notary; zkTLS and
/// TEE attestations become additional variants without touching the receipt or
/// the verifier's structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LegProof {
    /// Ed25519 signature over [`LegClaim::signing_message`] (toy stand-in for zkTLS).
    Notary { pubkey: String, signature: String },
}

/// One attested leg: the claim plus the proof of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegAttestation {
    pub claim: LegClaim,
    pub proof: LegProof,
}

impl LegAttestation {
    /// Check the leg proof is internally valid (e.g. the notary signature verifies).
    /// Whether to *trust* the proving party is the caller's policy (see [`verify`]).
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

    /// The notary public key, if this leg is notary-proven.
    pub fn notary_pubkey(&self) -> Option<&str> {
        match &self.proof {
            LegProof::Notary { pubkey, .. } => Some(pubkey),
        }
    }
}

/// The interior node — how the sold output is bound to the legs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Interior {
    /// Output is exactly the single leg's response (`output_digest == legs[0].response_digest`).
    Passthrough,
    /// A publicly-recomputable transform; the verifier re-runs `fn_id` over the legs.
    Recompute { fn_id: String },
    // Zk { vk, proof } / Inference { model, proof } / Tee { quote } — later.
}

/// The proof-carrying bundle. Travels alongside the MPP receipt and is bound to it
/// via [`payment_reference`](Self::payment_reference).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessReceipt {
    pub manifest_id: String,
    pub legs: Vec<LegAttestation>,
    pub interior: Interior,
    /// SHA-256 (hex) of the output the harness sold.
    pub output_digest: String,
    /// The MPP receipt reference (charge tx hash or channel id) this is bound to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
}

impl HarnessReceipt {
    /// Encode for an HTTP header (base64url of the JSON bundle).
    pub fn to_header(&self) -> String {
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(self).expect("receipt serializes"))
    }

    /// Decode a bundle produced by [`to_header`](Self::to_header).
    pub fn from_header(value: &str) -> Result<Self, VerifyError> {
        let json = URL_SAFE_NO_PAD
            .decode(value.trim())
            .map_err(|_| VerifyError::Malformed("base64"))?;
        serde_json::from_slice(&json).map_err(|_| VerifyError::Malformed("json"))
    }
}

/// The public commitment a buyer/contract pins out-of-band: which harness, which
/// hosts the legs must come from, and which interior is expected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub id: String,
    pub hosts: Vec<String>,
    pub interior: Interior,
}

/// What the verifier expects; everything here is checked by [`verify`].
pub struct Expectation<'a> {
    pub manifest: &'a Manifest,
    /// Pinned trusted notary key (for notary-proven legs). `None` = don't pin.
    pub notary_pubkey: Option<&'a str>,
    /// SHA-256 (hex) of the bytes the buyer was actually served.
    pub served_output_digest: &'a str,
    /// The MPP receipt reference the bundle must be bound to.
    pub payment_reference: &'a str,
    /// For `Recompute` interiors: the digest the buyer got re-running the transform.
    pub recomputed_output_digest: Option<&'a str>,
}

/// One named verifier check and whether it passed.
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

/// Full verification: legs, interior binding, delivered-output binding, payment binding.
pub fn verify(receipt: &HarnessReceipt, expect: &Expectation) -> Vec<Check> {
    let m = expect.manifest;
    let mut checks = vec![Check::new("manifest matches", receipt.manifest_id == m.id)];

    // 1. Legs: proof valid · host allowed · (optionally) pinned key.
    for (i, leg) in receipt.legs.iter().enumerate() {
        checks.push(Check::new(
            format!("leg {i} proof valid"),
            leg.verify_proof().is_ok(),
        ));
        checks.push(Check::new(
            format!("leg {i} host allowed ({})", leg.claim.host),
            m.hosts.iter().any(|h| h == &leg.claim.host),
        ));
        if let Some(pin) = expect.notary_pubkey {
            checks.push(Check::new(
                format!("leg {i} notary key matches pinned"),
                leg.notary_pubkey() == Some(pin),
            ));
        }
    }

    // 2. Interior kind matches the manifest, then the interior binding.
    checks.push(Check::new(
        "interior matches manifest",
        std::mem::discriminant(&receipt.interior) == std::mem::discriminant(&m.interior),
    ));
    match &receipt.interior {
        Interior::Passthrough => {
            let ok = receipt
                .legs
                .first()
                .map(|l| l.claim.response_digest == receipt.output_digest)
                .unwrap_or(false);
            checks.push(Check::new("interior passthrough: output == leg response", ok));
        }
        Interior::Recompute { .. } => match expect.recomputed_output_digest {
            Some(r) => checks.push(Check::new(
                "interior recompute: output == recomputed",
                r == receipt.output_digest,
            )),
            None => checks.push(Check::new(
                "interior recompute: NOT re-verified (no recomputer supplied)",
                false,
            )),
        },
    }

    // 3. Delivered-output binding — catches substitution/tampering.
    checks.push(Check::new(
        "delivered bytes match notarized output",
        receipt.output_digest == expect.served_output_digest,
    ));

    // 4. Payment binding — proof ↔ payment.
    checks.push(Check::new(
        "attestation bound to this payment",
        receipt.payment_reference.as_deref() == Some(expect.payment_reference),
    ));

    checks
}

/// Verifier-side errors.
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
