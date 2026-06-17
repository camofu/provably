//! A **toy zkTLS notary**.
//!
//! Real zkTLS (TLSNotary / MPC-TLS) has a *notary* witness a TLS session between
//! a prover and a server, then sign a commitment over the transcript. The verifier
//! later checks that signature to learn that specific bytes really crossed that
//! specific TLS connection — without the prover being able to forge the transcript.
//!
//! This crate keeps the **shape** of that protocol but not its cryptographic
//! guarantee: the notary is handed the request/response digests directly and signs
//! them with an Ed25519 key. The interesting, real part that survives the
//! simplification is the **binding check on the verifier side**: a buyer recomputes
//! the digest of the bytes it was actually served and compares it to what the notary
//! signed. If a reseller substitutes a cheaper model's output for the notarized one,
//! the digests diverge and the buyer detects it.
//!
//! Swap-in point for real TLSNotary: replace [`Notary::notarize`] with a call into
//! an MPC-TLS prover/notary, and have [`TranscriptCommitment`] carry the real
//! transcript commitment instead of plain SHA-256 digests. Everything downstream
//! (the [`Attestation`] envelope, the header encoding, the verifier checks) stays.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separator mixed into every signed message so a notary signature can
/// never be confused with a signature over some other kind of payload.
const DOMAIN: &[u8] = b"provable-harness/zktls-attestation/v1";

/// SHA-256 of `bytes`, lowercase hex. Used everywhere a body digest is needed so
/// the reseller and the buyer compute it identically.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// The facts the notary attests to about one upstream request/response exchange.
///
/// Field order is fixed and there are no maps, so `serde_json::to_vec` is a stable
/// canonicalization — both signer and verifier hash the identical bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranscriptCommitment {
    /// TLS server name the bytes were observed to come from (e.g. `api.anthropic.com`).
    pub server_name: String,
    /// HTTP method of the attested request.
    pub method: String,
    /// Request path (e.g. `/v1/messages`).
    pub path: String,
    /// SHA-256 (hex) of the request body sent upstream.
    pub request_digest: String,
    /// SHA-256 (hex) of the response body received from upstream.
    pub response_digest: String,
    /// Upstream HTTP status code.
    pub response_status: u16,
    /// When the exchange was notarized (ISO-8601).
    pub timestamp: String,
    /// **Output binding.** The MPP receipt reference (Tempo tx hash) this
    /// attestation is bound to, tying proof ↔ payment ↔ delivered bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_reference: Option<String>,
}

impl TranscriptCommitment {
    /// Deterministic bytes that get signed: `DOMAIN || 0x00 || canonical_json`.
    fn signing_message(&self) -> Vec<u8> {
        let json = serde_json::to_vec(self).expect("commitment serializes");
        let mut msg = Vec::with_capacity(DOMAIN.len() + 1 + json.len());
        msg.extend_from_slice(DOMAIN);
        msg.push(0x00);
        msg.extend_from_slice(&json);
        msg
    }
}

/// A notary signature over a [`TranscriptCommitment`], plus the public key needed
/// to check it. Self-contained: it travels in one HTTP header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub commitment: TranscriptCommitment,
    /// Notary Ed25519 public key, hex.
    pub notary_pubkey: String,
    /// Ed25519 signature over `commitment.signing_message()`, hex.
    pub signature: String,
}

impl Attestation {
    /// Encode for transport in an HTTP header (base64url of the JSON envelope).
    pub fn to_header(&self) -> String {
        let json = serde_json::to_vec(self).expect("attestation serializes");
        URL_SAFE_NO_PAD.encode(json)
    }

    /// Decode an attestation produced by [`to_header`](Self::to_header).
    pub fn from_header(value: &str) -> Result<Self, VerifyError> {
        let json = URL_SAFE_NO_PAD
            .decode(value.trim())
            .map_err(|_| VerifyError::Malformed("base64"))?;
        serde_json::from_slice(&json).map_err(|_| VerifyError::Malformed("json"))
    }

    /// Check the notary signature against the embedded public key.
    ///
    /// This proves the commitment is authentic *for whoever holds this key*. The
    /// caller must still decide whether it trusts this key (pin it out-of-band) and
    /// whether the committed facts match what it expected — see [`verify`].
    pub fn verify_signature(&self) -> Result<(), VerifyError> {
        let pk_bytes: [u8; 32] = decode_fixed(&self.notary_pubkey)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| VerifyError::BadKey)?;
        let sig_bytes: [u8; 64] = decode_fixed(&self.signature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(&self.commitment.signing_message(), &sig)
            .map_err(|_| VerifyError::BadSignature)
    }
}

/// What the verifier expects to see; everything here is checked by [`verify`].
pub struct Expectation<'a> {
    /// The notary public key the buyer trusts (pinned out-of-band in production).
    pub notary_pubkey: &'a str,
    /// The TLS server name the bytes must have come from.
    pub server_name: &'a str,
    /// SHA-256 (hex) of the body the buyer was actually served.
    pub served_body_digest: &'a str,
    /// The MPP receipt reference the attestation must be bound to.
    pub payment_reference: &'a str,
}

/// Full verifier check: signature, trusted key, origin, body binding, payment binding.
///
/// Returns the list of checks performed (each pass/fail) so a CLI can show its work.
pub fn verify(att: &Attestation, expect: &Expectation) -> Vec<Check> {
    let c = &att.commitment;
    vec![
        Check::new("notary signature valid", att.verify_signature().is_ok()),
        Check::new(
            "notary key matches pinned key",
            constant_ish_eq(&att.notary_pubkey, expect.notary_pubkey),
        ),
        Check::new(
            &format!("served by {}", expect.server_name),
            c.server_name == expect.server_name,
        ),
        Check::new(
            "delivered bytes match notarized response",
            c.response_digest == expect.served_body_digest,
        ),
        Check::new(
            "attestation bound to this payment",
            c.payment_reference.as_deref() == Some(expect.payment_reference),
        ),
    ]
}

/// One named verifier check and whether it passed.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: String,
    pub passed: bool,
}

impl Check {
    fn new(name: &str, passed: bool) -> Self {
        Self {
            name: name.to_string(),
            passed,
        }
    }
}

/// The notary's signing identity.
pub struct Notary {
    signing_key: SigningKey,
}

impl Notary {
    /// Derive a deterministic notary key from a seed string. Deterministic on
    /// purpose: a buyer can pin a known public key for the demo. (A real notary
    /// would use a hardware-protected random key; this is a toy.)
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

    /// Witness an exchange: sign the commitment and wrap it in an [`Attestation`].
    pub fn notarize(&self, commitment: TranscriptCommitment) -> Attestation {
        let sig = self.signing_key.sign(&commitment.signing_message());
        Attestation {
            commitment,
            notary_pubkey: self.public_key_hex(),
            signature: hex::encode(sig.to_bytes()),
        }
    }
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
            VerifyError::Malformed(what) => write!(f, "malformed attestation ({what})"),
            VerifyError::BadKey => write!(f, "invalid notary public key"),
            VerifyError::BadSignature => write!(f, "notary signature did not verify"),
        }
    }
}

impl std::error::Error for VerifyError {}

fn decode_fixed<const N: usize>(hex_str: &str) -> Result<[u8; N], VerifyError> {
    let bytes = hex::decode(hex_str).map_err(|_| VerifyError::Malformed("hex"))?;
    bytes
        .try_into()
        .map_err(|_| VerifyError::Malformed("length"))
}

/// Length-independent string compare for the pinned-key check. (Not the place that
/// matters for HMAC security, but keeps the comparison free of an early-exit tell.)
fn constant_ish_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn commitment(resp_digest: &str, payment: &str) -> TranscriptCommitment {
        TranscriptCommitment {
            server_name: "api.anthropic.com".into(),
            method: "POST".into(),
            path: "/v1/messages".into(),
            request_digest: sha256_hex(b"req"),
            response_digest: resp_digest.into(),
            response_status: 200,
            timestamp: "2026-06-17T00:00:00Z".into(),
            payment_reference: Some(payment.into()),
        }
    }

    #[test]
    fn honest_attestation_passes_every_check() {
        let notary = Notary::from_seed("demo-notary");
        let body = b"the real claude response";
        let att = notary.notarize(commitment(&sha256_hex(body), "0xtx"));

        let expect = Expectation {
            notary_pubkey: &notary.public_key_hex(),
            server_name: "api.anthropic.com",
            served_body_digest: &sha256_hex(body),
            payment_reference: "0xtx",
        };
        assert!(verify(&att, &expect).iter().all(|c| c.passed));
    }

    #[test]
    fn substituted_body_fails_binding_check() {
        let notary = Notary::from_seed("demo-notary");
        let real = b"expensive opus output";
        let att = notary.notarize(commitment(&sha256_hex(real), "0xtx"));

        // Buyer is served different (cheaper) bytes than were notarized.
        let served = b"cheap haiku output";
        let expect = Expectation {
            notary_pubkey: &notary.public_key_hex(),
            server_name: "api.anthropic.com",
            served_body_digest: &sha256_hex(served),
            payment_reference: "0xtx",
        };
        let checks = verify(&att, &expect);
        let binding = checks
            .iter()
            .find(|c| c.name.contains("delivered bytes"))
            .unwrap();
        assert!(!binding.passed, "substitution must be detected");
    }

    #[test]
    fn tampered_commitment_breaks_signature() {
        let notary = Notary::from_seed("demo-notary");
        let mut att = notary.notarize(commitment(&sha256_hex(b"x"), "0xtx"));
        att.commitment.response_status = 500; // tamper after signing
        assert_eq!(att.verify_signature(), Err(VerifyError::BadSignature));
    }

    #[test]
    fn header_roundtrip() {
        let notary = Notary::from_seed("s");
        let att = notary.notarize(commitment(&sha256_hex(b"x"), "0xtx"));
        let decoded = Attestation::from_header(&att.to_header()).unwrap();
        assert!(decoded.verify_signature().is_ok());
        assert_eq!(decoded.commitment, att.commitment);
    }
}
