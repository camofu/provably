//! The **buyer** (a paying agent).
//!
//! Pays the reseller for a yes/no verdict over MPP, then *verifies the proof* it gets
//! back before trusting the output. The harness is `leg0 -> verdict`: the seller calls
//! Claude (leg0), then an interior node emits `1` if the answer starts with "yes", else
//! `0`. The buyer checks:
//!
//!   1. the notary signature on leg0 is valid and under the pinned key,
//!   2. leg0 was attested as coming from `api.anthropic.com`,
//!   3. the leg bytes the seller shipped hash to the notarized response digest
//!      (this is what catches model substitution),
//!   4. re-running the interior transform over those bytes reproduces the committed
//!      verdict digest, and the delivered verdict matches it, and
//!   5. the attestation is bound to the payment we just made.
//!
//! The interior proof here is a toy: instead of a zk/TEE proof, the buyer re-runs its
//! own copy of the public transform (from the `harness` crate) over the notarized leg
//! bytes the seller ships in the materials sidecar.
//!
//! Run (after starting the notary + reseller from `tlsn/`):
//!   cargo run --bin buyer
//!   cargo run --bin buyer -- "Is the sky blue? Begin your answer with Yes or No."
//!
//! Env: RESELLER_URL (default http://localhost:3000), EXPECTED_UPSTREAM
//! (default api.anthropic.com), NOTARY_PUBKEY (pin out-of-band; else fetched).

use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use harness::{recompute, MANIFEST_ID, VERDICT_FN_ID};
use mpp::client::{Fetch, TempoProvider};
use mpp::{parse_receipt, PrivateKeySigner};
use provably_core::{sha256_hex, InteriorProof, Manifest, NodeProof};
use provably_verifier::{verify, Check, Expectation};
use provably_mpp::{
    materials_from_header, read_receipt_header, PROVABLY_MATERIALS_HEADER, PROVABLY_RECEIPT_HEADER,
};
use reqwest::Client;
use std::collections::HashMap;
use tempo_alloy::TempoNetwork;

#[tokio::main]
async fn main() {
    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());
    let reseller =
        std::env::var("RESELLER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let expected_upstream =
        std::env::var("EXPECTED_UPSTREAM").unwrap_or_else(|_| "api.anthropic.com".to_string());
    let prompt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Is the sky blue? Begin your answer with Yes or No.".to_string());

    // Wallet — funded from the testnet faucet so it can pay.
    let signer = PrivateKeySigner::random();
    let rpc =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = rpc
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let provider = TempoProvider::new(signer, &rpc_url).expect("provider");

    let http = Client::new();

    // Pin the notary key. In production this is distributed out-of-band; for the
    // demo we fetch it (and say so) unless NOTARY_PUBKEY is set.
    let pinned_pubkey = match std::env::var("NOTARY_PUBKEY") {
        Ok(k) => {
            println!("notary key: pinned from NOTARY_PUBKEY");
            k
        }
        Err(_) => {
            let v: serde_json::Value = http
                .get(format!("{reseller}/notary/pubkey"))
                .send()
                .await
                .expect("fetch notary key")
                .json()
                .await
                .expect("notary key json");
            let k = v["pubkey"].as_str().unwrap_or_default().to_string();
            println!("notary key: fetched from reseller (demo only — pin out-of-band in prod)");
            k
        }
    };

    let payload = serde_json::json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 256,
        "messages": [{ "role": "user", "content": prompt }],
    });
    // Serialize once so we can hash the *exact* bytes we send. The verifier binds
    // the response to this request digest, so a reseller can't quietly ask the
    // upstream a different (cheaper) question and pass off that genuine answer.
    let request_body = serde_json::to_vec(&payload).expect("serialize request");
    let request_digest = sha256_hex(&request_body);

    println!("\npaying reseller for: {prompt:?}");
    let resp = http
        .post(format!("{reseller}/v1/messages"))
        .header("content-type", "application/json")
        .body(request_body)
        .send_with_payment(&provider)
        .await
        .expect("request failed");

    let status = resp.status();
    let receipt_hdr = header(&resp, "payment-receipt");
    let bundle_hdr = header(&resp, PROVABLY_RECEIPT_HEADER);
    let materials_hdr = header(&resp, PROVABLY_MATERIALS_HEADER);
    let body = resp.bytes().await.expect("read body");

    println!("status: {status}\n");
    if !status.is_success() {
        println!("response: {}", String::from_utf8_lossy(&body));
        return;
    }

    // The product is the verdict (1/0). The full upstream answer rides in the materials
    // sidecar so we can re-run the transform; show it too (substitution is then visible).
    let materials = materials_hdr
        .as_deref()
        .map(materials_from_header)
        .expect("missing materials header")
        .expect("malformed materials header");
    println!("verdict      : {}", String::from_utf8_lossy(&body));
    if let Some(answer) = materials.get("leg0") {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(answer) {
            println!("upstream ans : {}\n", v["content"][0]["text"]);
        }
    }

    let receipt = receipt_hdr
        .as_deref()
        .and_then(|s| parse_receipt(s).ok())
        .expect("missing/invalid payment receipt");
    println!("payment tx   : {}", receipt.reference);

    let harness_receipt = bundle_hdr
        .as_deref()
        .map(read_receipt_header)
        .expect("missing provably receipt")
        .expect("malformed provably receipt");

    // The verification that replaces trust. The buyer pins the manifest it expects:
    // this seller's harness, with leg0 from `expected_upstream`.
    let manifest = Manifest {
        id: MANIFEST_ID.into(),
        hosts: vec![expected_upstream.clone()],
    };
    let served_digest = sha256_hex(&body);

    // Re-run the interior transform ourselves. First confirm each shipped material is the
    // genuine committed bytes — for leg0 that digest is the notary-attested one (verify()
    // checks that separately), so this ties our re-run input to the real upstream answer.
    // A reseller that fed its computation substituted bytes is caught right here.
    let committed: HashMap<&str, &str> = harness_receipt
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n.output_digest.as_str()))
        .collect();
    let mut material_checks: Vec<Check> = Vec::new();
    let mut trusted: HashMap<&str, &[u8]> = HashMap::new();
    for (id, bytes) in &materials {
        let ok = committed
            .get(id.as_str())
            .map(|d| *d == sha256_hex(bytes).as_str())
            .unwrap_or(false);
        material_checks.push(Check {
            name: format!("material {id} matches committed digest"),
            passed: ok,
        });
        if ok {
            trusted.insert(id.as_str(), bytes.as_slice());
        }
    }

    // Re-run each interior Recompute node over its (trusted) inputs and record the digest
    // for the verifier to bind against the node's committed output.
    let mut recomputed: Vec<(String, String)> = Vec::new();
    for node in &harness_receipt.nodes {
        if let NodeProof::Interior(InteriorProof::Recompute { fn_id }) = &node.proof {
            let inputs: Option<Vec<&[u8]>> = node
                .inputs
                .iter()
                .map(|i| trusted.get(i.as_str()).copied())
                .collect();
            if let Some(inputs) = inputs {
                if let Some(out) = recompute(fn_id, &inputs) {
                    recomputed.push((node.id.clone(), sha256_hex(&out)));
                }
            }
        }
    }

    let checks = verify(
        &harness_receipt,
        &Expectation {
            manifest: &manifest,
            notary_pubkey: Some(&pinned_pubkey),
            served_output_digest: &served_digest,
            payment_reference: &receipt.reference,
            served_request_digest: Some(&request_digest),
            recomputed: &recomputed,
        },
    );

    println!("\nproof verification:");
    let all: Vec<&Check> = material_checks.iter().chain(checks.iter()).collect();
    for c in &all {
        println!("  {} {}", if c.passed { "[PASS]" } else { "[FAIL]" }, c.name);
    }

    if all.iter().all(|c| c.passed) {
        println!(
            "\n✅ VERIFIED — verdict provably computed by `{VERDICT_FN_ID}` over the notarized \
             {expected_upstream} answer, bound to payment {}.",
            receipt.reference
        );
    } else {
        println!(
            "\n❌ REJECTED — proof failed. The verdict was not provably computed from the \
             notarized upstream answer (model substitution / tampering). Do not trust this \
             output; dispute the payment or slash the reseller's bond."
        );
    }
}

fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}
