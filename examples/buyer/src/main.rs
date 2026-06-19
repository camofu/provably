//! The **buyer** (a paying agent).
//!
//! Pays the reseller for a Claude message over MPP, then *verifies the proof* it
//! gets back before trusting the output:
//!
//!   1. the notary signature is valid and under the pinned key,
//!   2. the bytes were attested as coming from `api.anthropic.com`,
//!   3. the body actually delivered hashes to the notarized response digest
//!      (this is what catches model substitution), and
//!   4. the attestation is bound to the payment we just made.
//!
//! Run (after starting the notary + reseller from `tlsn/`):
//!   cargo run --bin buyer
//!   cargo run --bin buyer -- "summarize zkTLS in one line"
//!
//! Env: RESELLER_URL (default http://localhost:3000), EXPECTED_UPSTREAM
//! (default api.anthropic.com), NOTARY_PUBKEY (pin out-of-band; else fetched).

use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use mpp::client::{Fetch, TempoProvider};
use mpp::{parse_receipt, PrivateKeySigner};
use provably_core::{sha256_hex, Manifest};
use provably_verifier::{verify, Expectation};
use provably_mpp::{read_receipt_header, PROVABLY_RECEIPT_HEADER};
use reqwest::Client;
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
        .unwrap_or_else(|| "In one sentence, what is the Machine Payments Protocol?".to_string());

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
        "model": "claude-opus-4-8",
        "max_tokens": 256,
        "messages": [{ "role": "user", "content": prompt }],
    });

    println!("\npaying reseller for: {prompt:?}");
    let resp = http
        .post(format!("{reseller}/v1/messages"))
        .json(&payload)
        .send_with_payment(&provider)
        .await
        .expect("request failed");

    let status = resp.status();
    let receipt_hdr = header(&resp, "payment-receipt");
    let bundle_hdr = header(&resp, PROVABLY_RECEIPT_HEADER);
    let body = resp.bytes().await.expect("read body");

    println!("status: {status}\n");
    if !status.is_success() {
        println!("response: {}", String::from_utf8_lossy(&body));
        return;
    }

    // What we were actually served (so substitution is visible to the eye too).
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
        println!("served model : {}", v["model"]);
        println!("served text  : {}\n", v["content"][0]["text"]);
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
    // a single-leg passthrough from `expected_upstream`.
    let manifest = Manifest {
        id: "passthrough-llm-v1".into(),
        hosts: vec![expected_upstream.clone()],
    };
    let served_digest = sha256_hex(&body);
    let checks = verify(
        &harness_receipt,
        &Expectation {
            manifest: &manifest,
            notary_pubkey: Some(&pinned_pubkey),
            served_output_digest: &served_digest,
            payment_reference: &receipt.reference,
            recomputed: &[],
        },
    );

    println!("\nproof verification:");
    for c in &checks {
        println!("  {} {}", if c.passed { "[PASS]" } else { "[FAIL]" }, c.name);
    }

    if checks.iter().all(|c| c.passed) {
        println!(
            "\n✅ VERIFIED — output provably served by {expected_upstream}, bound to payment {}.",
            receipt.reference
        );
    } else {
        println!(
            "\n❌ REJECTED — proof failed. The reseller did not deliver the notarized \
             upstream bytes (model substitution / tampering). Do not trust this output; \
             dispute the payment or slash the reseller's bond."
        );
    }
}

fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}
