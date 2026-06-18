//! The buyer, **session / voucher rail** (parallel to `buyer`).
//!
//! Opens one Tempo payment channel, sends several messages paying each with an
//! off-chain voucher (no per-call gas), verifies the zkTLS attestation on every
//! response, and closes once to settle on-chain.
//!
//! Fair-exchange behaviour at this (discrete) granularity: vouchers are
//! voucher-up-front, so a failed proof means the buyer **stops the session
//! immediately** — it refuses to release any further vouchers to a reseller it
//! caught cheating. Loss is bounded to the single disputed message; the rest of
//! the planned spend is never paid. (The stronger "deliver → verify → release
//! voucher" interleave is the streaming/SSE Tier-1 in
//! `fair-exchange-voucher-conditioning.md`.)
//!
//! Run (after mock-llm-api + reseller-session):
//!   cargo run --bin buyer-session
//!   cargo run --bin buyer-session -- "prompt one" "prompt two"
//!
//! Env: RESELLER_URL, EXPECTED_UPSTREAM, NOTARY_PUBKEY (pin out-of-band; else fetched).

use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use mpp::client::{Fetch, TempoSessionProvider};
use mpp::{parse_receipt, PrivateKeySigner};
use provably_core::{sha256_hex, verify, Expectation, Interior, Manifest};
use provably_mpp::{read_receipt_header, PROVABLY_RECEIPT_HEADER};
use reqwest::Client;
use tempo_alloy::TempoNetwork;

const CURRENCY: &str = "0x20c0000000000000000000000000000000000000";
/// 1.0 pathUSD max channel deposit (6 decimals).
const MAX_DEPOSIT: u128 = 1_000_000;

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

#[tokio::main]
async fn main() {
    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());
    let reseller =
        std::env::var("RESELLER_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let expected_upstream =
        std::env::var("EXPECTED_UPSTREAM").unwrap_or_else(|_| "api.anthropic.com".to_string());

    let mut prompts: Vec<String> = std::env::args().skip(1).collect();
    if prompts.is_empty() {
        prompts = vec![
            "What is the Machine Payments Protocol in one sentence?".into(),
            "Name one advantage of payment channels over per-call settlement.".into(),
            "In one line: what does a zkTLS attestation prove?".into(),
        ];
    }

    let signer = PrivateKeySigner::random();
    let signer_address = signer.address();

    let faucet =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = faucet
        .raw_request("tempo_fundAddress".into(), (signer_address,))
        .await
        .expect("faucet funding failed");

    // Wait for the faucet's pathUSD to land before opening the channel.
    let currency_addr: Address = CURRENCY.parse().unwrap();
    let erc20 = IERC20::new(currency_addr, &faucet);
    for _ in 0..30 {
        if let Ok(bal) = erc20.balanceOf(signer_address).call().await {
            if bal.to::<u128>() > 0 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    let session = TempoSessionProvider::new(signer, &rpc_url)
        .expect("session provider")
        .with_max_deposit(MAX_DEPOSIT);
    let http = Client::new();

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

    let messages_url = format!("{reseller}/anthropic/v1/messages");
    println!(
        "\n--- Opening payment channel (max deposit {} pathUSD) ---",
        MAX_DEPOSIT as f64 / 1e6
    );

    let mut verified = 0u32;
    let mut fraud_cut = false;
    let mut open_seen = false;
    let mut idx = 0usize;
    let mut guard = 0u32;

    // The SDK's first round-trip opens the channel (a management response with no
    // content); subsequent voucher requests deliver content. We detect the open by
    // the absence of an attestation header and retry the same prompt.
    while idx < prompts.len() {
        guard += 1;
        if guard > prompts.len() as u32 + 3 {
            eprintln!("unexpected: too many non-content responses; aborting");
            break;
        }

        let payload = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 256,
            "messages": [{ "role": "user", "content": prompts[idx] }],
        });

        let resp = match http
            .post(&messages_url)
            .json(&payload)
            .send_with_payment(&session)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("request failed: {e}");
                break;
            }
        };

        let status = resp.status();
        let receipt_hdr = header(&resp, "payment-receipt");
        let bundle_hdr = header(&resp, PROVABLY_RECEIPT_HEADER);
        let body = resp.bytes().await.unwrap_or_default();

        if !status.is_success() {
            eprintln!("→ {}: {}", status, String::from_utf8_lossy(&body));
            break;
        }

        let receipt = match receipt_hdr.as_deref().and_then(|s| parse_receipt(s).ok()) {
            Some(r) => r,
            None => {
                eprintln!("missing payment receipt");
                break;
            }
        };

        let harness_receipt = match bundle_hdr.as_deref().map(read_receipt_header) {
            Some(Ok(r)) => r,
            _ => {
                // Channel-open / management response: no content this round.
                if !open_seen {
                    println!("  channel opened (id {})", receipt.reference);
                    open_seen = true;
                }
                continue; // retry same prompt; channel is now open → next call delivers content
            }
        };

        let model = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .map(|v| v["model"].to_string())
            .unwrap_or_default();
        let served_digest = sha256_hex(&body);
        let manifest = Manifest {
            id: "passthrough-llm-v1".into(),
            hosts: vec![expected_upstream.clone()],
            interior: Interior::Passthrough,
        };
        let checks = verify(
            &harness_receipt,
            &Expectation {
                manifest: &manifest,
                notary_pubkey: Some(&pinned_pubkey),
                served_output_digest: &served_digest,
                payment_reference: &receipt.reference,
                recomputed_output_digest: None,
            },
        );
        let ok = checks.iter().all(|c| c.passed);
        let cumulative = session.cumulative() as f64 / 1e6;

        println!("\nmessage {} (model {model}) — voucher cumulative {cumulative:.2} pathUSD", idx + 1);
        for c in &checks {
            println!("  {} {}", if c.passed { "[PASS]" } else { "[FAIL]" }, c.name);
        }

        if ok {
            verified += 1;
            idx += 1;
            println!("  ✅ verified");
        } else {
            println!("  ❌ proof failed — model substitution / tampering detected.");
            println!("     Cutting off the session: no further vouchers released to this reseller.");
            fraud_cut = true;
            break;
        }
    }

    // Capture the voucher total before close (cumulative() reads from the open channel).
    let voucher_total = session.cumulative() as f64 / 1e6;

    println!("\n--- Settlement (single on-chain close) ---");
    match session.close(&http, &messages_url).await {
        Ok(Some(r)) => println!(
            "  channel settled: https://explore.moderato.tempo.xyz/tx/{}",
            r.reference
        ),
        Ok(None) => println!("  no active channel to close"),
        Err(e) => eprintln!("  close failed: {e}"),
    }
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    println!("\n--- Summary ---");
    println!("  messages verified : {verified}/{}", prompts.len());
    println!("  voucher total     : {voucher_total:.2} pathUSD (one channel, off-chain vouchers, no per-call gas)");
    if fraud_cut {
        println!("  result            : ❌ fraud detected — session cut off after the bad message; the reseller earns only the disputed tick, not the rest.");
    } else if verified as usize == prompts.len() {
        println!("  result            : ✅ all messages provably served by {expected_upstream}, settled in a single on-chain close.");
    } else {
        println!("  result            : ⚠ session ended early (network/error) before all messages completed.");
    }
}

fn header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}
