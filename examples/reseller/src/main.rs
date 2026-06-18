//! The **provable reseller harness**.
//!
//! A payment-gated proxy in front of Anthropic. A buyer pays for `POST
//! /anthropic/v1/messages` over MPP (HTTP 402, settled on the Tempo testnet); the
//! reseller verifies the payment, forwards the request upstream, and returns the
//! response together with:
//!
//!   * `Payment-Receipt`        — the MPP receipt (Tempo tx hash)
//!   * `X-Zktls-Attestation`    — a (toy) zkTLS attestation that the bytes came
//!                                from `api.anthropic.com`, bound to that receipt
//!
//! This is the thesis in miniature: *condition delivery on a proof*. The buyer can
//! verify it got genuine upstream output and was not sold a substituted cheaper
//! model — without trusting the reseller.
//!
//! Env knobs:
//!   RPC_URL            Tempo RPC (default moderato testnet)
//!   MPP_SECRET_KEY     server secret for stateless challenge ids
//!   PRICE              price per call, human units (default "0.05")
//!   UPSTREAM_URL       where to forward (default http://localhost:4000, the mock)
//!   UPSTREAM_HOST      TLS server name to attest (default api.anthropic.com)
//!   ANTHROPIC_API_KEY  if set, injects x-api-key + anthropic-version (real upstream)
//!   NOTARY_SEED        deterministic notary key seed (default "demo-notary-key")
//!   RESELLER_MODE      "honest" (default) | "cheat-substitute" (demo fraud)
//!
//! Run: `cargo run --bin reseller`  (listens on :3000)

use alloy::primitives::B256;
use alloy::providers::{Provider, ProviderBuilder};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use mpp::server::{tempo, Mpp, TempoChargeMethod, TempoConfig};
use mpp::{format_www_authenticate, parse_authorization, PrivateKeySigner};
use provably_core::{sha256_hex, HarnessReceipt, Interior, LegClaim};
use provably_mpp::PROVABLY_RECEIPT_HEADER;
use provably_transport::Notary;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

type Payment = Mpp<TempoChargeMethod<mpp::server::TempoProvider>>;

/// The harness this reseller serves: a single-leg passthrough of the upstream LLM.
const MANIFEST_ID: &str = "passthrough-llm-v1";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Honest,
    CheatSubstitute,
}

struct App {
    payment: Payment,
    notary: Notary,
    http: reqwest::Client,
    upstream_url: String,
    upstream_host: String,
    api_key: Option<String>,
    price: String,
    mode: Mode,
}

#[tokio::main]
async fn main() {
    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());
    let upstream_url =
        std::env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://localhost:4000".to_string());
    let upstream_host =
        std::env::var("UPSTREAM_HOST").unwrap_or_else(|_| "api.anthropic.com".to_string());
    let api_key = std::env::var("ANTHROPIC_API_KEY").ok();
    let price = std::env::var("PRICE").unwrap_or_else(|_| "0.05".to_string());
    let notary_seed = std::env::var("NOTARY_SEED").unwrap_or_else(|_| "demo-notary-key".to_string());
    let mode = match std::env::var("RESELLER_MODE").as_deref() {
        Ok("cheat-substitute") => Mode::CheatSubstitute,
        _ => Mode::Honest,
    };

    // The reseller's wallet — where buyer payments land. Fund it on the testnet.
    let signer = PrivateKeySigner::random();
    let recipient = format!("{}", signer.address());
    let provider =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = provider
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");

    let payment = Mpp::create(
        tempo(TempoConfig {
            recipient: &recipient,
        })
        .rpc_url(&rpc_url)
        .secret_key(
            &std::env::var("MPP_SECRET_KEY")
                .unwrap_or_else(|_| "reseller-example-secret".to_string()),
        ),
    )
    .expect("failed to create payment handler");

    let notary = Notary::from_seed(&notary_seed);
    let notary_pubkey = notary.public_key_hex();

    let state = Arc::new(App {
        payment,
        notary,
        http: reqwest::Client::new(),
        upstream_url: upstream_url.clone(),
        upstream_host: upstream_host.clone(),
        api_key,
        price: price.clone(),
        mode,
    });

    let app = Router::new()
        .route("/health", get(|| async { Json(serde_json::json!({"status":"ok"})) }))
        .route("/notary/pubkey", get(notary_pubkey_route))
        .route("/anthropic/v1/messages", post(messages))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("bind");

    println!("provable reseller listening on http://localhost:3000");
    println!("  recipient wallet : {recipient}");
    println!("  notary pubkey    : {notary_pubkey}");
    println!("  upstream         : {upstream_url}  (attested as {upstream_host})");
    println!("  price            : {price}");
    println!(
        "  mode             : {}",
        if mode == Mode::Honest {
            "honest"
        } else {
            "CHEAT-SUBSTITUTE (will sell tampered bytes — buyer should detect it)"
        }
    );
    axum::serve(listener, app).await.expect("serve");
}

async fn notary_pubkey_route(State(st): State<Arc<App>>) -> impl IntoResponse {
    Json(serde_json::json!({ "pubkey": st.notary.public_key_hex() }))
}

async fn messages(State(st): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    // 1. Require a valid MPP payment, or hand back a 402 challenge.
    let receipt = match headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| parse_authorization(s).ok())
    {
        Some(credential) => match st.payment.verify_credential(&credential).await {
            Ok(receipt) => receipt,
            Err(e) => {
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response()
            }
        },
        None => return challenge(&st),
    };

    // 2. Forward upstream (the leg a real zkTLS notary would witness).
    let mut req = st
        .http
        .post(format!("{}/v1/messages", st.upstream_url))
        .header("content-type", "application/json")
        .body(body.to_vec());
    if let Some(key) = &st.api_key {
        req = req
            .header("x-api-key", key)
            .header("anthropic-version", "2023-06-01");
    }
    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("upstream request failed: {e}") })),
            )
                .into_response()
        }
    };
    let status = upstream.status();
    let upstream_body = upstream.bytes().await.unwrap_or_default();

    // 3. Attest the *genuine* leg and bundle a single-leg passthrough receipt,
    //    bound to this payment via the MPP receipt reference.
    let leg = st.notary.attest(LegClaim {
        host: st.upstream_host.clone(),
        method: "POST".into(),
        path: "/v1/messages".into(),
        request_digest: sha256_hex(&body),
        response_digest: sha256_hex(&upstream_body),
        response_status: status.as_u16(),
        timestamp: receipt.timestamp.clone(),
    });
    let harness_receipt = HarnessReceipt {
        manifest_id: MANIFEST_ID.into(),
        legs: vec![leg],
        interior: Interior::Passthrough,
        output_digest: sha256_hex(&upstream_body),
        payment_reference: Some(receipt.reference.clone()),
    };

    // 4. In cheat mode, sell tampered bytes while the receipt still commits to the
    //    real output — exactly the model-substitution fraud the buyer must catch.
    let delivered = match st.mode {
        Mode::Honest => upstream_body.to_vec(),
        Mode::CheatSubstitute => substitute(&upstream_body),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("payment-receipt", receipt.to_header().unwrap_or_default())
        .header(PROVABLY_RECEIPT_HEADER, harness_receipt.to_header())
        .body(Body::from(delivered))
        .expect("valid response")
}

/// Build the 402 Payment Required response with a fresh charge challenge.
fn challenge(st: &App) -> Response {
    match st.payment.charge(&st.price) {
        Ok(challenge) => match format_www_authenticate(&challenge) {
            Ok(www_auth) => (
                StatusCode::PAYMENT_REQUIRED,
                [(header::WWW_AUTHENTICATE, www_auth)],
                Json(serde_json::json!({ "error": "Payment Required" })),
            )
                .into_response(),
            Err(e) => server_error(e.to_string()),
        },
        Err(e) => server_error(e.to_string()),
    }
}

/// Replace the model and text with a cheaper substitute, leaving valid JSON.
fn substitute(real: &[u8]) -> Vec<u8> {
    match serde_json::from_slice::<serde_json::Value>(real) {
        Ok(mut v) => {
            v["model"] = serde_json::json!("claude-haiku-cheap-substitute");
            if let Some(text) = v
                .get_mut("content")
                .and_then(|c| c.get_mut(0))
                .and_then(|p| p.get_mut("text"))
            {
                *text = serde_json::json!("[SUBSTITUTED cheaper output — not the notarized bytes]");
            }
            serde_json::to_vec(&v).unwrap_or_else(|_| real.to_vec())
        }
        Err(_) => real.to_vec(),
    }
}

fn server_error(msg: String) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": msg })),
    )
        .into_response()
}
