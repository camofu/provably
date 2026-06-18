//! The provable reseller, **session / voucher rail** (parallel to `reseller`).
//!
//! Same provable-harness idea as the charge-based `reseller`, but settlement is a
//! Tempo payment channel: the buyer opens a channel once (one on-chain deposit),
//! pays per message with off-chain signed vouchers (no gas per call), and closes
//! once to settle. Each response still carries the MPP receipt + the (toy) zkTLS
//! attestation, so the proof layer is identical and rail-agnostic — it binds to
//! `receipt.reference`, which here is the channel id instead of a charge tx hash.
//!
//! Env knobs mirror `reseller`: RPC_URL, UPSTREAM_URL, UPSTREAM_HOST,
//! ANTHROPIC_API_KEY, NOTARY_SEED, RESELLER_MODE (honest | cheat-substitute).
//!
//! Run: `cargo run --bin reseller-session`  (listens on :3000)

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
use mpp::client::channel_ops::default_escrow_contract;
use mpp::server::{
    tempo, Mpp, SessionChallengeOptions, SessionChannelStore, SessionMethodConfig,
    TempoChargeMethod, TempoConfig, TempoSessionMethod,
};
use mpp::{parse_authorization, PrivateKeySigner};
use provably_core::{sha256_hex, HarnessReceipt, Interior, LegClaim};
use provably_mpp::PROVABLY_RECEIPT_HEADER;
use provably_transport::Notary;
use std::sync::Arc;
use tempo_alloy::TempoNetwork;

const CHAIN_ID: u64 = 42431;
/// 0.05 pathUSD per message, in 6-decimal base units.
const AMOUNT_PER_REQUEST: &str = "50000";
/// 1.0 pathUSD suggested channel deposit (~20 messages before top-up).
const SUGGESTED_DEPOSIT: &str = "1000000";
/// The harness this reseller serves: a single-leg passthrough of the upstream LLM.
const MANIFEST_ID: &str = "passthrough-llm-v1";

type PaymentHandler = Mpp<
    TempoChargeMethod<mpp::server::TempoProvider>,
    TempoSessionMethod<mpp::server::TempoProvider>,
>;

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Honest,
    CheatSubstitute,
}

struct App {
    payment: PaymentHandler,
    notary: Notary,
    http: reqwest::Client,
    upstream_url: String,
    upstream_host: String,
    api_key: Option<String>,
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
    let notary_seed = std::env::var("NOTARY_SEED").unwrap_or_else(|_| "demo-notary-key".to_string());
    let mode = match std::env::var("RESELLER_MODE").as_deref() {
        Ok("cheat-substitute") => Mode::CheatSubstitute,
        _ => Mode::Honest,
    };

    let signer = PrivateKeySigner::random();
    let recipient = format!("{:#x}", signer.address());

    // Fund the reseller wallet (it pays gas for channel open/close as fee payer).
    let faucet =
        ProviderBuilder::new_with_network::<TempoNetwork>().connect_http(rpc_url.parse().unwrap());
    let _: Vec<B256> = faucet
        .raw_request("tempo_fundAddress".into(), (signer.address(),))
        .await
        .expect("faucet funding failed");

    let base = Mpp::create(
        tempo(TempoConfig {
            recipient: &recipient,
        })
        .rpc_url(&rpc_url)
        .secret_key(
            &std::env::var("MPP_SECRET_KEY")
                .unwrap_or_else(|_| "reseller-session-secret".to_string()),
        ),
    )
    .expect("failed to create payment handler");

    let rpc_provider = mpp::server::tempo_provider(&rpc_url).expect("failed to create provider");
    let store = Arc::new(SessionChannelStore::new());
    let session_method = TempoSessionMethod::new(
        rpc_provider,
        store,
        SessionMethodConfig {
            escrow_contract: default_escrow_contract(CHAIN_ID).unwrap(),
            chain_id: CHAIN_ID,
            min_voucher_delta: 0,
        },
    )
    .with_close_signer(signer);

    let payment = base.with_session_method(session_method);

    let notary = Notary::from_seed(&notary_seed);
    let notary_pubkey = notary.public_key_hex();

    let state = Arc::new(App {
        payment,
        notary,
        http: reqwest::Client::new(),
        upstream_url: upstream_url.clone(),
        upstream_host: upstream_host.clone(),
        api_key,
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

    println!("provable reseller [SESSION / voucher rail] listening on http://localhost:3000");
    println!("  recipient wallet : {recipient}");
    println!("  notary pubkey    : {notary_pubkey}");
    println!("  upstream         : {upstream_url}  (attested as {upstream_host})");
    println!("  price / message  : {AMOUNT_PER_REQUEST} base units (0.05 pathUSD), off-chain voucher");
    println!(
        "  mode             : {}",
        if mode == Mode::Honest {
            "honest"
        } else {
            "CHEAT-SUBSTITUTE (sells tampered bytes — buyer should detect & cut off)"
        }
    );
    axum::serve(listener, app).await.expect("serve");
}

async fn notary_pubkey_route(State(st): State<Arc<App>>) -> impl IntoResponse {
    Json(serde_json::json!({ "pubkey": st.notary.public_key_hex() }))
}

async fn messages(State(st): State<Arc<App>>, headers: HeaderMap, body: Bytes) -> Response {
    let credential = match headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| parse_authorization(s).ok())
    {
        Some(c) => c,
        None => return session_challenge(&st),
    };

    let result = match st.payment.verify_session(&credential).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    };

    // Channel management (open / close / top-up): return the SDK's response as-is.
    if let Some(mgmt) = result.management_response {
        let receipt_header = result.receipt.to_header().unwrap_or_default();
        return (
            StatusCode::OK,
            [("payment-receipt", receipt_header)],
            Json(mgmt),
        )
            .into_response();
    }

    // Content request: the voucher covered this message → forward upstream & attest.
    let channel_id = result.receipt.reference.clone();

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

    // Attest the leg and bundle a passthrough receipt bound to the channel
    // (payment_reference = channel id).
    let leg = st.notary.attest(LegClaim {
        host: st.upstream_host.clone(),
        method: "POST".into(),
        path: "/v1/messages".into(),
        request_digest: sha256_hex(&body),
        response_digest: sha256_hex(&upstream_body),
        response_status: status.as_u16(),
        timestamp: result.receipt.timestamp.clone(),
    });
    let harness_receipt = HarnessReceipt {
        manifest_id: MANIFEST_ID.into(),
        legs: vec![leg],
        interior: Interior::Passthrough,
        output_digest: sha256_hex(&upstream_body),
        payment_reference: Some(channel_id),
    };

    let delivered = match st.mode {
        Mode::Honest => upstream_body.to_vec(),
        Mode::CheatSubstitute => substitute(&upstream_body),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("payment-receipt", result.receipt.to_header().unwrap_or_default())
        .header(PROVABLY_RECEIPT_HEADER, harness_receipt.to_header())
        .body(Body::from(delivered))
        .expect("valid response")
}

/// 402 with a Tempo **session** challenge (channel deposit + per-message price).
fn session_challenge(st: &App) -> Response {
    let currency = st.payment.currency().unwrap();
    let recipient = st.payment.recipient().unwrap();
    match st.payment.session_challenge_with_details(
        AMOUNT_PER_REQUEST,
        currency,
        recipient,
        SessionChallengeOptions {
            unit_type: Some("message"),
            suggested_deposit: Some(SUGGESTED_DEPOSIT),
            ..Default::default()
        },
    ) {
        Ok(ch) => match ch.to_header() {
            Ok(h) => (
                StatusCode::PAYMENT_REQUIRED,
                [(header::WWW_AUTHENTICATE, h)],
                "Payment required",
            )
                .into_response(),
            Err(e) => server_error(e.to_string()),
        },
        Err(e) => server_error(e.to_string()),
    }
}

/// Replace model + text with a cheaper substitute, leaving valid JSON.
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
