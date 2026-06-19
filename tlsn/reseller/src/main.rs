//! The **reseller, adapted into the TLSNotary Prover** (proxy mode).
//!
//! A payment-gated proxy: a buyer pays for `POST /v1/messages` over MPP
//! and gets the response plus an `x-provably-receipt`. Rather than calling upstream
//! directly and signing its own [`LegClaim`] — which would make the proof only as
//! trustworthy as the reseller — it routes the upstream TLS call **through the
//! `notary` process**: it is the TLSNotary **Prover**, and the notary witnesses
//! the session, verifies the server certificate, and signs the [`LegClaim`] with a
//! key the reseller does not hold. The reseller just relays that signed attestation.
//! It cannot forge the leg.
//!
//! Because the proof type on the wire is unchanged (`LegProof::Notary` + Ed25519),
//! the **buyer is unchanged** — it still pins the notary pubkey + manifest and runs
//! the same `verify()`. Only the reseller's interior changed.
//!
//! Note: the upstream must be a real **TLS** server — a plain-HTTP server cannot be
//! notarized, since there is no TLS handshake to witness. For example, to proxy
//! Anthropic, set `UPSTREAM_HOST=api.anthropic.com` and `UPSTREAM_API_KEY`.
//!
//! Env knobs:
//!   RPC_URL            Tempo RPC (default moderato testnet)
//!   MPP_SECRET_KEY     server secret for stateless challenge ids
//!   PRICE              price per call, human units (default "0.05")
//!   NOTARY_ADDR        where the notary process listens (default 127.0.0.1:7047)
//!   UPSTREAM_HOST      TLS server to proxy + attest, required (e.g. api.anthropic.com)
//!   UPSTREAM_API_KEY   injected as x-api-key (and *redacted* from the proof)
//!   UPSTREAM_HEADERS   extra request headers "Name: Value; …" (e.g. anthropic-version: 2023-06-01)
//!   NOTARY_SEED        notary key seed — only to expose /notary/pubkey (default "demo-notary-key")
//!   RESELLER_MODE      "honest" (default) | "cheat-substitute" (demo fraud)
//!
//! These are read from the environment or a `.env` file (loaded via dotenv, searched
//! up from the working directory — see `.env.example`).
//!
//! Run (with the `notary` already running): `cd tlsn/reseller && cargo run`

use std::sync::Arc;

use anyhow::{anyhow, Result};
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
use futures::io::AsyncReadExt as _;
use http_body_util::{BodyExt, Full};
use hyper::Request as HyperRequest;
use hyper_util::rt::TokioIo;
use mpp::server::{tempo, Mpp, TempoChargeMethod, TempoConfig};
use mpp::{format_www_authenticate, parse_authorization, PrivateKeySigner};
use provably_core::{sha256_hex, HarnessReceipt, LegAttestation, Node, NodeProof};
use provably_mpp::PROVABLY_RECEIPT_HEADER;
use provably_transport::Notary;
use std::future::IntoFuture;
use tempo_alloy::TempoNetwork;
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, ServerName},
    webpki::RootCertStore,
    Session,
};

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
    notary_addr: String,
    upstream_host: String,
    api_key: Option<String>,
    /// Extra request headers injected upstream (e.g. an API version header).
    upstream_headers: Vec<(String, String)>,
    notary_pubkey: String,
    price: String,
    mode: Mode,
}

#[tokio::main]
async fn main() {
    // Load config from a `.env` file (dotenv searches up from the working directory
    // to the repo root) so the demo runs with no env args; real environment
    // variables still take precedence.
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "https://rpc.moderato.tempo.xyz".to_string());
    let notary_addr =
        std::env::var("NOTARY_ADDR").unwrap_or_else(|_| "127.0.0.1:7047".to_string());
    let upstream_host = std::env::var("UPSTREAM_HOST")
        .expect("UPSTREAM_HOST must be set (the TLS server to proxy and attest)");
    let api_key = std::env::var("UPSTREAM_API_KEY").ok();
    let upstream_headers = std::env::var("UPSTREAM_HEADERS")
        .map(|s| parse_headers(&s))
        .unwrap_or_default();
    let price = std::env::var("PRICE").unwrap_or_else(|_| "0.05".to_string());
    let notary_seed =
        std::env::var("NOTARY_SEED").unwrap_or_else(|_| "demo-notary-key".to_string());
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

    // We do NOT hold a signing key — the notary signs. We derive the *public* key
    // from the shared seed only so the buyer can fetch it from /notary/pubkey
    // (a demo convenience; in production the buyer pins it out-of-band).
    let notary_pubkey = Notary::from_seed(&notary_seed).public_key_hex();

    let state = Arc::new(App {
        payment,
        notary_addr: notary_addr.clone(),
        upstream_host: upstream_host.clone(),
        api_key,
        upstream_headers,
        notary_pubkey: notary_pubkey.clone(),
        price: price.clone(),
        mode,
    });

    let app = Router::new()
        .route("/health", get(|| async { Json(serde_json::json!({"status":"ok"})) }))
        .route("/notary/pubkey", get(notary_pubkey_route))
        .route("/v1/messages", post(messages))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("bind");

    println!("provable reseller (TLSNotary Prover, proxy mode) listening on http://localhost:3000");
    println!("  recipient wallet : {recipient}");
    println!("  notary           : {notary_addr}  (pubkey {notary_pubkey})");
    println!("  upstream         : {upstream_host}:443  (attested via TLS cert)");
    println!("  price            : {price}");
    println!(
        "  mode             : {}",
        if mode == Mode::Honest {
            "honest"
        } else {
            "CHEAT-SUBSTITUTE (sells tampered bytes — buyer should detect it)"
        }
    );
    axum::serve(listener, app).await.expect("serve");
}

async fn notary_pubkey_route(State(st): State<Arc<App>>) -> impl IntoResponse {
    Json(serde_json::json!({ "pubkey": st.notary_pubkey }))
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

    // 2. Run the upstream call as the TLSNotary Prover through the notary, getting
    //    back the genuine response bytes and the notary's *signed* leg attestation.
    let (response_body, leg) = match run_prover(&st, &body).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("notarized upstream call failed: {e}") })),
            )
                .into_response()
        }
    };

    // The attested digest is the canonical commitment. In honest mode the bytes we
    // deliver must hash to it; if they don't, the on-wire encoding broke the
    // body-digest contract (see the notary: identity + non-chunked required).
    let output_digest = leg.claim.response_digest.clone();
    if st.mode == Mode::Honest && sha256_hex(&response_body) != output_digest {
        tracing::warn!(
            "delivered body digest != attested response digest — likely chunked/compressed \
             upstream; the buyer's check will fail. attested={output_digest}"
        );
    }

    // 3. Bundle a single-leg passthrough receipt bound to this payment.
    let harness_receipt = HarnessReceipt {
        manifest_id: MANIFEST_ID.into(),
        nodes: vec![Node {
            id: "leg0".into(),
            inputs: vec![],
            output_digest,
            proof: NodeProof::Leg(leg),
        }],
        output_node: "leg0".into(),
        payment_reference: Some(receipt.reference.clone()),
    };

    // 4. In cheat mode, sell tampered bytes while the receipt still commits to the
    //    real notarized output — the model-substitution fraud the buyer must catch.
    let delivered = match st.mode {
        Mode::Honest => response_body,
        Mode::CheatSubstitute => substitute(&response_body),
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("payment-receipt", receipt.to_header().unwrap_or_default())
        .header(PROVABLY_RECEIPT_HEADER, harness_receipt.to_header())
        .body(Body::from(delivered))
        .expect("valid response")
}

/// Drive the upstream `POST /v1/messages` as the TLSNotary Prover, talking to the
/// notary in proxy mode. Returns `(response_body, signed_leg_attestation)`.
async fn run_prover(st: &App, body: &Bytes) -> Result<(Vec<u8>, LegAttestation)> {
    // Control session with the notary (the prover<->verifier channel).
    let notary_conn = TcpStream::connect(&st.notary_addr).await?;
    notary_conn.set_nodelay(true)?;
    let session = Session::new(notary_conn.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Proxy mode: we declare the server, the notary opens the connection to it.
    let prover = handle
        .new_prover(ProverConfig::builder().build().map_err(|e| anyhow!("prover config: {e}"))?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(st.upstream_host.as_str())?)
                .build()?,
        )
        .await?;

    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(st.upstream_host.as_str().try_into()?))
            // Real upstreams chain to Mozilla roots.
            .root_store(RootCertStore::mozilla())
            .build()?,
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    // Attach a hyper client over the (notary-proxied) TLS connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    // `Accept-Encoding: identity` + non-streaming keeps the on-wire body equal to
    // the decoded body, so the notary's body digest matches what we deliver.
    let mut req = HyperRequest::builder()
        .uri("/v1/messages")
        .method("POST")
        .header("Host", st.upstream_host.as_str())
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("accept-encoding", "identity")
        .header("connection", "close");
    for (name, value) in &st.upstream_headers {
        req = req.header(name.as_str(), value.as_str());
    }
    if let Some(key) = &st.api_key {
        req = req.header("x-api-key", key.as_str());
    }
    let req = req.body(Full::new(body.clone()))?;

    let response = request_sender.send_request(req).await?;
    let response_body = response.into_body().collect().await?.to_bytes().to_vec();

    // Reclaim the prover for the disclosure/prove phase.
    let mut prover = prover_task.await??;

    // Selective disclosure: reveal the server identity and the full response;
    // reveal the request EXCEPT the api-key value, so the notary never sees the key.
    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.server_identity();
    builder.reveal_recv(&(0..recv_len))?;
    match &st.api_key {
        Some(key) => {
            let sent = prover.transcript().sent();
            match sent
                .windows(key.len())
                .position(|w| w == key.as_bytes())
            {
                Some(pos) => {
                    builder.reveal_sent(&(0..pos))?;
                    builder.reveal_sent(&(pos + key.len()..sent_len))?;
                }
                // Fail closed: if we can't locate the key to redact it, we must NOT
                // fall back to revealing the whole request — that would disclose the
                // x-api-key header to the notary. Abort the proof instead.
                None => {
                    return Err(anyhow!(
                        "aborting proof: could not locate the api-key in the sent \
                         transcript to redact it — refusing to disclose the request \
                         and leak the key to the notary"
                    ));
                }
            }
        }
        None => {
            builder.reveal_sent(&(0..sent_len))?;
        }
    }
    let config = builder.build()?;
    prover.prove(&config).await?;
    prover.close().await?;

    // Tear down the session and reclaim the raw socket; the notary writes the
    // signed attestation (JSON) until EOF (see the notary's wire-protocol note).
    handle.close();
    let mut socket = driver_task.await??;
    let mut buf = Vec::new();
    socket.read_to_end(&mut buf).await?;
    let leg: LegAttestation = serde_json::from_slice(&buf)
        .map_err(|e| anyhow!("decoding notary attestation ({} bytes): {e}", buf.len()))?;

    Ok((response_body, leg))
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

/// Parse `UPSTREAM_HEADERS` ("Name: Value; Name2: Value2") into header pairs.
fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter_map(|pair| {
            let (name, value) = pair.trim().split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
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
