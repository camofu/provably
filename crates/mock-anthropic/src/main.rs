//! Mock upstream standing in for `api.anthropic.com`.
//!
//! Serves a single `POST /v1/messages` route returning a canned Anthropic Messages
//! API response that echoes the requested model and reflects the prompt, so the
//! reseller demo "feels" real while staying fully offline and deterministic.
//!
//! To point the reseller at the real Anthropic instead, set `UPSTREAM_URL` and
//! `ANTHROPIC_API_KEY` on the reseller — this binary is then unused.
//!
//! Run: `cargo run --bin mock-anthropic`  (listens on :4000)

use axum::{extract::Json, http::StatusCode, response::IntoResponse, routing::post, Router};
use serde_json::{json, Value};

#[tokio::main]
async fn main() {
    let app = Router::new().route("/v1/messages", post(messages));
    let addr = "0.0.0.0:4000";
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    println!("mock-anthropic (pretending to be api.anthropic.com) listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}

async fn messages(Json(req): Json<Value>) -> impl IntoResponse {
    let model = req
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("claude-opus-4-8")
        .to_string();

    // Reflect the latest user turn so the canned reply visibly depends on input.
    let prompt = req
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|m| m.last())
        .and_then(|m| m.get("content"))
        .map(stringify_content)
        .unwrap_or_default();

    let reply = format!("[{model}] mock reply to: {prompt}");

    let body = json!({
        "id": "msg_mock_0001",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{ "type": "text", "text": reply }],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": { "input_tokens": prompt.len() / 4 + 1, "output_tokens": 16 }
    });

    // A real api.anthropic.com identifies itself via TLS; here we just label it so
    // the notary has a server name to attest in the offline demo.
    (
        StatusCode::OK,
        [("x-served-by", "api.anthropic.com")],
        Json(body),
    )
}

fn stringify_content(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.get("text").and_then(Value::as_str))
            .collect::<Vec<_>>()
            .join(" "),
        other => other.to_string(),
    }
}
