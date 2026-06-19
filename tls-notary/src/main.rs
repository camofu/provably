//! `tls-notary` — the third-party TLSNotary **proxy + notary** (proxy mode).
//!
//! This is the separate party that turns a self-attestation into a real proof.
//! In the toy, the reseller signed its own [`LegClaim`] with a key it controlled,
//! so "trust the proof" collapsed to "trust the reseller." Here the reseller is
//! the TLSNotary *Prover* and must route its upstream TLS call **through this
//! process**, which:
//!
//!   1. proxies the encrypted traffic between the prover and the real server
//!      (proxy mode — no MPC, so it works against TLS 1.3 servers and is fast),
//!   2. cryptographically verifies the TLS session and the server's certificate,
//!   3. signs the witnessed [`LegClaim`] with the notary key — a key the reseller
//!      does **not** hold.
//!
//! The buyer pins this notary's public key. Because the prover never holds the
//! key and this process actually witnessed the bytes on the wire, the reseller
//! can no longer forge a leg — which is the whole point.
//!
//! Architecture: this is **interactive-verify + re-sign**, not a portable zk
//! presentation. The notary verifies the session live and signs a [`LegClaim`];
//! the buyer then trusts that signature. The buyer holds no re-checkable
//! cryptographic proof — TLS/cert verification happens once, here, and a smart
//! contract can't re-run it. That's the classic notary trust model: lighter (the
//! buyer never pulls in tlsn/mpz) but a genuine downgrade from a presentation the
//! buyer could verify itself.
//!
//! Trust model — what this notary sees: during live proxying it sees only
//! *ciphertext* (no session keys, can't decrypt). But in the disclosure phase the
//! prover *opens selected plaintext* to the verifier, and because this notary
//! digests the request/response **bodies**, the prover must disclose them — so the
//! notary does see the prompt and the LLM response in plaintext. It is therefore
//! **trusted for privacy**, not blind. A blind notary (signing over commitments it
//! cannot read) is specifically what MPC + presentation buys. End-game is to run
//! this as an independent third party or inside a TEE; for the PoC we operate it
//! ourselves, but as a **separate process with its own key**, which is what
//! preserves the guarantee against the reseller.
//!
//! Env knobs:
//!   NOTARY_LISTEN   address the prover (reseller) connects to (default 0.0.0.0:7047)
//!   UPSTREAM_HOST   server to proxy to and attest (default api.anthropic.com)
//!   UPSTREAM_PORT   server port (default 443)
//!   NOTARY_SEED     deterministic notary key seed (default "demo-notary-key")
//!
//! Run: `cd tls-notary && cargo run` (cd in so the rust-toolchain.toml pin applies)

use std::{env, sync::Arc};

use anyhow::{anyhow, Result};
use futures::io::AsyncWriteExt as _;
use provably_core::{sha256_hex, LegClaim};
use provably_transport::Notary;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;

use tlsn::{
    config::verifier::VerifierConfig,
    connection::ServerName,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
    Session,
};

struct Config {
    upstream_host: String,
    upstream_port: u16,
    root_store: RootCertStore,
    notary: Notary,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let listen = env::var("NOTARY_LISTEN").unwrap_or_else(|_| "0.0.0.0:7047".into());
    let upstream_host = env::var("UPSTREAM_HOST").unwrap_or_else(|_| "api.anthropic.com".into());
    let upstream_port: u16 = env::var("UPSTREAM_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(443);
    let seed = env::var("NOTARY_SEED").unwrap_or_else(|_| "demo-notary-key".into());

    let notary = Notary::from_seed(&seed);
    let pubkey = notary.public_key_hex();

    let cfg = Arc::new(Config {
        upstream_host,
        upstream_port,
        // Real servers (e.g. api.anthropic.com) chain to Mozilla's roots. For an
        // offline/self-signed test target, swap this for a custom RootCertStore.
        root_store: RootCertStore::mozilla(),
        notary,
    });

    let listener = TcpListener::bind(&listen).await?;
    println!("tls-notary (proxy mode) listening on {listen}");
    println!("  notary pubkey : {pubkey}");
    println!(
        "  proxying to   : {}:{}  (attested via its TLS certificate)",
        cfg.upstream_host, cfg.upstream_port
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = notarize_session(stream, cfg).await {
                tracing::error!("session from {peer} failed: {e:#}");
            }
        });
    }
}

/// Verify one prover session in proxy mode and sign the witnessed leg.
async fn notarize_session(prover_stream: TcpStream, cfg: Arc<Config>) -> Result<()> {
    // The control session between this notary and the prover (reseller).
    let session = Session::new(prover_stream.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let verifier_config = VerifierConfig::builder()
        .root_store(cfg.root_store.clone())
        .build()
        .map_err(|e| anyhow!("verifier config: {e}"))?;

    // Inspect the protocol the prover requested. This notary serves proxy mode
    // only; reject an MPC request rather than silently doing something else.
    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(v) => {
            v.reject(Some("this notary runs in proxy mode only")).await?;
            return Err(anyhow!("prover requested MPC mode; rejected"));
        }
        VerifierCommitStart::Proxy(v) => {
            // Proxy mode: we open the connection to the server and shuttle the
            // (encrypted) traffic between prover and server.
            let server =
                TcpStream::connect((cfg.upstream_host.as_str(), cfg.upstream_port)).await?;
            server.set_nodelay(true)?;
            v.accept().await?.run(server.compat()).await?
        }
    };

    // Receive the prover's disclosure request and require the server identity.
    let verifier = verifier.verify().await?;
    if !verifier.request().server_identity() {
        let verifier = verifier
            .reject(Some("server identity must be revealed"))
            .await?;
        verifier.close().await?;
        return Err(anyhow!("prover did not reveal the server name"));
    }

    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier.accept().await?;

    // The independently-witnessed connection time, not our wall clock — that
    // attested timestamp is the whole point of having a notary.
    let witnessed_time = verifier.tls_transcript().time();
    verifier.close().await?;

    // Tear down the session and reclaim the raw socket so we can hand the signed
    // attestation back to the prover.
    handle.close();
    let mut socket = driver_task.await??;

    let ServerName::Dns(dns) =
        server_name.ok_or_else(|| anyhow!("prover did not reveal server name"))?;
    let host = dns.as_str().to_string();
    let transcript = transcript.ok_or_else(|| anyhow!("prover revealed no transcript data"))?;

    // This notary serves a single upstream by construction. The proxied TLS
    // handshake already fails unless the server's cert matches the prover's
    // server_name, but assert the witnessed host is the one we dialed so a
    // misconfiguration is loud rather than silently attesting the wrong server.
    if host != cfg.upstream_host {
        return Err(anyhow!(
            "witnessed server {host:?} != configured upstream {:?}",
            cfg.upstream_host
        ));
    }

    // What we cryptographically verified crossed this connection.
    let sent = transcript.sent_unsafe();
    let received = transcript.received_unsafe();
    let (method, path) = request_line(sent);
    let status = status_code(received);

    // Digest the *bodies* (matching how the reseller/buyer hash the payload they
    // exchange), not the full HTTP framing. CONTRACT, not optional: this naive
    // "after the first blank line" split only equals the bytes the reseller
    // delivers to the buyer when the prover forces `Accept-Encoding: identity`
    // (tlsn does not support compression) AND the response is not chunked. The
    // prover wiring must guarantee that, or this notary must instead parse via
    // tlsn-formats `HttpTranscript` and de-chunk. Until then a chunked/compressed
    // upstream will make the buyer's "output == leg response" check fail.
    let claim = LegClaim {
        host: host.clone(),
        method,
        path,
        request_digest: sha256_hex(http_body(sent)),
        response_digest: sha256_hex(http_body(received)),
        response_status: status,
        timestamp: witnessed_time.to_string(),
    };

    // Sign as the separate witnessing party. The reseller cannot produce this.
    let attestation = cfg.notary.attest(claim);
    let json = serde_json::to_vec(&attestation)?;

    tracing::info!(%host, status, "verified TLS session; signed leg attestation");
    tracing::debug!(attestation = %String::from_utf8_lossy(&json));

    // Hand the signed attestation back to the prover (best-effort: the prover
    // side that consumes it is wired separately).
    //
    // Wire protocol the prover MUST match: the notary writes the JSON-serialized
    // `LegAttestation` then closes the stream; the prover reads to EOF and
    // deserializes. Unframed — the length is implied by EOF, so nothing may follow.
    if let Err(e) = async {
        socket.write_all(&json).await?;
        socket.close().await?;
        anyhow::Ok(())
    }
    .await
    {
        tracing::warn!("could not return attestation to prover: {e}");
    }

    Ok(())
}

/// Body bytes after the first blank line; falls back to the whole buffer.
fn http_body(buf: &[u8]) -> &[u8] {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &buf[i + 4..])
        .unwrap_or(buf)
}

/// `(method, path)` parsed from the HTTP request line.
fn request_line(buf: &[u8]) -> (String, String) {
    let line = buf.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or(&[]);
    let s = String::from_utf8_lossy(line);
    let mut it = s.split_whitespace();
    (
        it.next().unwrap_or_default().to_string(),
        it.next().unwrap_or_default().to_string(),
    )
}

/// HTTP status code parsed from the response status line.
fn status_code(buf: &[u8]) -> u16 {
    let line = buf.split(|&b| b == b'\r' || b == b'\n').next().unwrap_or(&[]);
    String::from_utf8_lossy(line)
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}
