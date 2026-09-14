//! vcp-broker — HTTP server for the Vantage Connection Protocol handshake engine.
//!
//! Config (env vars):
//!   VCP_PORT         — listen port (default 7791)
//!   VANTAGE_URL      — Vantage base URL (optional, forwards device registration)
//!   VANTAGE_KEY      — Vantage API key
//!
//! Routes:
//!   POST /api/devices/register          — device submits DeviceManifest
//!   GET  /api/devices                   — list fresh devices
//!   GET  /api/devices/:id               — get device manifest
//!   POST /api/sessions                  — agent requests session (returns challenge)
//!   POST /api/sessions/:id/auth         — device answers challenge (returns CapNeg)
//!   POST /api/sessions/:id/grant        — agent accepts capabilities (returns Grant)
//!   DELETE /api/sessions/:id            — revoke session
//!   GET  /api/sessions/:id/receipt      — retrieve completed session receipt
//!   GET  /health                        — liveness probe

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use vcp_broker::{HandshakeEngine};
use vcp_types::{DeviceManifest, GrantScope};

#[derive(Clone)]
struct AppState {
    engine: Arc<HandshakeEngine>,
}

// ── handlers ──────────────────────────────────────────────────────────────────

async fn register_device(
    State(s): State<AppState>,
    Json(manifest): Json<DeviceManifest>,
) -> impl IntoResponse {
    match s.engine.register_device(manifest.clone()) {
        Ok(()) => (StatusCode::OK, Json(json!({
            "ok": true,
            "device_id": manifest.device_id,
        }))),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "error": e.to_string() }))),
    }
}

async fn list_devices(State(s): State<AppState>) -> impl IntoResponse {
    let devices = s.engine.registry.list_fresh();
    Json(json!({ "devices": devices }))
}

async fn get_device(
    State(s): State<AppState>,
    Path(device_id): Path<String>,
) -> impl IntoResponse {
    match s.engine.registry.get(&device_id) {
        Some(m) => (StatusCode::OK,       Json(json!(m))),
        None    => (StatusCode::NOT_FOUND, Json(json!({ "error": "device not found or stale" }))),
    }
}

#[derive(Deserialize)]
struct RequestSessionBody {
    device_id:     String,
    agent_did:     String,
    required_caps: Option<Vec<String>>,
}

async fn request_session(
    State(s): State<AppState>,
    Json(body): Json<RequestSessionBody>,
) -> impl IntoResponse {
    let caps = body.required_caps.unwrap_or_default();
    match s.engine.issue_challenge(&body.device_id, &body.agent_did, caps) {
        Ok((session_id, challenge)) => (StatusCode::OK, Json(json!({
            "session_id": session_id,
            "challenge":  challenge,
        }))),
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "error": e.to_string() }))),
    }
}

async fn auth_session(
    State(s): State<AppState>,
    Path(session_id_str): Path<String>,
    Json(auth): Json<vcp_types::AuthResponse>,
) -> impl IntoResponse {
    let session_id = match Uuid::parse_str(&session_id_str) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid session_id" }))),
    };
    match s.engine.handle_auth(session_id, &auth) {
        Ok(cap_neg) => (StatusCode::OK, Json(json!(cap_neg))),
        Err(e)      => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "error": e.to_string() }))),
    }
}

#[derive(Deserialize)]
struct CreateGrantBody {
    agent_did:     String,
    device_id:     String,
    challenge_id:  Uuid,
    granted_caps:  Vec<String>,
    duration_secs: Option<i64>,
    scope:         Option<String>,
}

async fn create_grant(
    State(s): State<AppState>,
    Path(session_id_str): Path<String>,
    Json(body): Json<CreateGrantBody>,
) -> impl IntoResponse {
    let session_id = match Uuid::parse_str(&session_id_str) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid session_id" }))),
    };
    let scope = match body.scope.as_deref() {
        Some("Shared")    => GrantScope::Shared,
        Some("SingleUse") => GrantScope::SingleUse,
        _                 => GrantScope::Exclusive,
    };
    match s.engine.create_grant(
        session_id,
        body.agent_did,
        body.device_id,
        body.challenge_id,
        body.granted_caps,
        body.duration_secs.unwrap_or(3600),
        scope,
    ) {
        Ok(grant) => (StatusCode::OK, Json(json!(grant))),
        Err(e)    => (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({ "error": e.to_string() }))),
    }
}

async fn revoke_session(
    State(s): State<AppState>,
    Path(session_id_str): Path<String>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let session_id = match Uuid::parse_str(&session_id_str) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid session_id" }))),
    };
    let grant_id    = Uuid::new_v4();
    let revoker_did = body["revoker_did"].as_str().unwrap_or("unknown").to_string();
    let record = s.engine.revoke(
        session_id, grant_id, revoker_did,
        vcp_types::RevocationReason::AgentRequest,
    );
    (StatusCode::OK, Json(json!(record)))
}

async fn get_receipt(
    State(s): State<AppState>,
    Path(session_id_str): Path<String>,
) -> impl IntoResponse {
    let session_id = match Uuid::parse_str(&session_id_str) {
        Ok(id) => id,
        Err(_) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": "invalid session_id" }))),
    };
    match s.engine.sessions.get_receipt(session_id) {
        Some(r) => {
            let hash = r.hash();
            (StatusCode::OK, Json(json!({ "receipt": r, "receipt_hash": hash })))
        }
        None => (StatusCode::NOT_FOUND, Json(json!({ "error": "no receipt for this session" }))),
    }
}

async fn health() -> impl IntoResponse {
    Json(json!({ "ok": true, "service": "vcp-broker" }))
}

// ── startup ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let port: u16 = std::env::var("VCP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(7791);

    let engine = Arc::new(HandshakeEngine::new());
    let state  = AppState { engine };

    let app = Router::new()
        .route("/api/devices/register",        post(register_device))
        .route("/api/devices",                 get(list_devices))
        .route("/api/devices/{id}",             get(get_device))
        .route("/api/sessions",                post(request_session))
        .route("/api/sessions/{id}/auth",       post(auth_session))
        .route("/api/sessions/{id}/grant",      post(create_grant))
        .route("/api/sessions/{id}",            delete(revoke_session))
        .route("/api/sessions/{id}/receipt",    get(get_receipt))
        .route("/health",                      get(health))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("vcp-broker listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
