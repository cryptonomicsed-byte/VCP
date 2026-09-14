use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::SafetyClass;

/// The complete 7-step VCP handshake as a typed enum.
///
/// State machine:
///   Discovery → Challenge → Auth → CapNeg → Grant → (Session stream) → Receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case")]
pub enum HandshakeMessage {
    Discovery  { manifest_json: String },   // device → broker
    Challenge  (ChallengeRequest),          // broker → device
    Auth       (AuthResponse),              // device → broker
    CapNeg     (CapabilityNegotiation),     // broker → agent
    Grant      (CapabilityGrant),           // agent → device (broker relays)
    Revoke     (RevocationRecord),          // any party → device
}

// ── step 2: challenge ─────────────────────────────────────────────────────────

/// Broker challenges the device to prove its identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRequest {
    pub challenge_id:    Uuid,
    pub nonce:           String,          // 32 random bytes, hex-encoded
    pub issued_at:       DateTime<Utc>,
    pub expires_in_secs: u32,
    /// Capabilities the requesting agent requires (must be subset of DeviceManifest).
    pub required_caps:   Vec<String>,
    /// Safety class the agent claims it needs.
    pub required_safety: SafetyClass,
}

// ── step 3: auth ──────────────────────────────────────────────────────────────

/// Device proves it holds the private key matching its DeviceManifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub challenge_id:   Uuid,
    pub device_id:      String,
    /// Ed25519 signature over `challenge_id || nonce`.
    pub signature:      String,
    /// Agent DID this session is being established for (optional; broker verifies).
    pub agent_did:      Option<String>,
    pub responded_at:   DateTime<Utc>,
}

// ── step 4: capability negotiation ───────────────────────────────────────────

/// Broker informs the requesting agent what the device can offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityNegotiation {
    pub challenge_id:    Uuid,
    pub device_id:       String,
    /// Subset of DeviceCapability kinds the agent may use in this session.
    pub offered_caps:    Vec<String>,
    /// Maximum safety class the agent is permitted to invoke.
    pub max_safety:      SafetyClass,
    /// Proposed session duration ceiling.
    pub max_duration_secs: u32,
    /// Estimated cost in ASE micro-units (0 = free / sovereign node).
    pub estimated_cost_uase: u64,
}

// ── step 5: grant ─────────────────────────────────────────────────────────────

/// The capability grant — a signed, scoped, expiring authorization ticket.
///
/// Equivalent to an OAuth2 access token but for physical device actions.
/// The device validates this grant on every command it receives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub grant_id:        Uuid,
    pub challenge_id:    Uuid,
    pub device_id:       String,
    pub agent_did:       String,
    pub session_id:      Uuid,

    pub scope:           GrantScope,
    pub granted_caps:    Vec<String>,      // intersection of required + offered
    pub max_safety:      SafetyClass,

    pub issued_at:       DateTime<Utc>,
    pub expires_at:      DateTime<Utc>,

    /// Hex-encoded Ed25519 signature by the granting agent over canonical JSON
    /// of all fields above.
    pub agent_signature: String,
    /// Optional co-signature from a parent agent (T5+ delegation).
    pub parent_signature: Option<String>,
}

/// How broadly the grant applies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GrantScope {
    /// Agent inhabits the device exclusively for the session duration.
    Exclusive,
    /// Agent shares device with other sessions (read/observe only).
    Shared,
    /// One-shot: grant expires after a single command is executed.
    SingleUse,
}

// ── revocation ────────────────────────────────────────────────────────────────

/// Any party can revoke an active grant by broadcasting a RevocationRecord.
/// Devices MUST honour revocations immediately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRecord {
    pub grant_id:        Uuid,
    pub session_id:      Uuid,
    pub revoked_at:      DateTime<Utc>,
    pub reason:          RevocationReason,
    /// Hex-encoded Ed25519 signature by the revoking party.
    pub signature:       String,
    /// DID of the revoking party (agent, device owner, or broker).
    pub revoker_did:     String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    AgentRequest,
    DeviceOwnerOverride,
    BrokerSafetyViolation,
    GrantExpired,
    AuthenticationFailure,
    PolicyViolation(String),
}
