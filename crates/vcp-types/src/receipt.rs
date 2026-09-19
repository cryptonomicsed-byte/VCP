use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::session::SessionId;

/// The canonical audit trail produced at session end.
///
/// A VcpReceipt is the VCP equivalent of UCX ComputeReceipt.  Both flow
/// through the Action Receipt Protocol v1 as `kind = "vcp_session"`.
///
/// Zàngbétò anchors this receipt by setting `zangbeto_anchor` after the
/// ucx-osovm integration layer processes it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VcpReceipt {
    pub receipt_id:      Uuid,
    pub session_id:      SessionId,
    pub grant_id:        Uuid,

    pub device_id:       String,
    pub agent_did:       String,
    pub owner_did:       String,

    pub started_at:      DateTime<Utc>,
    pub ended_at:        DateTime<Utc>,

    pub outcome:         SessionOutcome,
    pub message_count:   u64,
    pub command_count:   u64,
    pub telemetry_count: u64,

    /// SHA-256 of the ordered telemetry stream (deterministic commitment).
    pub telemetry_hash:  Option<String>,
    /// SHA-256 of any trajectory data recorded.
    pub trajectory_hash: Option<String>,
    /// Link to the sim proof that preceded physical execution (if any).
    pub sim_proof_id:    Option<String>,

    pub witnesses:       Vec<WitnessAttestation>,

    /// Set by ucx-osovm integration after Zàngbétò settlement.
    pub zangbeto_anchor: Option<String>,

    /// GIX1 canonical_id (hex SHA-256) for this receipt — set by the caller
    /// after computing `Gix1::new(Receipt, MeshDevice, receipt_id.as_bytes(), ...)`.
    #[serde(default)]
    pub gix1_canonical_id: Option<String>,

    /// Hex-encoded Ed25519 signature by the device over canonical JSON.
    pub device_signature: String,
    /// Hex-encoded Ed25519 signature by the agent over canonical JSON.
    pub agent_signature:  String,
}

impl VcpReceipt {
    /// SHA-256 commitment over the receipt's canonical fields.
    pub fn hash(&self) -> String {
        let canonical = serde_json::json!({
            "receipt_id":      self.receipt_id,
            "session_id":      self.session_id,
            "grant_id":        self.grant_id,
            "device_id":       self.device_id,
            "agent_did":       self.agent_did,
            "started_at":      self.started_at,
            "ended_at":        self.ended_at,
            "outcome":         self.outcome,
            "message_count":   self.message_count,
            "telemetry_hash":  self.telemetry_hash,
            "trajectory_hash": self.trajectory_hash,
        });
        let mut hasher = Sha256::new();
        hasher.update(canonical.to_string().as_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionOutcome {
    /// Mission completed as intended.
    Success,
    /// Session ended by agent request before mission complete.
    AgentTerminated,
    /// Session ended by device owner override.
    OwnerRevoked,
    /// Broker detected safety violation and terminated.
    SafetyViolation,
    /// Connectivity loss — device entered autonomous failsafe.
    ConnectivityLoss,
    /// Hardware fault.
    DeviceFault,
}

/// A signed observation from a physical witness node.
///
/// Maps to Nostr kind 31020 (Capture Receipt) when anchored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessAttestation {
    pub witness_id:   String,
    pub attested_at:  DateTime<Utc>,
    /// What the witness physically observed.
    pub observation:  String,
    pub outcome_hash: String,
    /// Base64-encoded Ed25519 signature.
    pub signature:    String,
}
