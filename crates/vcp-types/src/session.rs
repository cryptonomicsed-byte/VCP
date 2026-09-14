use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type SessionId = Uuid;

/// A single message exchanged during an active VCP session.
///
/// All messages are signed by the sender.  The device validates command
/// messages against the active CapabilityGrant before executing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMessage {
    pub session_id:  SessionId,
    pub sequence:    u64,              // monotonically increasing per session
    pub kind:        SessionMessageKind,
    pub timestamp:   DateTime<Utc>,
    /// Hex-encoded Ed25519 signature by the sender over canonical JSON.
    pub signature:   String,
    pub sender_did:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionMessageKind {
    /// Agent → device: execute an actuation command.
    Command {
        actuator: String,
        params:   serde_json::Value,
    },
    /// Device → agent: sensor observation or state update.
    Observation {
        sensor:  String,
        reading: serde_json::Value,
    },
    /// Device → agent: telemetry batch.
    Telemetry(Vec<TelemetryPoint>),
    /// Either party: human-readable status note.
    Note { text: String },
    /// Either party: request session termination.
    EndRequest { reason: String },
    /// Device → agent: error or safety alert.
    Alert {
        severity: AlertSeverity,
        code:     String,
        message:  String,
    },
    /// Device → agent: photo or video frame.
    Frame {
        media_type: String,    // "image/jpeg", "video/h264", etc.
        data_uri:   String,    // base64 data URI or blossom blob URL
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryPoint {
    pub channel:   String,
    pub value:     f64,
    pub unit:      String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    /// Session MUST be terminated immediately.
    Critical,
}
