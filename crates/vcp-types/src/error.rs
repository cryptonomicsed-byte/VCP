use thiserror::Error;

#[derive(Debug, Error)]
pub enum VcpError {
    #[error("device not found: {device_id}")]
    DeviceNotFound { device_id: String },

    #[error("session not found: {session_id}")]
    SessionNotFound { session_id: String },

    #[error("challenge failed: {reason}")]
    ChallengeFailed { reason: String },

    #[error("capability denied: agent {agent_id} lacks {capability}")]
    CapabilityDenied { agent_id: String, capability: String },

    #[error("grant expired: session {session_id}")]
    GrantExpired { session_id: String },

    #[error("grant revoked: {reason}")]
    GrantRevoked { reason: String },

    #[error("safety violation: {rule}")]
    SafetyViolation { rule: String },

    #[error("signature invalid")]
    SignatureInvalid,

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}
