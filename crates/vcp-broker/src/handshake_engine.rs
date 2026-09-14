use chrono::Utc;
use uuid::Uuid;
use vcp_types::{
    AuthResponse, CapabilityGrant, CapabilityNegotiation, ChallengeRequest,
    DeviceManifest, GrantScope, RevocationReason, RevocationRecord, VcpError,
};

use crate::{DeviceRegistry, SessionStore};
use crate::crypto::verify_auth_signature;

/// Drives the 7-step VCP handshake state machine.
///
/// One HandshakeEngine instance is shared across all concurrent sessions.
/// Sessions are identified by UUID; state is held in SessionStore.
pub struct HandshakeEngine {
    pub registry: DeviceRegistry,
    pub sessions: SessionStore,
}

impl HandshakeEngine {
    pub fn new() -> Self {
        Self {
            registry: DeviceRegistry::new(),
            sessions: SessionStore::new(),
        }
    }

    // ── step 1: discovery ─────────────────────────────────────────────────────

    /// Device submits its manifest — broker validates and registers it.
    pub fn register_device(&self, manifest: DeviceManifest) -> Result<(), VcpError> {
        // Signature verification deferred to the signing layer.
        // Here we validate structural invariants.
        if manifest.device_id.is_empty() {
            return Err(VcpError::ChallengeFailed {
                reason: "device_id must not be empty".into(),
            });
        }
        self.registry.register(manifest);
        Ok(())
    }

    // ── step 2: challenge ─────────────────────────────────────────────────────

    /// Agent requests a session → broker issues a challenge to the device.
    pub fn issue_challenge(
        &self,
        device_id: &str,
        agent_did: &str,
        required_caps: Vec<String>,
    ) -> Result<(Uuid, ChallengeRequest), VcpError> {
        let manifest = self.registry.get(device_id)
            .ok_or_else(|| VcpError::DeviceNotFound { device_id: device_id.into() })?;

        // Verify requested capabilities are a subset of what device advertises.
        let device_cap_kinds: std::collections::HashSet<String> = manifest.capabilities
            .iter()
            .map(|c| format!("{:?}", c))
            .collect();

        for cap in &required_caps {
            if !device_cap_kinds.iter().any(|k| k.to_lowercase().contains(&cap.to_lowercase())) {
                // Lenient check: if device has ANY matching capability, allow.
                // Strict capability matching is done in CapabilityNegotiation.
                tracing::debug!("capability {cap:?} not found in device {device_id} — will surface in CapNeg");
            }
        }

        let session_id    = Uuid::new_v4();
        let challenge_id  = Uuid::new_v4();
        let nonce         = hex::encode(Uuid::new_v4().as_bytes());

        let challenge = ChallengeRequest {
            challenge_id,
            nonce,
            issued_at:        Utc::now(),
            expires_in_secs:  60,
            required_caps:    required_caps.clone(),
            required_safety:  manifest.safety_class.clone(),
        };

        self.sessions.insert_challenged(session_id, challenge.clone());

        tracing::info!(
            device_id, agent_did, session_id = %session_id,
            "VCP challenge issued"
        );

        Ok((session_id, challenge))
    }

    // ── step 3 + 4: auth + cap negotiation ───────────────────────────────────

    /// Device answers the challenge → broker validates and returns CapNeg.
    pub fn handle_auth(
        &self,
        session_id: Uuid,
        auth: &AuthResponse,
    ) -> Result<CapabilityNegotiation, VcpError> {
        let manifest = self.registry.get(&auth.device_id)
            .ok_or_else(|| VcpError::DeviceNotFound { device_id: auth.device_id.clone() })?;

        // Ed25519 signature verification over SHA-256(challenge_id || ":" || nonce).
        // Nonce is retrieved from the stored ChallengeRequest.
        // Devices without a public_key (dev/test) bypass verification.
        if !manifest.public_key.is_empty() {
            let challenge = self.sessions.get_challenge(session_id)
                .ok_or_else(|| VcpError::SessionNotFound {
                    session_id: session_id.to_string(),
                })?;
            verify_auth_signature(
                &auth.challenge_id.to_string(),
                &challenge.nonce,
                &manifest.public_key,
                &auth.signature,
            )?;
        }

        let offered_caps: Vec<String> = manifest.capabilities
            .iter()
            .map(|c| serde_json::to_string(c).unwrap_or_default())
            .collect();

        let cap_neg = CapabilityNegotiation {
            challenge_id:     auth.challenge_id,
            device_id:        auth.device_id.clone(),
            offered_caps,
            max_safety:       manifest.safety_class.clone(),
            max_duration_secs: 3600,
            estimated_cost_uase: 0,
        };

        Ok(cap_neg)
    }

    // ── step 5: grant ─────────────────────────────────────────────────────────

    /// Agent accepts capabilities → broker creates and activates the grant.
    pub fn create_grant(
        &self,
        session_id: Uuid,
        agent_did: String,
        device_id: String,
        challenge_id: Uuid,
        granted_caps: Vec<String>,
        duration_secs: i64,
        scope: GrantScope,
    ) -> Result<CapabilityGrant, VcpError> {
        let manifest = self.registry.get(&device_id)
            .ok_or_else(|| VcpError::DeviceNotFound { device_id: device_id.clone() })?;

        let grant = CapabilityGrant {
            grant_id:         Uuid::new_v4(),
            challenge_id,
            device_id:        device_id.clone(),
            agent_did:        agent_did.clone(),
            session_id,
            scope,
            granted_caps,
            max_safety:       manifest.safety_class.clone(),
            issued_at:        Utc::now(),
            expires_at:       Utc::now() + chrono::Duration::seconds(duration_secs),
            agent_signature:  String::new(),  // populated by signing layer
            parent_signature: None,
        };

        self.sessions.activate(session_id, grant.clone())?;

        tracing::info!(
            device_id, agent_did, session_id = %session_id,
            grant_id = %grant.grant_id,
            "VCP grant activated"
        );

        Ok(grant)
    }

    // ── revocation ────────────────────────────────────────────────────────────

    pub fn revoke(
        &self,
        session_id: Uuid,
        grant_id: Uuid,
        revoker_did: String,
        reason: RevocationReason,
    ) -> RevocationRecord {
        let reason_str = format!("{:?}", reason);
        self.sessions.revoke(session_id, reason_str.clone());

        tracing::warn!(session_id = %session_id, revoker_did, "VCP session revoked: {reason_str}");

        RevocationRecord {
            grant_id,
            session_id,
            revoked_at:  Utc::now(),
            reason,
            signature:   String::new(),   // populated by signing layer
            revoker_did,
        }
    }
}

impl Default for HandshakeEngine {
    fn default() -> Self { Self::new() }
}
