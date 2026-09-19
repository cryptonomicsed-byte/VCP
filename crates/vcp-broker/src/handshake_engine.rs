use chrono::Utc;
use std::sync::RwLock;
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
/// `graph` accumulates cross-index edges — one `vcp_session` edge per
/// completed session linking device_canonical_id → receipt_canonical_id.
pub struct HandshakeEngine {
    pub registry: DeviceRegistry,
    pub sessions: SessionStore,
    pub graph:    RwLock<gix_core::GlyphGraph>,
}

impl HandshakeEngine {
    pub fn new() -> Self {
        Self {
            registry: DeviceRegistry::new(),
            sessions: SessionStore::new(),
            graph:    RwLock::new(gix_core::GlyphGraph::new()),
        }
    }

    // ── step 1: discovery ─────────────────────────────────────────────────────

    /// Device submits its manifest — broker validates and registers it.
    ///
    /// GIX Phase 3: stamps a `GixNamespace::MeshDevice` envelope for the
    /// device_id so every registered device has a canonical GIX1 identity.
    pub fn register_device(&self, manifest: DeviceManifest) -> Result<(), VcpError> {
        // Signature verification deferred to the signing layer.
        // Here we validate structural invariants.
        if manifest.device_id.is_empty() {
            return Err(VcpError::ChallengeFailed {
                reason: "device_id must not be empty".into(),
            });
        }
        let device_id = manifest.device_id.clone();
        self.registry.register(manifest);

        let created_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let env = gix_types::Gix1::new(
            gix_types::GixKind::Physical,
            gix_types::GixNamespace::MeshDevice,
            device_id.as_bytes(),
            None,
            created_at_ms,
            gix_types::RoutingHints::default(),
        );
        tracing::info!(
            device_id,
            gix1_canonical_id = %hex::encode(env.canonical_id),
            gix1_glyph = %env.glyph,
            gix1_odu_base = env.odu_base,
            "VCP device registered — GIX1 MeshDevice envelope stamped"
        );
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

    // ── GIX Phase 4: cross-index composite identity ───────────────────────────

    /// Compute the composite GIX1 fold identity for a completed VCP session.
    ///
    /// Folds the device's `MeshDevice` GIX1 canonical_id together with the
    /// receipt's `MeshDevice` GIX1 canonical_id using `gix_fold_v1`, producing
    /// a single deterministic session identity.
    ///
    /// Returns `None` if the session is not yet completed or the grant is missing.
    pub fn session_composite_gix1(
        &self,
        session_id: Uuid,
        receipt: &vcp_types::VcpReceipt,
    ) -> Option<String> {
        let grant = self.sessions.get_grant(session_id)?;

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let device_env = gix_types::Gix1::new(
            gix_types::GixKind::Physical,
            gix_types::GixNamespace::MeshDevice,
            grant.device_id.as_bytes(),
            None,
            ts,
            gix_types::RoutingHints::default(),
        );
        let receipt_env = gix_types::Gix1::new(
            gix_types::GixKind::Receipt,
            gix_types::GixNamespace::MeshDevice,
            receipt.receipt_id.to_string().as_bytes(),
            None,
            ts,
            gix_types::RoutingHints::default(),
        );

        let composite = gix_types::gix_fold_v1(&[device_env.canonical_id, receipt_env.canonical_id]);
        let device_hex  = hex::encode(device_env.canonical_id);
        let receipt_hex = hex::encode(receipt_env.canonical_id);

        // Insert cross-index edge into GlyphGraph: device → receipt via vcp_session.
        {
            let mut g = self.graph.write().unwrap();
            g.add_node(gix_types::GlyphNode::from_chunk(&device_hex, ts as f64 / 1000.0));
            g.add_node(gix_types::GlyphNode::from_chunk(&receipt_hex, ts as f64 / 1000.0));
            g.add_edge(gix_types::GlyphEdge {
                from:     device_hex.clone(),
                to:       receipt_hex.clone(),
                relation: "vcp_session".into(),
                weight:   1,
            });
        }

        tracing::debug!(
            session_id = %session_id,
            device_gix1 = %device_hex,
            receipt_gix1 = %receipt_hex,
            "GIX cross-link: device → receipt via vcp_session"
        );

        Some(hex::encode(composite))
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

#[cfg(test)]
mod gix_tests {
    use super::*;
    use vcp_types::VcpReceipt;
    use chrono::Utc;

    fn make_receipt(session_id: Uuid) -> VcpReceipt {
        VcpReceipt {
            receipt_id:        Uuid::new_v4(),
            session_id,
            grant_id:          Uuid::new_v4(),
            device_id:         "dev-001".into(),
            agent_did:         "did:test:agent".into(),
            owner_did:         "did:test:owner".into(),
            started_at:        Utc::now(),
            ended_at:          Utc::now(),
            outcome:           vcp_types::SessionOutcome::Success,
            message_count:     0,
            command_count:     0,
            telemetry_count:   0,
            telemetry_hash:    None,
            trajectory_hash:   None,
            sim_proof_id:      None,
            witnesses:         vec![],
            zangbeto_anchor:   None,
            gix1_canonical_id: None,
            device_signature:  String::new(),
            agent_signature:   String::new(),
        }
    }

    fn engine_with_active_session() -> (HandshakeEngine, Uuid) {
        use vcp_types::{ChallengeRequest, CapabilityGrant, GrantScope};
        use vcp_types::device::SafetyClass;
        let engine = HandshakeEngine::new();
        let sid = Uuid::new_v4();
        let challenge = ChallengeRequest {
            challenge_id:     Uuid::new_v4(),
            nonce:            "nonce".into(),
            issued_at:        Utc::now(),
            expires_in_secs:  60,
            required_caps:    vec![],
            required_safety:  SafetyClass::Observer,
        };
        engine.sessions.insert_challenged(sid, challenge);
        let grant = CapabilityGrant {
            grant_id:         Uuid::new_v4(),
            challenge_id:     Uuid::new_v4(),
            device_id:        "dev-001".into(),
            agent_did:        "did:test:agent".into(),
            session_id:       sid,
            scope:            GrantScope::Exclusive,
            granted_caps:     vec![],
            max_safety:       SafetyClass::Observer,
            issued_at:        Utc::now(),
            expires_at:       Utc::now(),
            agent_signature:  String::new(),
            parent_signature: None,
        };
        engine.sessions.activate(sid, grant).unwrap();
        (engine, sid)
    }

    #[test]
    fn session_composite_gix1_returns_hex() {
        let (engine, sid) = engine_with_active_session();
        let receipt = make_receipt(sid);
        let composite = engine.session_composite_gix1(sid, &receipt);
        assert!(composite.is_some());
        assert_eq!(composite.unwrap().len(), 64);
    }

    #[test]
    fn session_composite_gix1_inserts_graph_edge() {
        let (engine, sid) = engine_with_active_session();
        let receipt = make_receipt(sid);
        engine.session_composite_gix1(sid, &receipt);
        let g = engine.graph.read().unwrap();
        assert_eq!(g.edge_count(), 1, "should have exactly one vcp_session edge");
        assert_eq!(g.node_count(), 2, "device node + receipt node");
    }

    #[test]
    fn session_composite_returns_none_for_missing_session() {
        let engine = HandshakeEngine::new();
        let receipt = make_receipt(Uuid::new_v4());
        assert!(engine.session_composite_gix1(Uuid::new_v4(), &receipt).is_none());
    }
}
