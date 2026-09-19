use std::collections::HashMap;
use std::sync::RwLock;

use vcp_types::{ChallengeRequest, CapabilityGrant, VcpReceipt, VcpError};
use uuid::Uuid;

pub enum SessionState {
    Challenged { challenge: ChallengeRequest },
    Active     { grant: CapabilityGrant },
    Completed  { receipt: VcpReceipt },
    Revoked    { reason: String },
}

pub struct SessionStore {
    sessions: RwLock<HashMap<Uuid, SessionState>>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self { sessions: RwLock::new(HashMap::new()) }
    }

    pub fn insert_challenged(&self, session_id: Uuid, challenge: ChallengeRequest) {
        let mut map = self.sessions.write().unwrap();
        map.insert(session_id, SessionState::Challenged { challenge });
    }

    pub fn get_challenge(&self, session_id: Uuid) -> Option<ChallengeRequest> {
        let map = self.sessions.read().unwrap();
        match map.get(&session_id) {
            Some(SessionState::Challenged { challenge }) => Some(challenge.clone()),
            _ => None,
        }
    }

    pub fn activate(&self, session_id: Uuid, grant: CapabilityGrant) -> Result<(), VcpError> {
        let mut map = self.sessions.write().unwrap();
        match map.get(&session_id) {
            Some(SessionState::Challenged { challenge: _ }) => {
                map.insert(session_id, SessionState::Active { grant });
                Ok(())
            }
            _ => Err(VcpError::SessionNotFound { session_id: session_id.to_string() }),
        }
    }

    /// Transition session to Completed, auto-stamping `gix1_canonical_id` if absent.
    ///
    /// GIX Phase 4: every VcpReceipt gets a canonical GIX1 id
    /// (Receipt, MeshDevice, receipt_id) before being stored.
    pub fn complete(&self, session_id: Uuid, mut receipt: VcpReceipt) -> Result<(), VcpError> {
        if receipt.gix1_canonical_id.is_none() {
            let created_at_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let env = gix_types::Gix1::new(
                gix_types::GixKind::Receipt,
                gix_types::GixNamespace::MeshDevice,
                receipt.receipt_id.to_string().as_bytes(),
                None,
                created_at_ms,
                gix_types::RoutingHints::default(),
            );
            receipt.gix1_canonical_id = Some(hex::encode(env.canonical_id));
        }
        let mut map = self.sessions.write().unwrap();
        match map.get(&session_id) {
            Some(SessionState::Active { .. }) => {
                map.insert(session_id, SessionState::Completed { receipt });
                Ok(())
            }
            _ => Err(VcpError::SessionNotFound { session_id: session_id.to_string() }),
        }
    }

    pub fn revoke(&self, session_id: Uuid, reason: String) {
        let mut map = self.sessions.write().unwrap();
        map.insert(session_id, SessionState::Revoked { reason });
    }

    pub fn get_grant(&self, session_id: Uuid) -> Option<CapabilityGrant> {
        let map = self.sessions.read().unwrap();
        match map.get(&session_id) {
            Some(SessionState::Active { grant }) => Some(grant.clone()),
            _ => None,
        }
    }

    pub fn get_receipt(&self, session_id: Uuid) -> Option<VcpReceipt> {
        let map = self.sessions.read().unwrap();
        match map.get(&session_id) {
            Some(SessionState::Completed { receipt }) => Some(receipt.clone()),
            _ => None,
        }
    }
}

impl Default for SessionStore {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod gix_tests {
    use super::*;
    use vcp_types::{ChallengeRequest, CapabilityGrant, GrantScope};
    use vcp_types::device::SafetyClass;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_grant(session_id: Uuid) -> CapabilityGrant {
        CapabilityGrant {
            grant_id:         Uuid::new_v4(),
            challenge_id:     Uuid::new_v4(),
            device_id:        "dev-001".into(),
            agent_did:        "did:test:agent".into(),
            session_id,
            scope:            GrantScope::Exclusive,
            granted_caps:     vec![],
            max_safety:       SafetyClass::Observer,
            issued_at:        Utc::now(),
            expires_at:       Utc::now(),
            agent_signature:  String::new(),
            parent_signature: None,
        }
    }

    fn make_receipt() -> VcpReceipt {
        VcpReceipt {
            receipt_id:        Uuid::new_v4(),
            session_id:        Uuid::new_v4(),
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

    fn activated_session() -> (SessionStore, Uuid) {
        let store = SessionStore::new();
        let sid = Uuid::new_v4();
        let challenge = ChallengeRequest {
            challenge_id:     Uuid::new_v4(),
            nonce:            "abc".into(),
            issued_at:        Utc::now(),
            expires_in_secs:  60,
            required_caps:    vec![],
            required_safety:  SafetyClass::Observer,
        };
        store.insert_challenged(sid, challenge);
        let grant = make_grant(sid);
        store.activate(sid, grant).unwrap();
        (store, sid)
    }

    #[test]
    fn complete_auto_stamps_gix1() {
        let (store, sid) = activated_session();
        let receipt = make_receipt();
        assert!(receipt.gix1_canonical_id.is_none());
        store.complete(sid, receipt).unwrap();
        let stored = store.get_receipt(sid).unwrap();
        assert!(stored.gix1_canonical_id.is_some());
        let hex = stored.gix1_canonical_id.unwrap();
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn complete_preserves_existing_gix1() {
        let (store, sid) = activated_session();
        let mut receipt = make_receipt();
        receipt.gix1_canonical_id = Some("a".repeat(64));
        store.complete(sid, receipt).unwrap();
        let stored = store.get_receipt(sid).unwrap();
        assert_eq!(stored.gix1_canonical_id.unwrap(), "a".repeat(64));
    }
}
