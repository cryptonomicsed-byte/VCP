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

    pub fn complete(&self, session_id: Uuid, receipt: VcpReceipt) -> Result<(), VcpError> {
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
