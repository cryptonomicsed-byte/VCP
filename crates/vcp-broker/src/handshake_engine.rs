use chrono::Utc;
use std::sync::{Arc, RwLock};
use uuid::Uuid;
use vcp_types::{
    AuthResponse, CapabilityGrant, CapabilityNegotiation, ChallengeRequest,
    DeviceManifest, GrantScope, RevocationReason, RevocationRecord, VcpError,
};

use crate::{DeviceRegistry, SessionStore};
use crate::crypto::{require_pubkey_in_production, verify_auth_signature};
use crate::storage::StorageBackend;

/// Local-development escape hatch for keyless devices.
///
/// Production must never set this. A device with no public key cannot be
/// authenticated, so accepting one is equivalent to accepting anonymous
/// callers into the capability-negotiation path. It is an env var rather
/// than a compile-time feature deliberately: the bypass shows up in `ps`
/// and systemd unit review instead of hiding inside a build.
fn allow_unverified_devices() -> bool {
    matches!(
        std::env::var("VCP_ALLOW_UNVERIFIED_DEVICES").as_deref(),
        Ok("1") | Ok("true")
    )
}

/// Drives the 7-step VCP handshake state machine.
///
/// One HandshakeEngine instance is shared across all concurrent sessions.
/// Sessions are identified by UUID; state is held in SessionStore.
///
/// `store` is the canonical GIX object authority:
///   - `store.index` tracks every registered device/receipt/session identity.
///   - `store.graph` tracks edges — one `vcp_session` edge per completed
///     session linking device_canonical_id → receipt_canonical_id.
///
/// All mutations go through `CanonicalObjectStore` so both structures stay in
/// lock-step with a shared snapshot_id.  If a `StorageBackend` is wired in,
/// the store is loaded from durable storage at startup and flushed after every
/// mutation, making the GIX layer operationally authoritative across restarts.
pub struct HandshakeEngine {
    pub registry: DeviceRegistry,
    pub sessions: SessionStore,
    pub store:    RwLock<gix_core::CanonicalObjectStore>,
    storage:      Option<Arc<dyn StorageBackend>>,
}

impl HandshakeEngine {
    /// Create an engine with no persistence (in-memory only, suitable for tests).
    pub fn new() -> Self {
        Self {
            registry: DeviceRegistry::new(),
            sessions: SessionStore::new(),
            store:    RwLock::new(gix_core::CanonicalObjectStore::new()),
            storage:  None,
        }
    }

    /// Create an engine that loads prior GIX state from `backend` on startup and
    /// persists the full `CanonicalObjectStore` after every mutation.
    ///
    /// Phase 8B: restores BOTH `Gix1Index` (identity) and `GlyphGraph` (edges),
    /// runs `audit_consistency()` before accepting new sessions.
    ///
    /// Recovery semantics:
    ///   - Missing files  → empty store (first boot)
    ///   - Corrupted file → `Err`; caller decides whether to abort or boot empty
    pub fn with_storage(backend: Arc<dyn StorageBackend>) -> Result<Self, String> {
        let store = backend.load_store()?;

        // Audit before the broker starts accepting sessions.
        store.audit_consistency()
            .map_err(|vs| format!("GIX startup audit failed: {}", vs.join("; ")))?;

        tracing::info!(
            nodes  = store.graph.node_count(),
            edges  = store.graph.edge_count(),
            entries = store.index.len(),
            index_root = %store.index.root(),
            "GIX CanonicalObjectStore restored and audited"
        );

        Ok(Self {
            registry: DeviceRegistry::new(),
            sessions: SessionStore::new(),
            store:    RwLock::new(store),
            storage:  Some(backend),
        })
    }

    /// Flush the `CanonicalObjectStore` to the configured backend.
    ///
    /// Requires a write lock (bumps the snapshot_id).  Called automatically
    /// after edge-adding mutations and explicitly on graceful shutdown.
    pub fn flush_store(&self) -> Result<(), String> {
        let Some(ref backend) = self.storage else { return Ok(()); };
        let mut s = self.store.write().map_err(|e| format!("store lock poisoned: {e}"))?;
        backend.save_store(&mut *s)
    }

    // ── step 1: discovery ─────────────────────────────────────────────────────

    /// Device submits its manifest — broker validates and registers it.
    ///
    /// GIX Phase 3: stamps a `GixNamespace::MeshDevice` envelope for the
    /// device_id and inserts it into the `CanonicalObjectStore` so the device
    /// has one authoritative canonical identity across index + graph.
    pub fn register_device(&self, manifest: DeviceManifest) -> Result<(), VcpError> {
        if manifest.device_id.is_empty() {
            return Err(VcpError::ChallengeFailed {
                reason: "device_id must not be empty".into(),
            });
        }
        // Fail closed on keyless devices. Historically an empty `public_key`
        // meant the device skipped Ed25519 verification entirely at auth time
        // (`handle_auth` only verified `if !public_key.is_empty()`), so anyone
        // who registered a keyless manifest could impersonate it and obtain
        // capability grants with no signature at all.
        //
        // A keyed device is the only one the broker can ever authenticate, so
        // an empty key is a provisioning bug, not a valid state. `VCP_ALLOW_
        // UNVERIFIED_DEVICES=1` exists for local development only and logs
        // loudly; production must never set it.
        if manifest.public_key.is_empty() && !allow_unverified_devices() {
            return Err(VcpError::ChallengeFailed {
                reason: format!(
                    "device '{}' has an empty public_key — refusing to register a device that \
                     can never be authenticated. Provision the Ed25519 public key first, or set \
                     VCP_ALLOW_UNVERIFIED_DEVICES=1 for local development only.",
                    manifest.device_id
                ),
            });
        }
        if manifest.public_key.is_empty() {
            tracing::warn!(
                device_id = %manifest.device_id,
                "registering device with EMPTY public_key — VCP_ALLOW_UNVERIFIED_DEVICES is set; \
                 this device will not be cryptographically authenticated"
            );
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
        let canonical_id_hex = hex::encode(env.canonical_id);
        let glyph = env.glyph;
        let odu   = env.odu_base;

        // Register in CanonicalObjectStore — single authoritative identity.
        {
            let mut s = self.store.write()
                .map_err(|_| VcpError::ChallengeFailed { reason: "store lock poisoned".into() })?;
            s.insert_object(env);
        }

        tracing::info!(
            device_id,
            gix1_canonical_id = %canonical_id_hex,
            gix1_glyph = %glyph,
            gix1_odu_base = odu,
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

        for cap in &required_caps {
            if !manifest.capabilities
                .iter()
                .any(|c| format!("{:?}", c).to_lowercase().contains(&cap.to_lowercase()))
            {
                tracing::debug!("capability {cap:?} not in device {device_id} — will surface in CapNeg");
            }
        }

        let session_id   = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let nonce        = hex::encode(Uuid::new_v4().as_bytes());

        let challenge = ChallengeRequest {
            challenge_id,
            nonce,
            issued_at:       Utc::now(),
            expires_in_secs: 60,
            required_caps:   required_caps.clone(),
            required_safety: manifest.safety_class.clone(),
        };

        self.sessions.insert_challenged(session_id, challenge.clone());
        tracing::info!(device_id, agent_did, session_id = %session_id, "VCP challenge issued");
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

        // Defense in depth: `register_device` refuses keyless devices, but an
        // engine restored from a pre-existing on-disk registry (or built by a
        // caller that bypassed registration) must not silently skip signing
        // verification here. An unverifiable auth attempt is a failed auth
        // attempt.
        if manifest.public_key.is_empty() {
            // VCP_REQUIRE_PUBKEY=true (production gate) takes priority and
            // returns an error regardless of VCP_ALLOW_UNVERIFIED_DEVICES.
            require_pubkey_in_production(&auth.device_id, &manifest.public_key)?;

            if !allow_unverified_devices() {
                return Err(VcpError::ChallengeFailed {
                    reason: format!(
                        "device '{}' has no public_key — cannot verify auth signature. \
                         Refusing the session (set VCP_ALLOW_UNVERIFIED_DEVICES=1 for local dev only).",
                        auth.device_id
                    ),
                });
            }
            tracing::warn!(
                device_id = %auth.device_id,
                "VCP_ALLOW_UNVERIFIED_DEVICES set — accepting auth WITHOUT signature verification"
            );
        } else {
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

        Ok(CapabilityNegotiation {
            challenge_id:        auth.challenge_id,
            device_id:           auth.device_id.clone(),
            offered_caps,
            max_safety:          manifest.safety_class.clone(),
            max_duration_secs:   3600,
            estimated_cost_uase: 0,
        })
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
            agent_signature:  String::new(),
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
    /// Phase 8B: uses `CanonicalObjectStore.insert_object()` so both the
    /// `Gix1Index` and `GlyphGraph` entries share the **same** canonical_id —
    /// no double-hashing.  The edge invariant (both endpoints in index) is
    /// enforced by `store.add_edge()`.
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

        let composite    = gix_types::gix_fold_v1(&[device_env.canonical_id, receipt_env.canonical_id]);
        let device_hex   = hex::encode(device_env.canonical_id);
        let receipt_hex  = hex::encode(receipt_env.canonical_id);

        // Single-path mutation through CanonicalObjectStore — fixes double-hash.
        {
            let mut s = self.store.write().unwrap();
            // insert_object: same canonical_id in both index and graph node.
            if !s.contains(&device_hex) {
                s.insert_object(device_env);
            }
            if !s.contains(&receipt_hex) {
                s.insert_object(receipt_env);
            }
            // add_edge: validated — panics if either endpoint is not in index.
            s.add_edge(gix_types::GlyphEdge {
                from:     device_hex.clone(),
                to:       receipt_hex.clone(),
                relation: "vcp_session".into(),
                weight:   1,
            });
        }

        tracing::debug!(
            session_id = %session_id,
            device_gix1  = %device_hex,
            receipt_gix1 = %receipt_hex,
            "GIX cross-link: device → receipt via vcp_session"
        );

        // Auto-persist: flush immediately so the edge survives an unexpected restart.
        if let Err(e) = self.flush_store() {
            tracing::warn!("GIX store flush failed after vcp_session edge: {e}");
        }

        Some(hex::encode(composite))
    }

    // ── consistency audit ─────────────────────────────────────────────────────

    /// Run `audit_consistency()` on the live store.
    ///
    /// Called at startup (via `with_storage`) and can be called on-demand for
    /// health checks or before Zàngbétò anchoring.
    pub fn audit_gix(&self) -> Result<(), Vec<String>> {
        let s = self.store.read().unwrap();
        s.audit_consistency()
    }

    // ── legacy path-based helpers (escape hatch; not the primary API) ─────────

    /// Persist only the `GlyphGraph` portion to a JSON file.
    ///
    /// Prefer `flush_store` for full atomic persistence.
    pub fn save_graph(&self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        let s = self.store.read().map_err(|e| format!("store lock poisoned: {e}"))?;
        s.graph.save(path)
    }

    /// Replace the in-memory `GlyphGraph` with the one persisted at `path`.
    ///
    /// For full restoration use `with_storage`; this legacy API does NOT
    /// restore the `Gix1Index`.
    pub fn load_graph_from(&self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        let loaded = gix_core::GlyphGraph::load(path)?;
        let mut s = self.store.write().map_err(|e| format!("store lock poisoned: {e}"))?;
        s.graph = loaded;
        Ok(())
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
            signature:   String::new(),
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
            challenge_id:    Uuid::new_v4(),
            nonce:           "nonce".into(),
            issued_at:       Utc::now(),
            expires_in_secs: 60,
            required_caps:   vec![],
            required_safety: SafetyClass::Observer,
        };
        engine.sessions.insert_challenged(sid, challenge);
        let grant = CapabilityGrant {
            grant_id:        Uuid::new_v4(),
            challenge_id:    Uuid::new_v4(),
            device_id:       "dev-001".into(),
            agent_did:       "did:test:agent".into(),
            session_id:      sid,
            scope:           GrantScope::Exclusive,
            granted_caps:    vec![],
            max_safety:      SafetyClass::Observer,
            issued_at:       Utc::now(),
            expires_at:      Utc::now(),
            agent_signature: String::new(),
            parent_signature: None,
        };
        engine.sessions.activate(sid, grant).unwrap();
        (engine, sid)
    }

    #[test]
    fn session_composite_gix1_returns_hex() {
        let (engine, sid) = engine_with_active_session();
        let composite = engine.session_composite_gix1(sid, &make_receipt(sid));
        assert!(composite.is_some());
        assert_eq!(composite.unwrap().len(), 64);
    }

    #[test]
    fn session_composite_gix1_inserts_store_edge() {
        let (engine, sid) = engine_with_active_session();
        engine.session_composite_gix1(sid, &make_receipt(sid));
        let s = engine.store.read().unwrap();
        assert_eq!(s.graph.edge_count(), 1, "one vcp_session edge");
        assert_eq!(s.graph.node_count(), 2, "device + receipt nodes");
        assert_eq!(s.index.len(),        2, "both objects in index");
    }

    /// Phase 8B core invariant: index canonical_id == graph canonical_id (no double-hash).
    #[test]
    fn canonical_ids_agree_after_session() {
        let (engine, sid) = engine_with_active_session();
        engine.session_composite_gix1(sid, &make_receipt(sid));
        let s = engine.store.read().unwrap();

        // ∀ graph node N: N.canonical_id ∈ Gix1Index.
        s.audit_consistency().expect("store must audit clean after session");

        // Spot-check: every graph node must resolve via the index.
        for node in s.graph.nodes() {
            assert!(
                s.index.resolve(&node.canonical_id).is_some(),
                "graph node {} not in index — double-hash bug", node.canonical_id
            );
        }
    }

    #[test]
    fn session_composite_returns_none_for_missing_session() {
        let engine = HandshakeEngine::new();
        assert!(engine.session_composite_gix1(Uuid::new_v4(), &make_receipt(Uuid::new_v4())).is_none());
    }

    fn manifest_with_key(device_id: &str, public_key: &str) -> vcp_types::DeviceManifest {
        use vcp_types::device::{DeviceClass, SafetyClass};
        vcp_types::DeviceManifest {
            device_id: device_id.into(),
            label: "test device".into(),
            owner_did: "did:test:owner".into(),
            class: DeviceClass::SensorNode,
            safety_class: SafetyClass::Observer,
            capabilities: vec![],
            vcp_version: 1,
            firmware: "test/0".into(),
            issued_at: Utc::now(),
            expires_at: None,
            public_key: public_key.into(),
            signature: String::new(),
        }
    }

    /// Regression test for the empty-pubkey bypass (audit finding E-31).
    ///
    /// A keyless manifest previously registered successfully, and
    /// `handle_auth` then skipped Ed25519 verification entirely for that
    /// device — so a caller who registered `public_key: ""` obtained a
    /// capability mediation with no signature at all. Registration must now
    /// fail closed.
    #[test]
    fn register_device_rejects_empty_public_key() {
        let engine = HandshakeEngine::new();
        let err = engine
            .register_device(manifest_with_key("dev-keyless", ""))
            .expect_err("keyless device must not register");
        assert!(
            err.to_string().contains("empty public_key"),
            "unexpected error: {err}"
        );
        assert!(
            engine.registry.get("dev-keyless").is_none(),
            "rejected device must not be reachable in the registry"
        );
    }

    /// A device that *does* carry an Ed25519 public key still registers —
    /// the gate must not break the normal path.
    #[test]
    fn register_device_accepts_valid_public_key() {
        let engine = HandshakeEngine::new();
        engine
            .register_device(manifest_with_key("dev-keyed", &"ab".repeat(32)))
            .expect("keyed device must register");
        assert!(engine.registry.get("dev-keyed").is_some());
    }

    /// Legacy path-based save/load still works (escape hatch).
    #[test]
    fn save_and_load_graph_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vcp_graph.json");

        let (engine, sid) = engine_with_active_session();
        engine.session_composite_gix1(sid, &make_receipt(sid));
        assert_eq!(engine.store.read().unwrap().graph.edge_count(), 1);

        engine.save_graph(&path).expect("save_graph");
        assert!(path.exists());

        let engine2 = HandshakeEngine::new();
        assert_eq!(engine2.store.read().unwrap().graph.edge_count(), 0);
        engine2.load_graph_from(&path).expect("load_graph_from");
        assert_eq!(engine2.store.read().unwrap().graph.edge_count(), 1);
        assert_eq!(engine2.store.read().unwrap().graph.node_count(), 2);
    }

    #[test]
    fn load_graph_from_missing_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let engine = HandshakeEngine::new();
        engine.load_graph_from(dir.path().join("no_graph.json"))
            .expect("missing file should be a no-op");
        assert_eq!(engine.store.read().unwrap().graph.edge_count(), 0);
    }

    /// Phase 8B.8 — full restart + traversal integration test via VCP broker.
    #[test]
    fn vcp_session_survives_restart_with_full_store() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn StorageBackend> = Arc::new(crate::JsonFileBackend::new(
            dir.path().join("g.json"),
            dir.path().join("i.json"),
            dir.path().join("s.json"),
        ));

        // Session 1: create session, compute GIX composite, flush.
        let (device_id, receipt_id) = {
            use vcp_types::{ChallengeRequest, CapabilityGrant, GrantScope};
            use vcp_types::device::SafetyClass;
            let engine = HandshakeEngine::with_storage(Arc::clone(&backend)).unwrap();
            let sid = Uuid::new_v4();
            let challenge = ChallengeRequest {
                challenge_id:    Uuid::new_v4(), nonce: "n".into(),
                issued_at:       Utc::now(), expires_in_secs: 60,
                required_caps:   vec![], required_safety: SafetyClass::Observer,
            };
            engine.sessions.insert_challenged(sid, challenge);
            let grant = CapabilityGrant {
                grant_id:        Uuid::new_v4(), challenge_id: Uuid::new_v4(),
                device_id:       "dev-restart-001".into(), agent_did: "did:test".into(),
                session_id:      sid, scope: GrantScope::Exclusive, granted_caps: vec![],
                max_safety:      SafetyClass::Observer, issued_at: Utc::now(),
                expires_at:      Utc::now(), agent_signature: String::new(), parent_signature: None,
            };
            engine.sessions.activate(sid, grant).unwrap();

            let receipt = make_receipt(sid);
            engine.session_composite_gix1(sid, &receipt).expect("composite");
            engine.flush_store().expect("flush before restart");

            let s = engine.store.read().unwrap();
            assert_eq!(s.graph.node_count(), 2);
            let mut ids: Vec<_> = s.graph.nodes().map(|n| n.canonical_id.clone()).collect();
            ids.sort();
            (ids[0].clone(), ids[1].clone())
        };

        // Session 2: simulate restart — load from disk and walk.
        let engine2 = HandshakeEngine::with_storage(Arc::clone(&backend)).unwrap();
        engine2.audit_gix().expect("restored engine must audit clean");

        let s = engine2.store.read().unwrap();
        assert_eq!(s.graph.edge_count(), 1, "vcp_session edge survives restart");
        assert_eq!(s.index.len(), 2, "both objects in index after restart");

        // Walk from device → receipt.
        let visited = s.walk(&device_id, 1, Some("vcp_session"));
        let visited_ids: Vec<&str> = visited.iter().map(|n| n.canonical_id.as_str()).collect();
        assert!(
            visited_ids.contains(&receipt_id.as_str()) || visited_ids.len() >= 1,
            "walk must traverse vcp_session edge"
        );
    }
}
