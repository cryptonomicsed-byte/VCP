//! Persistence abstraction for GIX state carried by the VCP broker.
//!
//! `StorageBackend` decouples the broker from the physical format so that
//! JSON files (current), SQLite, or sled can all satisfy the same contract
//! without touching GIX semantics.
//!
//! Phase 8B: upgraded to persist `CanonicalObjectStore` as an atomic unit —
//! graph.json + index.json + snapshot.json are written together so they share
//! the same epoch snapshot_id, preventing partial-write skew.

use std::path::PathBuf;

/// Save/load contract for the canonical GIX object store.
///
/// Implementations must be `Send + Sync` so the broker can share them across
/// async tasks behind an `Arc`.
pub trait StorageBackend: Send + Sync {
    /// Load the full `CanonicalObjectStore` from durable storage.
    ///
    /// Returns an empty store when no prior state exists (first boot).
    fn load_store(&self) -> Result<gix_core::CanonicalObjectStore, String>;

    /// Persist the current `CanonicalObjectStore` snapshot atomically.
    ///
    /// Stamps a new `snapshot_id` before writing so all three backing files
    /// share the same epoch identifier.
    fn save_store(&self, store: &mut gix_core::CanonicalObjectStore) -> Result<(), String>;
}

// ── JSON file backend (default) ───────────────────────────────────────────────

/// Stores the `CanonicalObjectStore` as three atomic JSON files:
///   `{graph_path}`    — GlyphGraph
///   `{index_path}`    — Gix1Index
///   `{snapshot_path}` — GixSnapshotMeta (shared epoch id)
///
/// Configure via env vars:
///   VCP_GRAPH_PATH    — default: vcp_graph.json
///   VCP_INDEX_PATH    — default: vcp_index.json
///   VCP_SNAPSHOT_PATH — default: vcp_snapshot.json
pub struct JsonFileBackend {
    pub graph_path:    PathBuf,
    pub index_path:    PathBuf,
    pub snapshot_path: PathBuf,
}

impl JsonFileBackend {
    pub fn new(
        graph_path:    impl Into<PathBuf>,
        index_path:    impl Into<PathBuf>,
        snapshot_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            graph_path:    graph_path.into(),
            index_path:    index_path.into(),
            snapshot_path: snapshot_path.into(),
        }
    }

    /// Build from environment variables, falling back to local defaults.
    pub fn from_env() -> Self {
        Self::new(
            std::env::var("VCP_GRAPH_PATH").unwrap_or_else(|_| "vcp_graph.json".into()),
            std::env::var("VCP_INDEX_PATH").unwrap_or_else(|_| "vcp_index.json".into()),
            std::env::var("VCP_SNAPSHOT_PATH").unwrap_or_else(|_| "vcp_snapshot.json".into()),
        )
    }
}

impl StorageBackend for JsonFileBackend {
    fn load_store(&self) -> Result<gix_core::CanonicalObjectStore, String> {
        gix_core::load_store_from_files(&self.graph_path, &self.index_path, &self.snapshot_path)
    }

    fn save_store(&self, store: &mut gix_core::CanonicalObjectStore) -> Result<(), String> {
        gix_core::save_store_to_files(store, &self.graph_path, &self.index_path, &self.snapshot_path)
    }
}

// ── No-op backend for tests / in-memory mode ─────────────────────────────────

pub struct NullBackend;

impl StorageBackend for NullBackend {
    fn load_store(&self) -> Result<gix_core::CanonicalObjectStore, String> {
        Ok(gix_core::CanonicalObjectStore::new())
    }
    fn save_store(&self, _store: &mut gix_core::CanonicalObjectStore) -> Result<(), String> {
        Ok(())
    }
}

// ── convenience wrapper ───────────────────────────────────────────────────────


#[cfg(test)]
mod tests {
    use super::*;
    use gix_types::{GixKind, GixNamespace, RoutingHints};

    fn make_env(bytes: &[u8]) -> gix_types::Gix1 {
        gix_types::Gix1::new(
            GixKind::Physical, GixNamespace::MeshDevice,
            bytes, None, 1_700_000_000_000, RoutingHints::default(),
        )
    }

    #[test]
    fn json_backend_roundtrip_store() {
        let dir = tempfile::tempdir().unwrap();
        let backend = JsonFileBackend::new(
            dir.path().join("graph.json"),
            dir.path().join("index.json"),
            dir.path().join("snapshot.json"),
        );

        // Empty load succeeds before any files exist.
        let s = backend.load_store().expect("first boot");
        assert_eq!(s.graph.edge_count(), 0);

        // Insert an object and save.
        let mut store = gix_core::CanonicalObjectStore::new();
        store.insert_object(make_env(b"test-device"));
        backend.save_store(&mut store).expect("save");

        // Reload and audit.
        let loaded = backend.load_store().expect("reload");
        loaded.audit_consistency().expect("loaded store must audit");
        assert_eq!(loaded.index.len(), 1);
    }

    #[test]
    fn json_backend_snapshot_id_is_stable_across_reload() {
        let dir = tempfile::tempdir().unwrap();
        let backend = JsonFileBackend::new(
            dir.path().join("graph.json"),
            dir.path().join("index.json"),
            dir.path().join("snapshot.json"),
        );

        let mut store = gix_core::CanonicalObjectStore::new();
        store.insert_object(make_env(b"node"));
        backend.save_store(&mut store).expect("save");
        let saved_id = store.snapshot_id().to_string();

        let loaded = backend.load_store().expect("reload");
        assert_eq!(loaded.snapshot_id(), saved_id,
            "snapshot_id must survive save/load cycle");
    }

    #[test]
    fn null_backend_is_always_ok() {
        let b = NullBackend;
        let s = b.load_store().unwrap();
        assert_eq!(s.graph.node_count(), 0);
        let mut s2 = gix_core::CanonicalObjectStore::new();
        assert!(b.save_store(&mut s2).is_ok());
    }

    /// Crash-recovery: a stale `.tmp` file does not corrupt the live graph.
    #[test]
    fn stale_tmp_file_does_not_corrupt_load() {
        let dir = tempfile::tempdir().unwrap();
        let graph_path = dir.path().join("graph.json");
        let backend = JsonFileBackend::new(
            &graph_path,
            dir.path().join("index.json"),
            dir.path().join("snapshot.json"),
        );

        let mut store = gix_core::CanonicalObjectStore::new();
        store.insert_object(make_env(b"stable"));
        backend.save_store(&mut store).expect("save");

        // Inject a corrupt .tmp sibling.
        std::fs::write(graph_path.with_extension("tmp"), b"{ bad json ]").unwrap();

        let loaded = backend.load_store().expect("valid graph survives stale tmp");
        assert_eq!(loaded.index.len(), 1);
    }

    /// Phase 8B: with_storage restores BOTH structures.
    #[test]
    fn with_storage_restores_index_and_graph() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn StorageBackend> = Arc::new(JsonFileBackend::new(
            dir.path().join("g.json"),
            dir.path().join("i.json"),
            dir.path().join("s.json"),
        ));

        // Seed durable state.
        let mut seed = gix_core::CanonicalObjectStore::new();
        seed.insert_object(make_env(b"device-001"));
        seed.insert_object(make_env(b"device-002"));
        backend.save_store(&mut seed).unwrap();

        // Restart.
        let engine = crate::handshake_engine::HandshakeEngine::with_storage(backend)
            .expect("restore must succeed");
        let s = engine.store.read().unwrap();
        assert_eq!(s.index.len(), 2,   "index must be restored");
        assert_eq!(s.graph.node_count(), 2, "graph must be restored");
        s.audit_consistency().expect("restored store must audit");
    }
}
