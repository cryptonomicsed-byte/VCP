//! Persistence abstraction for GIX state carried by the VCP broker.
//!
//! `StorageBackend` decouples the broker from the physical format so that
//! JSON files (current), SQLite, or sled can all satisfy the same contract
//! without touching GIX semantics.

use std::path::PathBuf;

/// Save/load contract for GlyphGraph + Gix1Index.
///
/// Implementations must be `Send + Sync` so the broker can share them across
/// async tasks behind an `Arc`.
pub trait StorageBackend: Send + Sync {
    /// Load the GlyphGraph from durable storage.
    ///
    /// Returns an empty graph when no prior state exists (first boot).
    fn load_graph(&self) -> Result<gix_core::GlyphGraph, String>;

    /// Persist the current GlyphGraph snapshot atomically.
    fn save_graph(&self, graph: &gix_core::GlyphGraph) -> Result<(), String>;

    /// Load the Gix1Index from durable storage.
    ///
    /// Returns an empty index when no prior state exists.
    fn load_index(&self) -> Result<gix_core::Gix1Index, String>;

    /// Persist the current Gix1Index snapshot atomically.
    fn save_index(&self, index: &gix_core::Gix1Index) -> Result<(), String>;
}

// ── JSON file backend (default) ───────────────────────────────────────────────

/// Stores GlyphGraph and Gix1Index as pretty-printed JSON files.
///
/// Writes are atomic: data lands in a `.tmp` sibling first, then renamed.
/// Configure via env vars:
///   VCP_GRAPH_PATH  — path to graph JSON file  (default: vcp_graph.json)
///   VCP_INDEX_PATH  — path to index JSON file  (default: vcp_index.json)
pub struct JsonFileBackend {
    pub graph_path: PathBuf,
    pub index_path: PathBuf,
}

impl JsonFileBackend {
    pub fn new(graph_path: impl Into<PathBuf>, index_path: impl Into<PathBuf>) -> Self {
        Self {
            graph_path: graph_path.into(),
            index_path: index_path.into(),
        }
    }

    /// Build from environment variables, falling back to local defaults.
    pub fn from_env() -> Self {
        let graph_path = std::env::var("VCP_GRAPH_PATH")
            .unwrap_or_else(|_| "vcp_graph.json".into());
        let index_path = std::env::var("VCP_INDEX_PATH")
            .unwrap_or_else(|_| "vcp_index.json".into());
        Self::new(graph_path, index_path)
    }
}

impl StorageBackend for JsonFileBackend {
    fn load_graph(&self) -> Result<gix_core::GlyphGraph, String> {
        gix_core::GlyphGraph::load(&self.graph_path)
    }

    fn save_graph(&self, graph: &gix_core::GlyphGraph) -> Result<(), String> {
        graph.save(&self.graph_path)
    }

    fn load_index(&self) -> Result<gix_core::Gix1Index, String> {
        gix_core::Gix1Index::load(&self.index_path)
    }

    fn save_index(&self, index: &gix_core::Gix1Index) -> Result<(), String> {
        index.save(&self.index_path)
    }
}

/// A no-op backend used in tests where persistence is not needed.
pub struct NullBackend;

impl StorageBackend for NullBackend {
    fn load_graph(&self) -> Result<gix_core::GlyphGraph, String> {
        Ok(gix_core::GlyphGraph::new())
    }
    fn save_graph(&self, _graph: &gix_core::GlyphGraph) -> Result<(), String> {
        Ok(())
    }
    fn load_index(&self) -> Result<gix_core::Gix1Index, String> {
        Ok(gix_core::Gix1Index::new())
    }
    fn save_index(&self, _index: &gix_core::Gix1Index) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_backend_roundtrip_graph() {
        let dir = tempfile::tempdir().unwrap();
        let backend = JsonFileBackend::new(
            dir.path().join("graph.json"),
            dir.path().join("index.json"),
        );

        // Empty load succeeds before the file exists.
        let g = backend.load_graph().expect("empty load");
        assert_eq!(g.edge_count(), 0);

        // Save and reload.
        let mut g2 = gix_core::GlyphGraph::new();
        g2.add_node(gix_types::GlyphNode::from_chunk("test-node", 1.0));
        backend.save_graph(&g2).expect("save");

        let g3 = backend.load_graph().expect("reload");
        assert_eq!(g3.node_count(), 1);
    }

    #[test]
    fn json_backend_roundtrip_index() {
        let dir = tempfile::tempdir().unwrap();
        let backend = JsonFileBackend::new(
            dir.path().join("graph.json"),
            dir.path().join("index.json"),
        );

        let idx = backend.load_index().expect("empty index load");
        assert_eq!(idx.root(), gix_types::GIX1_EMPTY_ROOT);

        backend.save_index(&idx).expect("save empty index");
        let idx2 = backend.load_index().expect("reload");
        assert_eq!(idx2.root(), gix_types::GIX1_EMPTY_ROOT);
    }

    #[test]
    fn null_backend_is_always_ok() {
        let b = NullBackend;
        assert!(b.load_graph().is_ok());
        let g = gix_core::GlyphGraph::new();
        assert!(b.save_graph(&g).is_ok());
        assert!(b.load_index().is_ok());
        let idx = gix_core::Gix1Index::new();
        assert!(b.save_index(&idx).is_ok());
    }

    /// Crash-recovery: a stale `.tmp` file from an interrupted write must not
    /// prevent the previous valid graph from loading.
    #[test]
    fn stale_tmp_file_does_not_corrupt_load() {
        let dir = tempfile::tempdir().unwrap();
        let graph_path = dir.path().join("graph.json");
        let backend = JsonFileBackend::new(&graph_path, dir.path().join("index.json"));

        // Write a valid graph.
        let mut g = gix_core::GlyphGraph::new();
        g.add_node(gix_types::GlyphNode::from_chunk("stable-node", 1.0));
        backend.save_graph(&g).expect("initial save");

        // Simulate an interrupted write: leave a corrupt .tmp sibling.
        let tmp = graph_path.with_extension("tmp");
        std::fs::write(&tmp, b"{ invalid json ]").unwrap();

        // The valid graph file is still intact and loads correctly.
        let loaded = backend.load_graph().expect("should load valid graph despite stale .tmp");
        assert_eq!(loaded.node_count(), 1, "valid graph survives stale tmp file");
    }

    /// Phase 8A recovery: with_storage returns empty graph on missing file, not an error.
    #[test]
    fn with_storage_boots_empty_on_missing_files() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let backend: Arc<dyn StorageBackend> = Arc::new(JsonFileBackend::new(
            dir.path().join("no_graph.json"),
            dir.path().join("no_index.json"),
        ));
        let engine = crate::handshake_engine::HandshakeEngine::with_storage(backend)
            .expect("missing file = first boot, not an error");
        let g = engine.graph.read().unwrap();
        assert_eq!(g.edge_count(), 0);
    }
}
