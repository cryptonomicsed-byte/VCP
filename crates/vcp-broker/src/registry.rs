use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Instant, Duration};

use vcp_types::DeviceManifest;

const STALE_SECS: u64 = 300;   // 5 min — device must re-broadcast

struct RegistryEntry {
    manifest:    DeviceManifest,
    last_seen:   Instant,
}

/// In-memory registry of active DeviceManifests.
///
/// Production deployment replaces this with a Vantage-backed store by
/// setting VANTAGE_VCP_URL — the broker forwards register/heartbeat calls
/// to Vantage's /api/vcp/devices endpoints.
pub struct DeviceRegistry {
    entries: RwLock<HashMap<String, RegistryEntry>>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self { entries: RwLock::new(HashMap::new()) }
    }

    /// Register or refresh a device.
    pub fn register(&self, manifest: DeviceManifest) {
        let mut map = self.entries.write().unwrap();
        map.insert(manifest.device_id.clone(), RegistryEntry {
            manifest,
            last_seen: Instant::now(),
        });
    }

    /// Get a device's current manifest.
    pub fn get(&self, device_id: &str) -> Option<DeviceManifest> {
        let map = self.entries.read().unwrap();
        map.get(device_id).and_then(|e| {
            if e.last_seen.elapsed() < Duration::from_secs(STALE_SECS) {
                Some(e.manifest.clone())
            } else {
                None
            }
        })
    }

    /// List all fresh devices.
    pub fn list_fresh(&self) -> Vec<DeviceManifest> {
        let map = self.entries.read().unwrap();
        map.values()
            .filter(|e| e.last_seen.elapsed() < Duration::from_secs(STALE_SECS))
            .map(|e| e.manifest.clone())
            .collect()
    }

    /// Evict stale entries.
    pub fn prune(&self) {
        let mut map = self.entries.write().unwrap();
        map.retain(|_, e| e.last_seen.elapsed() < Duration::from_secs(STALE_SECS));
    }
}

impl Default for DeviceRegistry {
    fn default() -> Self { Self::new() }
}
