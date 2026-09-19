// ZimaOS device manifest factory (Phase 12.3).
//
// Produces a DeviceManifest for a ZimaOS / CasaOS self-hosted compute node.
//
// Config (env vars — no hardcoding):
//   ZIMA_API_URL    — e.g. http://192.168.1.10:8080 (used as metadata only here)
//   ZIMA_SERVER_ID  — stable server identifier (optional; falls back to hostname or UUID)
//
// SafetyClass::Infrastructure: only TIER 0 (Principal / owner_did) may grant capabilities.
//
// Usage:
//   let manifest = ZimaDevice::manifest_from_env();
//
// Or with explicit params:
//   let manifest = ZimaDevice::manifest("my-zima-01", "http://192.168.1.10:8080");

use chrono::Utc;
use uuid::Uuid;

use crate::{
    DeviceCapability, DeviceClass, DeviceManifest, SafetyClass,
    ComputeSpec, ConnectivitySpec,
};

/// Builder for a ZimaOS VCP DeviceManifest.
pub struct ZimaDevice;

impl ZimaDevice {
    /// Build a DeviceManifest from env vars.
    ///
    /// Returns `None` when `ZIMA_API_URL` is not set (fail-open: caller skips registration).
    pub fn manifest_from_env() -> Option<DeviceManifest> {
        let api_url = std::env::var("ZIMA_API_URL").ok().filter(|s| !s.is_empty())?;
        let server_id = std::env::var("ZIMA_SERVER_ID")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let owner_did = std::env::var("ZIMA_OWNER_DID")
            .unwrap_or_else(|_| "did:sovereign:unknown".to_string());

        Some(Self::manifest_with_owner(&server_id, &api_url, &owner_did))
    }

    /// Build a DeviceManifest with explicit params (for testing or programmatic use).
    pub fn manifest(server_id: &str, api_url: &str) -> DeviceManifest {
        Self::manifest_with_owner(server_id, api_url, "did:sovereign:unknown")
    }

    /// Build a DeviceManifest with explicit owner DID.
    pub fn manifest_with_owner(server_id: &str, api_url: &str, owner_did: &str) -> DeviceManifest {
        DeviceManifest {
            device_id: format!("zima:{}", server_id),
            // Embed api_url in label; DeviceManifest has no metadata field.
            // Downstream systems should use the ZIMA_API_URL env var for API calls.
            label: format!("ZimaOS node {} @ {}", server_id, api_url),
            owner_did: owner_did.to_string(),

            class: DeviceClass::EdgeServer,

            // Infrastructure class: only Tier 0 / Principal may grant capabilities.
            // Prevents untrusted agents from deploying or managing containers.
            safety_class: SafetyClass::Critical,

            capabilities: vec![
                // Container / app lifecycle
                DeviceCapability::Compute(ComputeSpec {
                    cpu_cores:    0,      // populated at runtime if ZIMA returns hardware info
                    ram_gb:       0.0,
                    gpu_vram_gb:  None,
                    tflops_fp16:  None,
                }),
                // Network connectivity
                DeviceCapability::Connectivity(ConnectivitySpec {
                    protocols: vec![
                        "http".to_string(),
                        "https".to_string(),
                        "casaos-api".to_string(),
                    ],
                    max_mbps: 1000.0,   // gigabit LAN typical for ZimaSpace hardware
                    mesh: false,
                }),
            ],

            vcp_version: 1,
            firmware: "zimaos/1.0".to_string(),
            issued_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(24)),

            // Device keys are provisioned at runtime by the VCP broker.
            // Empty strings here → broker fills in during registration.
            public_key: String::new(),
            signature:  String::new(),
        }
    }

    /// Named capability strings (for use in CapabilityGrant.scope).
    pub const CAPABILITIES: &'static [&'static str] = &[
        "compute.deploy",
        "compute.execute",
        "storage.read",
        "storage.write",
        "service.manage",
        "container.run",
    ];
}
