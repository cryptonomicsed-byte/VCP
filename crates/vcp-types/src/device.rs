use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// A device's self-description, broadcast during the DISCOVERY phase.
///
/// The DeviceManifest is signed by the device's private key and can be
/// verified by anyone with the device's DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceManifest {
    /// Stable device identity (DID or UUID).
    pub device_id:       String,
    /// Human-readable label.
    pub label:           String,
    /// Ownership — who controls this device (agent DID or Vantage name).
    pub owner_did:       String,

    pub class:           DeviceClass,
    pub safety_class:    SafetyClass,
    pub capabilities:    Vec<DeviceCapability>,

    /// Supported VCP protocol version.
    pub vcp_version:     u16,
    /// Firmware / software version string.
    pub firmware:        String,
    /// When this manifest was signed.
    pub issued_at:       DateTime<Utc>,
    /// Optional expiry — device should re-broadcast before this.
    pub expires_at:      Option<DateTime<Utc>>,

    /// Hex-encoded Ed25519 public key for this device (32 bytes = 64 hex chars).
    pub public_key:      String,
    /// Hex-encoded Ed25519 signature over canonical JSON of all fields above.
    pub signature:       String,
}

/// Broad classification drives safety and capability policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceClass {
    /// Wearable identity carrier — Agent Tag, smart ring, etc.
    AgentTag,
    /// Handheld / tabletop interface device — Companion.
    Companion,
    /// Stationary compute + radio gateway.
    Gateway,
    /// Quadruped or biped ground robot.
    GroundRobot,
    /// Multirotor or fixed-wing aerial vehicle.
    Drone,
    /// IoT sensor node (environmental, structural, etc.)
    SensorNode,
    /// Edge server or NAS.
    EdgeServer,
    /// Mobile phone / tablet running VCP agent.
    MobileDevice,
    /// Other — specify in `label`.
    Other(String),
}

/// Safety classification determines what a granted session may do.
///
/// Higher class = more dangerous actuation = stricter grant requirements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SafetyClass {
    /// Read-only: sensors, cameras, telemetry streams.
    Observer = 0,
    /// Low-power actuators: LEDs, buzzers, displays.
    LowImpact = 1,
    /// Controlled motion indoors: robot arm, pan/tilt.
    IndoorMotion = 2,
    /// Outdoor/free motion, may contact humans: ground robot.
    OutdoorMotion = 3,
    /// Aerial vehicle or high-speed actuator.
    Aerial = 4,
    /// Irreversible or safety-critical: industrial, medical.
    Critical = 5,
}

/// A concrete capability a device offers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceCapability {
    Sensor(SensorSpec),
    Actuator(ActuatorSpec),
    Compute(ComputeSpec),
    Connectivity(ConnectivitySpec),
    Camera { resolution_mp: f32, fov_deg: f32, night_vision: bool },
    Microphone { sample_rate_hz: u32, channels: u8 },
    Speaker { sample_rate_hz: u32, watt: f32 },
    Display { width_px: u32, height_px: u32, touch: bool },
    Gps { accuracy_m: f32, rtk: bool },
    Lidar { range_m: f32, hz: f32, points_per_sec: u64 },
    Imu { dof: u8, sample_rate_hz: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorSpec {
    pub sensor_type: String,   // e.g. "temperature", "humidity", "co2"
    pub unit:        String,
    pub range_min:   f64,
    pub range_max:   f64,
    pub sample_hz:   f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActuatorSpec {
    pub actuator_type: String,   // e.g. "servo", "relay", "motor"
    pub channels:      u8,
    pub max_force_n:   Option<f64>,
    pub reversible:    bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeSpec {
    pub cpu_cores:  u32,
    pub ram_gb:     f32,
    pub gpu_vram_gb: Option<f32>,
    pub tflops_fp16: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivitySpec {
    pub protocols: Vec<String>,   // e.g. ["wifi6", "ble5", "lora", "lte"]
    pub max_mbps:  f32,
    pub mesh:      bool,
}
