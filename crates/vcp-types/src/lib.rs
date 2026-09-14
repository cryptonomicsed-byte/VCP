//! Vantage Connection Protocol (VCP) — pure wire types.
//!
//! VCP is the protocol layer that lets agent-carrying devices (Agent Tags,
//! Companions, Gateways, robots, drones, IoT) participate in the sovereign
//! ecosystem.  An agent does not remote-control a device; instead, the agent
//! *temporarily inhabits* it for the duration of a scoped, revocable session.
//!
//! Handshake (7 steps):
//!   1. DISCOVERY   — device broadcasts DeviceManifest (mDNS / BLE / Nostr)
//!   2. CHALLENGE   — broker issues ChallengeRequest (nonce + required capabilities)
//!   3. AUTH        — device responds with AuthResponse (signed nonce, DID proof)
//!   4. CAP_NEG     — broker sends CapabilityNegotiation (what is offered vs. required)
//!   5. GRANT       — agent accepts a CapabilityGrant (scoped, expiring, signed)
//!   6. SESSION     — SessionMessage stream (telemetry, commands, observations)
//!   7. RECEIPT     — VcpReceipt signed by device + agent + optional witness

pub mod device;
pub mod error;
pub mod handshake;
pub mod receipt;
pub mod session;

pub use device::{
    DeviceClass, DeviceManifest, DeviceCapability, SensorSpec, ActuatorSpec,
    ComputeSpec, ConnectivitySpec, SafetyClass,
};
pub use error::VcpError;
pub use handshake::{
    AuthResponse, CapabilityGrant, CapabilityNegotiation, ChallengeRequest,
    GrantScope, HandshakeMessage, RevocationReason, RevocationRecord,
};
pub use receipt::{VcpReceipt, SessionOutcome, WitnessAttestation};
pub use session::{SessionId, SessionMessage, SessionMessageKind, TelemetryPoint};
