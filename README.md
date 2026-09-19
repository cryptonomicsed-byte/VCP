# VCP — Vantage Connection Protocol

Brokers authenticated sessions between Vantage and physical/virtual devices. Handles discovery, Ed25519 challenge-auth, capability negotiation, and scoped session receipts.

**Port:** 7791 | **Security:** high | **ARP:** vcp_session receipts (Nostr kind 31020)

## Architecture

```
VCP workspace
├── crates/vcp-types/       # DeviceManifest, CapabilityGrant, VcpReceipt
├── crates/vcp-broker/      # 7-step handshake, SessionStore, Ed25519 crypto.rs
└── MANIFEST.toml
```

## 7-Step Handshake

1. **discovery** — device announces via BLE/mDNS/Nostr
2. **challenge** — broker issues nonce
3. **auth** — device signs nonce with Ed25519 key
4. **cap_neg** — capability set negotiated
5. **grant** — `CapabilityGrant` issued (scoped + expiring)
6. **session** — active session record created
7. **receipt** — `VcpReceipt` signed and published (Nostr 31020)

## Safety Classes

`Observer` · `LowImpact` · `IndoorMotion` · `OutdoorMotion` · `Aerial` · `Critical`

## Environment

| Variable | Description |
|----------|-------------|
| `VCP_PORT` | HTTP server port (default: 7791) |
| `VCP_NOSTR_RELAY` | Relay URL for publishing receipts |
| `VCP_PRIVATE_KEY` | Broker signing key (hex Ed25519) |

## Quick Start

```bash
cd VCP
cargo build --release
VCP_PORT=7791 ./target/release/vcp-broker
```

## Devices with empty `public_key` skip Ed25519 verification (dev/test mode).
