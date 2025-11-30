# Discourse Polkadot Authentication Plugin

A Discourse plugin that enables users to authenticate using their Polkadot blockchain wallets via the Polkadot.js browser extension.

It isn't Web3, but helps us leverage the most advanced forum software to test alternative moderation and community management options. 

## Features

- Native Rust library for fast, secure verification via FFI, see: https://github.com/KarimJedda/polkadot-signature-verifier
- Polkadot.js Extension integration
- Session-based challenge authentication with expiration and (some) replay protection
- No blockchain connection required - pure cryptographic verification
- Full SS58 address as username - immutable identity anchor accross federated instances

## How It Works

### Authentication Flow

1. User clicks "Sign in with Polkadot"
2. Server generates a random challenge string (stored in session, expires in 5 minutes)
3. User signs the challenge with their Polkadot wallet
4. Server validates challenge from session (prevents replay/reuse)
5. Server verifies the SR25519 signature matches the wallet address
6. User is authenticated with their wallet address as their identity

### User Identity

| Field | Value |
|-------|-------|
| Username | Full SS58 address (e.g., `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`) |
| Email | `{SS58_ADDRESS}@dot.li` |
| Name | On-chain identity display name (set via cron job) |
| Badge | "Verified On-Chain Identity" (if verified by registrar) |

## Prerequisites

- Discourse 3.0+
- Polkadot.js browser extension (for users)
- Ruby FFI gem (included in Discourse)
- The compiled signature verifier library (`libpolkadot_sig_verifier.so`) needs to be added to `lib/verifier/`

## Installation

> Pending test 

### Enable the Plugin

1. Go to **Admin → Settings → Plugins**
2. Find "discourse-polkadot-auth"
3. Enable `polkadot_authentication_enabled`

## Configuration

### Required Site Settings

| Setting | Value | Description |
|---------|-------|-------------|
| `polkadot_authentication_enabled` | `true` | Enable Polkadot authentication |
| `max_username_length` | `60` | Required for full SS58 addresses (~47 chars) |
| `username_change_period` | `0` | Prevent users from changing their SS58 username |

### Optional Settings

| Setting | Description |
|---------|-------------|
| `polkadot_authentication_provides_groups` | Allow the plugin to manage group memberships |


## Building the Signature Verifier

The plugin includes a precompiled `.so` library for Linux x86_64. If you need to rebuild it or compile for a different platform, see the [polkadot-signature-verifier](polkadot-signature-verifier/) directory.

Note: not audited, can surely blow up. Needs investigation.

```bash
cd polkadot-signature-verifier
cargo build --release
cp target/release/libpolkadot_signature_verifier.so ../lib/verifier/libpolkadot_sig_verifier.so
```


## TODO / Future Work

- [ ] **Client-side display swap**: JavaScript plugin to display `name` (on-chain identity) instead of `username` (SS58) in the UI, while keeping SS58 as the canonical identifier under the hood. This would include:
  - Swap displayed usernames with `name` field in posts, user cards, etc.
  - Mention autocomplete shows names but inserts SS58 addresses
  - Tooltip/hover to show SS58 address for transparency
  - Light client necessary


## Support

For issues and questions, please open an issue on GitHub. This was made 50/50 with Claude, can contain traces of emojis and weird stuff. 
