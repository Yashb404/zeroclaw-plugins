# Token Risk Check Plugin

A ZeroClaw T0 plugin that analyzes token risks based on mint extensions.

## Features

- **Transfer Hook Decoding**: Detects custom transfer hooks that could control token movement.
- **Memo Required**: Checks for tokens that enforce memo requirements for transfers.
- **Non-Transferable**: Detects tokens that are permanently non-transferable.
- **Rate Limit**: Checks for tokens with enforced transfer rate limits.

## Installation

1. Build the plugin:
   ```bash
   cargo build --release --target wasm32-unknown-unknown
   ```

## Usage

The plugin will be available at `target/wasm32-unknown-unknown/release/token_risk_check.wasm`.

When loaded in ZeroClaw, it will automatically analyze Token-2022 mints and provide risk insights based on the extensions found.
