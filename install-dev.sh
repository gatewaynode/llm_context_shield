#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="llm_context_shield"
LINK_NAME="llm-shield"
TARGET_DIR="$HOME/.local/bin"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

cargo build --manifest-path "$REPO_DIR/Cargo.toml"

BINARY_PATH="$REPO_DIR/target/debug/$BINARY_NAME"

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Error: binary not found at $BINARY_PATH" >&2
    exit 1
fi

mkdir -p "$TARGET_DIR"
ln -sf "$BINARY_PATH" "$TARGET_DIR/$LINK_NAME"
echo "Linked $TARGET_DIR/$LINK_NAME -> $BINARY_PATH"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$TARGET_DIR"; then
    echo "Note: $TARGET_DIR is not in your PATH. Add this to your shell profile:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
