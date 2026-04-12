#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="llm_context_shield"
LINK_NAME="lcs"
SHARE_DIR="$HOME/.local/share/llm_context_shield"
BIN_DIR="$HOME/.local/bin"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Building $BINARY_NAME (release)..."
cargo build --release --all-features --manifest-path "$REPO_DIR/Cargo.toml"

BUILT="$REPO_DIR/target/release/$BINARY_NAME"
if [[ ! -f "$BUILT" ]]; then
    echo "Error: binary not found at $BUILT" >&2
    exit 1
fi

VERSION=$("$BUILT" --version | awk '{print $NF}')
if [[ -z "$VERSION" ]]; then
    echo "Error: could not determine version from binary" >&2
    exit 1
fi

DEST="$SHARE_DIR/${LINK_NAME}-${VERSION}"

# If a flat binary exists at SHARE_DIR (pre-versioned install), remove it
if [[ -e "$SHARE_DIR" && ! -d "$SHARE_DIR" ]]; then
    echo "Migrating: removing old flat binary at $SHARE_DIR"
    rm "$SHARE_DIR"
fi
mkdir -p "$SHARE_DIR" "$BIN_DIR"
cp "$BUILT" "$DEST"
chmod 755 "$DEST"

# Remove any existing file/symlink at the link path before creating the new one.
# ln -sf is not used here because on macOS, if the existing symlink resolves to a
# directory, ln places the new link inside that directory instead of replacing it.
rm -f "$BIN_DIR/$LINK_NAME"
ln -s "$DEST" "$BIN_DIR/$LINK_NAME"

echo "Installed: $DEST"
echo "Linked:    $BIN_DIR/$LINK_NAME -> $DEST"

if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
    echo ""
    echo "Note: $BIN_DIR is not in your PATH. Add to your shell profile:"
    echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
