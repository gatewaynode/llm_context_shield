#!/usr/bin/env bash
set -euo pipefail

# Install the `safe-fetch` Claude Code skill to the user skills directory.
#
# Usage:
#   bash install-skill.sh            # user-level install (~/.claude/skills/safe-fetch/)
#   bash install-skill.sh --project  # project-level install (./.claude/skills/safe-fetch/)
#
# The skill source of truth is skill/safe-fetch.md in this repo. The installer
# copies it to SKILL.md under the target Claude skills directory. Re-running is
# idempotent: an existing SKILL.md is overwritten.

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SKILL_SRC="$REPO_DIR/skill/safe-fetch.md"
SKILL_NAME="safe-fetch"

if [[ ! -f "$SKILL_SRC" ]]; then
    echo "Error: skill source not found at $SKILL_SRC" >&2
    exit 1
fi

SCOPE="user"
if [[ $# -gt 0 ]]; then
    case "$1" in
        --user)    SCOPE="user" ;;
        --project) SCOPE="project" ;;
        -h|--help)
            sed -n '3,12p' "$0"
            exit 0
            ;;
        *)
            echo "Error: unknown argument '$1'" >&2
            echo "Usage: bash install-skill.sh [--user|--project]" >&2
            exit 2
            ;;
    esac
fi

if [[ "$SCOPE" == "user" ]]; then
    TARGET_ROOT="$HOME/.claude/skills"
else
    TARGET_ROOT="$REPO_DIR/.claude/skills"
fi

TARGET_DIR="$TARGET_ROOT/$SKILL_NAME"
TARGET_FILE="$TARGET_DIR/SKILL.md"

mkdir -p "$TARGET_DIR"
cp "$SKILL_SRC" "$TARGET_FILE"
chmod 644 "$TARGET_FILE"

echo "Installed skill: $TARGET_FILE"
echo "Scope:           $SCOPE"
echo ""
echo "Claude Code will pick up the skill on the next session."
echo "Test it by asking Claude to 'fetch https://example.com'."
