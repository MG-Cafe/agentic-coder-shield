#!/bin/bash
# Agentic Coder Shield — Install Script
# Copies the protected skill to ~/.claude/skills/

set -e

SKILL_DIR="$HOME/.claude/skills/agentic-coder-protected"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="$SCRIPT_DIR/skills/agentic-coder-protected"

echo "=== Agentic Coder Shield — Installer ==="
echo ""

# Check if skill already exists
if [ -d "$SKILL_DIR" ]; then
    echo "Existing skill found at $SKILL_DIR"
    read -p "Overwrite? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
    rm -rf "$SKILL_DIR"
fi

# Create skill directory
mkdir -p "$SKILL_DIR/scripts"

# Copy skill files
cp "$SOURCE_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"
cp "$SOURCE_DIR/scripts/file_utils_safe.py" "$SKILL_DIR/scripts/file_utils_safe.py"
cp "$SOURCE_DIR/scripts/model_armor.py" "$SKILL_DIR/scripts/model_armor.py"
cp "$SOURCE_DIR/scripts/output_scanner.py" "$SKILL_DIR/scripts/output_scanner.py"

echo ""
echo "Skill installed to: $SKILL_DIR"
echo ""
echo "Claude Code will auto-discover it on next launch."
echo ""

# Check for google-cloud-modelarmor
if python3 -c "import google.cloud.modelarmor_v1" 2>/dev/null; then
    echo "google-cloud-modelarmor: installed"
else
    echo "Optional: Install Model Armor for cloud-based scanning:"
    echo "  pip install google-cloud-modelarmor"
    echo ""
    echo "Without it, the local regex scanner handles all detection."
fi

echo ""
echo "Done! Try: /agentic-coder-protected in Claude Code"
