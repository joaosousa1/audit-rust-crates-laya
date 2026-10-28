#!/bin/bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/bin"
WRAPPER_PATH="$BIN_DIR/audit-rust-crates-laya"

echo "=== Installing Agnostic Rust Crates Auditor (Official Laya Package) ==="
echo "Project directory: $PROJECT_DIR"

# 1. Create venv if it doesn't exist
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "Creating Python virtual environment (venv)..."
    python3 -m venv "$PROJECT_DIR/venv"
fi

# 2. Upgrade pip and install the official laya package
echo "Upgrading pip..."
"$PROJECT_DIR/venv/bin/pip" install --upgrade pip

echo "Installing official 'laya' decision package..."
"$PROJECT_DIR/venv/bin/pip" install laya || {
    echo "⚠️ Warning: Could not install 'laya'. The auditor will still work using TOML policy mode."
}

# 3. Ensure ~/bin exists
mkdir -p "$BIN_DIR"

# 4. Create global wrapper script
echo "Creating global command at $WRAPPER_PATH..."
cat << EOF > "$WRAPPER_PATH"
#!/bin/bash
exec "$PROJECT_DIR/venv/bin/python3" "$PROJECT_DIR/audit-rust-crates-laya.py" "\$@"
EOF

chmod +x "$WRAPPER_PATH"

# 5. Check PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    echo ""
    echo "⚠️ WARNING: '$BIN_DIR' is not in your current \$PATH."
    echo "Add this line to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$HOME/bin:\$PATH\""
    echo ""
else
    echo "✅ Successfully installed! 'audit-rust-crates-laya' is ready globally."
fi

echo ""
echo "Installation complete!"
echo "Usage:"
echo "  Deterministic TOML mode:   audit-rust-crates-laya --model-path policy.toml"
echo "  Laya Decision Model mode:  audit-rust-crates-laya --model-path convaiinnovations/laya"
