#!/usr/bin/env bash
# Installs NetMon on macOS (LaunchAgent) or Linux (systemd user service).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETMON_PY="$SCRIPT_DIR/netmon.py"
PYTHON="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo "")"

if [ -z "$PYTHON" ]; then
    echo "ERROR: python3 not found. Install Python 3.11+ first." >&2
    exit 1
fi

"$PYTHON" -c "import psutil, requests, dotenv" 2>/dev/null || {
    echo "ERROR: missing dependencies. Run: pip3 install -r requirements.txt" >&2
    exit 1
}

install_macos() {
    PLIST="$HOME/Library/LaunchAgents/com.netmon.plist"
    cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>             <string>com.netmon</string>
    <key>ProgramArguments</key>
    <array><string>$PYTHON</string><string>$NETMON_PY</string></array>
    <key>WorkingDirectory</key>  <string>$SCRIPT_DIR</string>
    <key>RunAtLoad</key>         <true/>
    <key>KeepAlive</key>         <true/>
    <key>StandardOutPath</key>   <string>$SCRIPT_DIR/netmon.log</string>
    <key>StandardErrorPath</key> <string>$SCRIPT_DIR/netmon.log</string>
</dict>
</plist>
PLIST_EOF
    launchctl load "$PLIST"
    echo "[+] LaunchAgent registered: $PLIST"
}

install_linux() {
    UNIT_DIR="$HOME/.config/systemd/user"
    mkdir -p "$UNIT_DIR"
    cat > "$UNIT_DIR/netmon.service" <<UNIT_EOF
[Unit]
Description=NetMon network monitoring daemon
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON $NETMON_PY
WorkingDirectory=$SCRIPT_DIR
Restart=on-failure
RestartSec=10
StandardOutput=append:$SCRIPT_DIR/netmon.log
StandardError=append:$SCRIPT_DIR/netmon.log

[Install]
WantedBy=default.target
UNIT_EOF
    systemctl --user daemon-reload
    systemctl --user enable --now netmon.service
    echo "[+] systemd user service enabled: netmon.service"
}

prompt_training() {
    read -r -p "Run 1-hour baseline training now? (Y/n) " choice
    case "$choice" in
        ''|[Yy]*)
            echo "Starting baseline training (1 hour)..."
            "$PYTHON" "$NETMON_PY" --train 3600
            echo "Baseline training complete."
            ;;
        *) echo "Skipping baseline training." ;;
    esac
}

case "$(uname -s)" in
    Darwin) install_macos ;;
    Linux)  install_linux ;;
    *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

prompt_training
echo ""
echo "[+] NetMon installed. Logs: $SCRIPT_DIR/netmon.log"
