#!/bin/bash
# Install the `lab` command + wstunnel launchd agent + SSH shortcuts on this Mac.
# Idempotent: safe to re-run. Run from the repo root:  bash scripts/install-lab-cli.sh
# Never touches any other VPN on this Mac.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
LABDIR="$HOME/.wg-lab"
BIN="$LABDIR/bin"
LABEL="com.ocilab.wstunnel"
WSTUNNEL="$(command -v wstunnel || echo /opt/homebrew/bin/wstunnel)"

[ -x "$WSTUNNEL" ] || { echo "wstunnel not found - brew install wstunnel"; exit 1; }
[ -s "$LABDIR/wstunnel.secret" ] || { echo "missing $LABDIR/wstunnel.secret"; exit 1; }

echo "== 1/6 folders"
mkdir -p "$BIN"; chmod 700 "$LABDIR"
echo "$REPO" > "$LABDIR/repo_path"

echo "== 2/6 gateway endpoint"
if [ ! -s "$LABDIR/endpoint" ]; then
  (cd "$REPO" && terraform output -raw wg_gw_public_ip) > "$LABDIR/endpoint.tmp" && mv "$LABDIR/endpoint.tmp" "$LABDIR/endpoint"
fi
echo "   endpoint: $(cat "$LABDIR/endpoint")"

echo "== 3/6 wstunnel wrapper + launchd agent"
cat > "$BIN/wstunnel-client.sh" <<EOF
#!/bin/bash
# Started by launchd ($LABEL). Reads the secret from a file so it never sits in the plist.
set -euo pipefail
exec "$WSTUNNEL" client \\
  -L 'udp://127.0.0.1:51820:127.0.0.1:51820?timeout_sec=0' \\
  -P "\$(cat "$LABDIR/wstunnel.secret")" \\
  "wss://\$(cat "$LABDIR/endpoint"):443"
EOF
chmod 700 "$BIN/wstunnel-client.sh"

cat > "$LABDIR/$LABEL.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array><string>/bin/bash</string><string>$BIN/wstunnel-client.sh</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>$LABDIR/wstunnel.log</string>
  <key>StandardErrorPath</key><string>$LABDIR/wstunnel.log</string>
</dict>
</plist>
EOF
plutil -lint "$LABDIR/$LABEL.plist" >/dev/null && echo "   plist OK"

echo "== 4/6 lab command"
install -m 0755 "$REPO/scripts/lab" "$BIN/lab"
if ! grep -q 'wg-lab/bin' "$HOME/.zshrc" 2>/dev/null; then
  echo 'export PATH="$HOME/.wg-lab/bin:$PATH"   # oci-soc-lab' >> "$HOME/.zshrc"
fi

echo "== 5/6 SSH shortcuts (lab-gw, lab-core)"
mkdir -p "$HOME/.ssh"; chmod 700 "$HOME/.ssh"
touch "$HOME/.ssh/config"; chmod 600 "$HOME/.ssh/config"
if ! grep -q '>>> oci-soc-lab >>>' "$HOME/.ssh/config"; then
  cat >> "$HOME/.ssh/config" <<'EOF'

# >>> oci-soc-lab >>>
Host lab-gw
  HostName 10.66.66.1
  User ubuntu
  IdentityFile ~/.ssh/oci_lab
  IdentitiesOnly yes
  UseKeychain yes
  AddKeysToAgent yes
Host lab-core
  HostName 10.10.1.129
  User ubuntu
  IdentityFile ~/.ssh/oci_lab
  IdentitiesOnly yes
  UseKeychain yes
  AddKeysToAgent yes
# <<< oci-soc-lab <<<
EOF
fi

echo "== 6/6 replace the manually started wstunnel (if any)"
MANUAL=$(lsof -nP -t -iUDP@127.0.0.1:51820 2>/dev/null || true)
for pid in $MANUAL; do
  if [ "$(ps -o comm= -p "$pid" | xargs basename)" = "wstunnel" ]; then
    kill "$pid" && echo "   stopped manual wstunnel (pid $pid)"
  fi
done
sleep 1

echo "INSTALL DONE - open a new Terminal tab (or: source ~/.zshrc), then run: lab up"
