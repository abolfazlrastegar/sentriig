#!/usr/bin/env bash
set -euo pipefail
[[ "${EUID}" -eq 0 ]] || { echo "Run as root with sudo" >&2; exit 1; }
command -v python3 >/dev/null && command -v systemctl >/dev/null || { echo "Python 3 and systemd required" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
id sentriig >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sentriig --shell /usr/sbin/nologin sentriig
install -d -m 0700 -o sentriig -g sentriig /var/lib/sentriig
install -d -m 0755 /opt/sentriig
cp -R "$ROOT/sentriig" /opt/sentriig/
find /opt/sentriig -type d -name __pycache__ -prune -exec rm -rf {} +
cat > /usr/local/bin/sentriig <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
export PYTHONPATH=/opt/sentriig
exec python3 -m sentriig.cli "$@"
WRAPPER
chmod 0755 /usr/local/bin/sentriig
cat > /etc/systemd/system/sentriig.service <<'UNIT'
[Unit]
Description=Sentriig Telegram monitor
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=sentriig
Group=sentriig
SupplementaryGroups=adm systemd-journal
Environment=SENTRIIG_HOME=/var/lib/sentriig
ExecStart=/usr/local/bin/sentriig run
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/sentriig
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable sentriig
echo "Installed. Run: sudo -u sentriig -H sentriig setup; sudo sentriig start; sudo -u sentriig -H sentriig pair"
