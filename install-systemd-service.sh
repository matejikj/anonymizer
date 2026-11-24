#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: sudo ./install-systemd-service.sh <app_dir> [port] [run_user]

Installs and starts rnd-log-anonymizer as a systemd unit that serves the
built static app (dist/ contents) via "python3 -m http.server".

The app is available under path /anonym (e.g. http://rnd-ai/anonym), NOT as
rnd-ai:<port>. This is done by having python http.server serve a dedicated
webroot containing only a symlink "anonym" -> app_dir — so URL /anonym/...
maps through the symlink to the real files without exposing the rest of the disk.

  app_dir   Directory with the built app (where deploy.sh uploaded dist/), e.g. ~/anonym
  port      Port the app listens on (default: 80 — standard HTTP, no port in URL)
  run_user  User the service runs as (default: user invoking sudo)

Example:
  sudo ./install-systemd-service.sh /home/matejik/anonym

Requires root (sudo) — writes a unit file to /etc/systemd/system/ and creates
/srv/rnd-log-anonymizer-webroot. The service itself then runs as run_user (not root);
port <1024 works via AmbientCapabilities=CAP_NET_BIND_SERVICE.
EOF
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "error: run via sudo (needs write access to /etc/systemd/system/ and /srv/)" >&2
  exit 1
fi

APP_DIR="$(realpath "$1")"
PORT="${2:-80}"
RUN_USER="${3:-${SUDO_USER:-$USER}}"
SERVICE_NAME="rnd-log-anonymizer"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
WEBROOT="/srv/${SERVICE_NAME}-webroot"

if [[ ! -d "$APP_DIR" ]]; then
  echo "error: directory ${APP_DIR} does not exist" >&2
  exit 1
fi

if [[ ! -f "${APP_DIR}/index.html" ]]; then
  echo "warning: ${APP_DIR}/index.html not found — is APP_DIR really the dist/ contents?" >&2
fi

PYTHON_BIN="$(command -v python3)" || {
  echo "error: python3 not found in PATH" >&2
  exit 1
}

if ! id "$RUN_USER" &>/dev/null; then
  echo "error: user '${RUN_USER}' does not exist on this host" >&2
  exit 1
fi

echo "==> Preparing webroot ${WEBROOT} (symlink anonym -> ${APP_DIR})"
mkdir -p "$WEBROOT"
chmod 755 "$WEBROOT"
ln -sfn "$APP_DIR" "${WEBROOT}/anonym"

if ! sudo -u "$RUN_USER" test -x "$WEBROOT"; then
  echo "error: user '${RUN_USER}' cannot traverse ${WEBROOT} even after chmod 755." >&2
  echo "        Check parent directory permissions (e.g. /srv), e.g.: namei -om ${WEBROOT}" >&2
  exit 1
fi

echo "==> Writing ${UNIT_PATH}"
cat > "$UNIT_PATH" <<EOF
[Unit]
Description=rnd-log-anonymizer (static SPA via python3 http.server, path /anonym)
After=network.target

[Service]
Type=simple
User=${RUN_USER}
WorkingDirectory=${WEBROOT}
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=${PYTHON_BIN} -m http.server ${PORT} --directory ${WEBROOT}
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
ProtectSystem=strict
ReadOnlyPaths=${APP_DIR} ${WEBROOT}

[Install]
WantedBy=multi-user.target
EOF

echo "==> systemctl daemon-reload"
systemctl daemon-reload

echo "==> Enabling and (re)starting service ${SERVICE_NAME}"
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"

echo
echo "==> Service status:"
systemctl --no-pager --full status "${SERVICE_NAME}.service" || true

echo
if [[ "$PORT" == "80" ]]; then
  echo "App is at http://<this-host>/anonym/ (port 80, no port in URL)."
else
  echo "App is at http://<this-host>:${PORT}/anonym/."
fi
echo
echo "Useful commands:"
echo "  systemctl status ${SERVICE_NAME}"
echo "  systemctl restart ${SERVICE_NAME}"
echo "  systemctl stop ${SERVICE_NAME}"
echo "  systemctl disable --now ${SERVICE_NAME}   # disable permanently"
echo "  journalctl -u ${SERVICE_NAME} -f"