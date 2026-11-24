#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./deploy.sh <ip> [remote_user] [remote_dir]

Builds the production rnd-log-anonymizer (npm run build) and uploads the
contents of dist/ to a remote host via tar streamed over SSH (does not require
rsync on the target — only ssh + tar). Starting a server on the target
(e.g. python3 -m http.server) is out of scope; this script only transfers files.

  ip           IP address or hostname of the target host (required)
  remote_user  SSH user on the target (default: current local user, $USER)
  remote_dir   Path on the target where files are uploaded (default: anonym,
               relative to remote_user's home). You may also use "~/something"
               or an absolute path.

Examples:
  ./deploy.sh 10.20.30.40
  ./deploy.sh 10.20.30.40 deploy
  ./deploy.sh 10.20.30.40 deploy /srv/anonym
EOF
}

if [[ $# -lt 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 1
fi

REMOTE_IP="$1"
REMOTE_USER="${2:-$USER}"
REMOTE_DIR="${3:-anonym}"
REMOTE_TARGET="${REMOTE_USER}@${REMOTE_IP}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "==> Building production bundle (tsc -b && vite build)"
npm run build

if [[ ! -d dist ]]; then
  echo "error: dist/ missing after build" >&2
  exit 1
fi

echo "==> Verifying SSH connection to ${REMOTE_TARGET}"
ssh -o BatchMode=yes -o ConnectTimeout=10 "$REMOTE_TARGET" true

# "~" inside single quotes on the remote shell is NEVER expanded, so we replace
# it here with the actual home path fetched via $HOME on the target.
if [[ "$REMOTE_DIR" == "~" || "$REMOTE_DIR" == "~/"* ]]; then
  REMOTE_HOME="$(ssh -o BatchMode=yes "$REMOTE_TARGET" 'printf %s "$HOME"')"
  REMOTE_DIR="${REMOTE_HOME}${REMOTE_DIR#\~}"
fi

case "$REMOTE_DIR" in
  ""|"/"|".")
    echo "error: unsafe remote_dir path: '${REMOTE_DIR}'" >&2
    exit 1
    ;;
esac

echo "==> Preparing target directory ${REMOTE_DIR} on ${REMOTE_TARGET} (clearing old contents)"
ssh "$REMOTE_TARGET" "mkdir -p '${REMOTE_DIR}' && find '${REMOTE_DIR}' -mindepth 1 -delete"

echo "==> Uploading dist/ to ${REMOTE_TARGET}:${REMOTE_DIR} (tar over ssh)"
tar -C dist -czf - . | ssh "$REMOTE_TARGET" "tar -C '${REMOTE_DIR}' -xzf -"

echo
echo "==> Done. Files are at ${REMOTE_TARGET}:${REMOTE_DIR}"
echo "    rnd-log-anonymizer is a static SPA only (text + pcap, no network API; see CSP connect-src 'none')."
echo "    Serve ${REMOTE_DIR} over HTTP(S), e.g.:"
echo "      ssh ${REMOTE_TARGET} 'cd ${REMOTE_DIR} && python3 -m http.server <PORT>'"
echo "    Or: sudo ./install-systemd-service.sh <app_dir>  → URL /anonym/"
echo "    Not via file:// — the app is unreliable in that mode (see README.md)."