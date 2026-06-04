#!/usr/bin/env bash
#
# Local test launch for the MeshCore n8n plugin.
#
# Uses n8n's documented "owner managed by env" provisioning so the test account
# is created by n8n itself at boot (no first-run setup screen, fixed/known creds).
# Docs: https://docs.n8n.io/hosting/configuration/user-management-self-hosted/
#       https://docs.n8n.io/integrations/creating-nodes/test/run-node-locally/
#
# NOTE: N8N_USER_MANAGEMENT_DISABLED was removed from n8n — there is no longer a
# way to disable the login screen, so we pre-provision a known owner instead.
# N8N_INSTANCE_OWNER_PASSWORD_HASH must be a bcrypt hash (plaintext breaks login).
#
# Usage:  scripts/dev-n8n.sh [port]
# Stop:   Ctrl+C
#
set -uo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="/home/kirill/111/progr/JS/n8n-mesh/node-v22.22.3-linux-x64/bin"
export PATH="$NODE_BIN:$PATH"

PORT="${1:-5678}"
USER_FOLDER="$PKG_DIR/.n8n-dev"

EMAIL="test@meshcore.local"
PASSWORD="Meshcore123"
BASE="http://localhost:$PORT"

# --- bcrypt the password (python3 preferred, htpasswd fallback) ---
hash_password() {
  if command -v python3 >/dev/null && python3 -c "import bcrypt" 2>/dev/null; then
    python3 -c "import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt(rounds=10)).decode())" "$PASSWORD"
  elif command -v htpasswd >/dev/null; then
    # htpasswd emits $2y$, which bcrypt verifiers accept
    htpasswd -bnBC 10 "" "$PASSWORD" | tr -d ':\n' | sed 's/^\$2y/\$2b/'
  else
    echo "NO_BCRYPT_TOOL"
  fi
}
PASSWORD_HASH="$(hash_password)"
if [ "$PASSWORD_HASH" = "NO_BCRYPT_TOOL" ] || [ -z "$PASSWORD_HASH" ]; then
  echo "ERROR: need python3+bcrypt or htpasswd to hash the owner password"; exit 1
fi

# --- node loading + owner provisioning via env ---
export N8N_USER_FOLDER="$USER_FOLDER"
export N8N_CUSTOM_EXTENSIONS="$PKG_DIR"           # loads this package's nodes (package.json "n8n" field)
export N8N_PORT="$PORT"
export N8N_DIAGNOSTICS_ENABLED=false
export N8N_SECURE_COOKIE=false
export DB_SQLITE_POOL_SIZE=1
export N8N_INSTANCE_OWNER_MANAGED_BY_ENV=true
export N8N_INSTANCE_OWNER_EMAIL="$EMAIL"
export N8N_INSTANCE_OWNER_FIRST_NAME=Test
export N8N_INSTANCE_OWNER_LAST_NAME=User
export N8N_INSTANCE_OWNER_PASSWORD_HASH="$PASSWORD_HASH"

mkdir -p "$USER_FOLDER"

echo "==> Building plugin (npm run build)"
if ! ( cd "$PKG_DIR" && npm run build ) >/tmp/meshcore-build.log 2>&1; then
  echo "BUILD FAILED — last lines of /tmp/meshcore-build.log:"; tail -20 /tmp/meshcore-build.log; exit 1
fi
echo "    build OK"

echo "==> Starting n8n on :$PORT  (user folder: $USER_FOLDER)"
npx -y n8n@latest start &
N8N_PID=$!
trap 'echo; echo "==> Stopping n8n ($N8N_PID)"; kill "$N8N_PID" 2>/dev/null; wait "$N8N_PID" 2>/dev/null; exit 0' INT TERM

http_code() { curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null || echo 000; }

# Wait for the node catalog to actually contain the node (real readiness signal).
# The catalog needs auth, so log in with the env-provisioned owner first (retry).
echo -n "==> Waiting for n8n + MeshCore nodes"
ok=""
for _ in $(seq 1 150); do
  [ "$(http_code "$BASE/rest/settings")" = "200" ] || { echo -n "."; sleep 2; continue; }
  cookie=$(curl -s -i -X POST "$BASE/rest/login" -H 'content-type: application/json' \
    -d "{\"emailOrLdapLoginId\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" 2>/dev/null \
    | grep -i '^set-cookie:' | sed 's/^[Ss]et-[Cc]ookie: //; s/;.*//')
  nodes=$(curl -s "$BASE/types/nodes.json" -b "${cookie:-}" 2>/dev/null \
    | grep -oE '"name":"[^"]*[Mm]esh[Cc]ore[^"]*"' | sort -u)
  if echo "$nodes" | grep -qi meshcore; then ok=1; break; fi
  echo -n "."; sleep 2
done
echo

if [ -n "$ok" ]; then
  echo "    login OK + nodes registered:"; echo "$nodes" | sed 's/^/      /'
else
  echo "    WARNING: could not confirm login/nodes (n8n still running). See /tmp/meshcore-build.log."
fi

cat <<EOF

==================================================================
  n8n is running
    URL:      $BASE
    Email:    $EMAIL
    Password: $PASSWORD
  Nodes:      MeshCore (action), MeshCore Trigger
  Stop:       Ctrl+C
==================================================================
READY
EOF

wait "$N8N_PID"
