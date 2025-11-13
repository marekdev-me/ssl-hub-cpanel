#!/bin/bash
# Wrapper to issue ZeroSSL certificates via acme.sh using cPanel DNS + deploy hooks.
set -euo pipefail
umask 077

STATE_DIR=${STATE_DIR:-/root/.ssl-hub}
ZEROSSL_KID_FILE="$STATE_DIR/zerossl_kid"
ZEROSSL_HMAC_FILE="$STATE_DIR/zerossl_hmac"

ACME_BIN="${HOME}/.acme.sh/acme.sh"
[ -x "$ACME_BIN" ] || ACME_BIN="/root/.acme.sh/acme.sh"

if [ ! -x "$ACME_BIN" ]; then
  echo "acme.sh not found. Install with: curl https://get.acme.sh | sh" >&2
  exit 1
fi

trim_ws() {
  local var="$1"
  var=${var#${var%%[![:space:]]*}}
  var=${var%${var##*[![:space:]]}}
  printf '%s' "$var"
}

read_secret_file() {
  local path="$1"
  if [ ! -f "$path" ]; then
    return 1
  fi
  local raw
  raw=$(head -n 1 "$path" | tr -d '\r')
  trim_ws "$raw"
}

discover_user_for_domain() {
  local domain="$1"
  /usr/local/cpanel/bin/whmapi1 listaccts --output=json 2>/dev/null \
    | python3 - "$domain" <<'PY'
import json
import sys

domain = sys.argv[1].strip().lower()
try:
    payload = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for acct in payload.get("data", {}).get("acct", []):
    dom = str(acct.get("domain", "")).strip().lower()
    if dom == domain:
        user = acct.get("user")
        if user:
            print(user)
            sys.exit(0)
        break
sys.exit(1)
PY
}

issue_domain() {
  local domain="$1"
  local user="${2:-}"

  echo "==> Requesting ZeroSSL certificate for $domain"
  if [ -z "$user" ]; then
    if user=$(discover_user_for_domain "$domain"); then
      echo "    cPanel user: $user"
    else
      echo "    Unable to determine cPanel user automatically; using CPANEL_Username context." >&2
      user=""
    fi
  else
    echo "    cPanel user: $user"
  fi

  if [ -n "$user" ]; then
    export DEPLOY_CPANEL_USER="$user"
  else
    unset DEPLOY_CPANEL_USER || true
  fi

  if ! "$ACME_BIN" --server zerossl --issue -d "$domain" -d "*.$domain" --dns dns_cpanel; then
    echo "[ERROR] Failed to issue certificate for $domain." >&2
    return 1
  fi
  if ! "$ACME_BIN" --deploy -d "$domain" --deploy-hook cpanel_uapi; then
    echo "[ERROR] Failed to deploy certificate for $domain." >&2
    return 1
  fi

  echo "[OK] Issued and installed certificate for $domain (+ wildcard)."
  return 0
}

run_all() {
  local -a accounts=()
  if ! mapfile -t accounts < <(/usr/local/cpanel/bin/whmapi1 listaccts --output=json 2>/dev/null \
    | python3 <<'PY'
import json
import sys

try:
    payload = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for acct in payload.get("data", {}).get("acct", []):
    if str(acct.get("suspended", "0")).lower() in {"1", "true", "yes"}:
        continue
    user = acct.get("user")
    domain = acct.get("domain")
    if not user or not domain:
        continue
    domain = str(domain).strip().lower()
    if not domain:
        continue
    print(f"{user} {domain}")
PY
  ); then
    echo "[ERROR] Failed to enumerate cPanel accounts." >&2
    return 1
  fi

  if [ ${#accounts[@]} -eq 0 ]; then
    echo "No active cPanel accounts found." >&2
    return 0
  fi

  local failures=0
  local entry
  for entry in "${accounts[@]}"; do
    local user="${entry%% *}"
    local domain="${entry#* }"
    echo ""
    echo "=== $domain (user: $user) ==="
    if issue_domain "$domain" "$user"; then
      continue
    fi
    failures=$((failures + 1))
  done

  if [ "$failures" -gt 0 ]; then
    echo "" >&2
    echo "Completed with $failures failure(s)." >&2
    return 1
  fi

  echo ""
  echo "All ZeroSSL certificates finished successfully."
  return 0
}

usage() {
  cat >&2 <<'USAGE'
Usage: zerossl.sh <primary-domain> [EAB_KID] [EAB_HMAC]
       zerossl.sh --run-all
USAGE
}

MODE="single"
DOMAIN=""
EAB_KID=""
EAB_HMAC=""

if [ $# -eq 0 ]; then
  usage
  exit 1
fi

case "$1" in
  --run-all)
    MODE="run_all"
    shift
    ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    DOMAIN="$1"
    shift
    if [ $# -ge 1 ]; then
      EAB_KID="$1"
      shift
    fi
    if [ $# -ge 1 ]; then
      EAB_HMAC="$1"
      shift
    fi
    ;;
ESAC

if [ "$MODE" = "single" ] && [ -z "$DOMAIN" ]; then
  echo "Primary domain is required." >&2
  exit 1
fi

if [ -z "$EAB_KID" ] && [ -n "${ZEROSSL_EAB_KID:-}" ]; then
  EAB_KID="$ZEROSSL_EAB_KID"
fi
if [ -z "$EAB_HMAC" ] && [ -n "${ZEROSSL_EAB_HMAC_KEY:-}" ]; then
  EAB_HMAC="$ZEROSSL_EAB_HMAC_KEY"
fi

if [ -z "$EAB_KID" ]; then
  if EAB_KID=$(read_secret_file "$ZEROSSL_KID_FILE"); then
    :
  fi
fi
if [ -z "$EAB_HMAC" ]; then
  if EAB_HMAC=$(read_secret_file "$ZEROSSL_HMAC_FILE"); then
    :
  fi
fi

if [ -z "$EAB_KID" ] || [ -z "$EAB_HMAC" ]; then
  echo "ZeroSSL External Account Binding credentials not provided. Save them first from the UI." >&2
  exit 1
fi

CPANEL_USERNAME=${CPANEL_Username:-root}
CPANEL_HOST=${CPANEL_Hostname:-127.0.0.1}
if [ -f "$STATE_DIR/cpanel_token" ]; then
  CPANEL_TOKEN=$(head -n 1 "$STATE_DIR/cpanel_token")
else
  CPANEL_TOKEN=${CPANEL_Token:-}
fi

export ZEROSSL_EAB_KID="$EAB_KID"
export ZEROSSL_EAB_HMAC_KEY="$EAB_HMAC"
export CPANEL_Username="$CPANEL_USERNAME"
export CPANEL_Hostname="$CPANEL_HOST"
export CPANEL_Token="$CPANEL_TOKEN"

"$ACME_BIN" --register-account --server zerossl \
  --eab-kid "$ZEROSSL_EAB_KID" --eab-hmac-key "$ZEROSSL_EAB_HMAC_KEY" || true

if [ "$MODE" = "run_all" ]; then
  run_all
else
  issue_domain "$DOMAIN"
fi
