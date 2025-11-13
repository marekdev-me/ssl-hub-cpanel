#!/bin/bash
# Wrapper to issue wildcard certs from ZeroSSL via acme.sh using dns_cpanel and deploy via cpanel_uapi
set -euo pipefail
umask 077


DOMAIN="$1" # example.com
EAB_KID="$2"
EAB_HMAC="$3"


ACME_BIN="${HOME}/.acme.sh/acme.sh"
[ -x "$ACME_BIN" ] || ACME_BIN="/root/.acme.sh/acme.sh"


if [ ! -x "$ACME_BIN" ]; then
echo "acme.sh not found. Install with: curl https://get.acme.sh | sh" >&2
exit 1
fi


# Read tokens from root-only files (created by installer); fall back to env if present
CPANEL_USERNAME=${CPANEL_Username:-root}
CPANEL_HOST=${CPANEL_Hostname:-127.0.0.1}
if [ -f /root/.ssl-hub/cpanel_token ]; then
CPANEL_TOKEN=$(cat /root/.ssl-hub/cpanel_token)
else
CPANEL_TOKEN=${CPANEL_Token:-}
fi


export ZEROSSL_EAB_KID="$EAB_KID"
export ZEROSSL_EAB_HMAC_KEY="$EAB_HMAC"
export CPANEL_Username="$CPANEL_USERNAME"
export CPANEL_Hostname="$CPANEL_HOST"
export CPANEL_Token="$CPANEL_TOKEN"


# Register account (idempotent)
"$ACME_BIN" --register-account --server zerossl \
--eab-kid "$ZEROSSL_EAB_KID" --eab-hmac-key "$ZEROSSL_EAB_HMAC_KEY" || true


# Issue example.com + *.example.com via DNS‑01 using cPanel DNS API
"$ACME_BIN" --server zerossl \
--issue -d "$DOMAIN" -d "*.$DOMAIN" --dns dns_cpanel


# Deploy into the matching cPanel account automatically
"$ACME_BIN" --deploy -d "$DOMAIN" --deploy-hook cpanel_uapi


echo "[OK] Issued and installed certificate for $DOMAIN (+ wildcard)."