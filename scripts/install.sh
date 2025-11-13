#!/bin/bash
set -euo pipefail
umask 022


BIN_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub"
APPCONF_DIR="/var/cpanel/apps"
STATE_DIR="/root/.ssl-hub"


mkdir -p "$BIN_DIR" "$APPCONF_DIR" "$STATE_DIR"
chmod 700 "$STATE_DIR"


# Copy files from the repo tree (assumes running from repo root)
install -m 750 whm/cgi/ssl-hub "$BIN_DIR/ssl-hub"
install -m 700 whm/cgi/zerossl.sh "$BIN_DIR/zerossl.sh"
install -m 644 whm/appconf/ssl-hub.conf "$APPCONF_DIR/ssl-hub.conf"


# Register AppConfig (adds WHM icon)
/usr/local/cpanel/bin/register_appconfig "$APPCONF_DIR/ssl-hub.conf"


echo "Installed SSL Hub. Optional: place a WHM/cPanel API token with DNS+SSL perms in $STATE_DIR/cpanel_token (0600)."