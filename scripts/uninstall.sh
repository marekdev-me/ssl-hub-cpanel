#!/bin/bash
set -euo pipefail


BIN_DIR="/usr/local/cpanel/whostmgr/docroot/cgi/ssl-hub"
APPCONF_DIR="/var/cpanel/apps"


# Unregister and remove files
/usr/local/cpanel/bin/unregister_appconfig ssl-hub.conf || true
rm -f "$APPCONF_DIR/ssl-hub.conf"
rm -f "$BIN_DIR/zerossl.sh" "$BIN_DIR/ssl-hub"
# Remove dir if empty
rmdir "$BIN_DIR" 2>/dev/null || true


echo "SSL Hub uninstalled. State in /root/.ssl-hub left intact (remove manually if desired)."