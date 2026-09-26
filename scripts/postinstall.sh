#!/bin/sh
set -e

# Fix permissions for existing installations. The modes match what
# `gateon install` sets (internal/install, which a test holds this file to):
# /etc/gateon holds global.json -- database credentials and the paseto secret
# that signs every admin session -- so it gets no world bits, and this runs on
# every upgrade, so anything looser here undoes an operator's own hardening.
mkdir -p /etc/gateon /var/lib/gateon
chown -R root:root /etc/gateon /var/lib/gateon
chmod 750 /etc/gateon
chmod 700 /var/lib/gateon

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable gateon 2>/dev/null || true
  # Restart to ensure it runs as root with new security settings
  systemctl restart gateon 2>/dev/null || true
fi
