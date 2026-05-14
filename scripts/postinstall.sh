#!/bin/sh
set -e

# Fix permissions for existing installations
mkdir -p /etc/gateon /var/lib/gateon
chown -R root:root /etc/gateon /var/lib/gateon
chmod 755 /etc/gateon
chmod 700 /var/lib/gateon

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable gateon 2>/dev/null || true
  # Restart to ensure it runs as root with new security settings
  systemctl restart gateon 2>/dev/null || true
fi
