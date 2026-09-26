#!/bin/sh
set -e

# The service runs as its own account, not root (ADR 0019). The same flags as
# useraddArgs in internal/install, which a test holds this file to.
if ! getent passwd gateon >/dev/null 2>&1; then
  shell=/usr/sbin/nologin
  [ -x "$shell" ] || shell=/sbin/nologin
  [ -x "$shell" ] || shell=/bin/false
  useradd --system --user-group --no-create-home --home-dir /var/lib/gateon --shell "$shell" gateon
fi

# Ownership and modes for new and existing installations. The modes match what
# `gateon install` sets (internal/install, which a test holds this file to):
# /etc/gateon holds global.json -- database credentials and the paseto secret
# that signs every admin session -- so it gets no world bits, and this runs on
# every upgrade, so anything looser here undoes an operator's own hardening.
# Both directories go to the service account, which writes to both at runtime.
# systemd would hand over /var/lib/gateon on start by itself (StateDirectory=),
# but it leaves an existing /etc/gateon alone, so an upgrade from a root-owned
# install needs this.
mkdir -p /etc/gateon /var/lib/gateon
chown -R gateon:gateon /etc/gateon /var/lib/gateon
chmod 750 /etc/gateon
chmod 700 /var/lib/gateon

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable gateon 2>/dev/null || true
  # Restart so it runs under the unit just installed, as the service account.
  systemctl restart gateon 2>/dev/null || true
fi
