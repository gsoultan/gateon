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

# The service: a fresh install enables and starts it. An upgrade leaves it as
# the operator had it -- enabled or not, running or not -- which preinstall
# recorded before the old package's scripts ran (review F11). It used to
# enable and restart it on every upgrade, undoing a deliberate disable.
#
# deb: postinst "configure"; rpm: %post with $1 = 1 (install) or 2 (upgrade).
# On rpm the old package's %postun runs after this, and v1.0.0's stops and
# disables the service, so posttrans applies the recorded state once more.
state=${GATEON_UPGRADE_STATE:-/run/gateon-upgrade.state}
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  if [ -f "$state" ]; then
    enabled=$(sed -n 's/^enabled=//p' "$state")
    active=$(sed -n 's/^active=//p' "$state")
    if [ "$enabled" = yes ]; then
      systemctl enable gateon 2>/dev/null || true
    fi
    if [ "$active" = yes ]; then
      # Restart so it runs the binary and unit just installed.
      systemctl restart gateon 2>/dev/null || true
    fi
    case "$1" in
      [0-9]*) ;; # rpm: posttrans reads it again, then removes it
      *) rm -f "$state" ;;
    esac
  else
    systemctl enable gateon 2>/dev/null || true
    systemctl restart gateon 2>/dev/null || true
  fi
fi
