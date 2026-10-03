#!/bin/sh
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
set -e

# On an upgrade, remember whether the service was enabled and running, so the
# new package can leave it that way (review F11). This runs before the old
# package's scripts: the postremove of v1.0.0 and earlier stops and disables
# the service on every upgrade, and the postinstall used to enable and start
# it again unconditionally, so a node an operator had deliberately disabled --
# a standby, one under maintenance -- came back on with every upgrade.
#
# deb: preinst "upgrade" <old-version>; rpm: %pre with $1 >= 2.
state=${GATEON_UPGRADE_STATE:-/run/gateon-upgrade.state}
case "$1" in
  upgrade) ;;
  [2-9]|[1-9][0-9]*) ;;
  *) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  enabled=no
  active=no
  systemctl is-enabled --quiet gateon 2>/dev/null && enabled=yes
  systemctl is-active --quiet gateon 2>/dev/null && active=yes
  printf 'enabled=%s\nactive=%s\n' "$enabled" "$active" > "$state"
fi
