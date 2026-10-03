#!/bin/sh
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
set -e

# rpm only: runs last in an upgrade, after the old package's %postun -- which
# in v1.0.0 and earlier stops and disables the service. Put back the state
# preinstall recorded (see postinstall.sh), then forget it.
state=${GATEON_UPGRADE_STATE:-/run/gateon-upgrade.state}
[ -f "$state" ] || exit 0
if command -v systemctl >/dev/null 2>&1; then
  if [ "$(sed -n 's/^enabled=//p' "$state")" = yes ]; then
    systemctl enable gateon 2>/dev/null || true
  fi
  if [ "$(sed -n 's/^active=//p' "$state")" = yes ]; then
    systemctl restart gateon 2>/dev/null || true
  fi
fi
rm -f "$state"
