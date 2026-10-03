#!/bin/sh
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT
set -e

# Stop and disable the service only when the package is being removed. This
# script also runs on every upgrade -- deb postrm "upgrade", rpm %postun with
# $1 = 1 -- and used to stop and disable the service then too, which undid an
# operator's choice either way: the postinstall that followed enabled it again.
#
# deb: postrm "remove" or "purge"; rpm: %postun with $1 = 0.
case "$1" in
  remove|purge|0) ;;
  *) exit 0 ;;
esac

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop gateon 2>/dev/null || true
  systemctl disable gateon 2>/dev/null || true
  systemctl daemon-reload || true
fi
