#!/bin/bash
# Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
# SPDX-License-Identifier: MIT

# This script runs 'buf generate' with the correct PATH to find all protoc plugins.
# It ensures that both Go-based plugins and Node.js-based plugins are available.

# Add GOPATH/bin and ui/node_modules/.bin to PATH
GOPATH_BIN=$(go env GOPATH)/bin
UI_BIN="$(pwd)/ui/node_modules/.bin"

export PATH="$PATH:$GOPATH_BIN:$UI_BIN"

echo "Using PATH: $PATH"

# Run buf generate using the rtk proxy for token optimization if available
if command -v rtk >/dev/null 2>&1; then
    rtk buf generate "$@"
elif [ -f "/opt/homebrew/bin/rtk" ]; then
    /opt/homebrew/bin/rtk buf generate "$@"
else
    buf generate "$@"
fi
