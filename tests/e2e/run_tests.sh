#!/bin/bash
set -e

# 1. Re-initialize database
rm -f gateon_test.db gateon_test.db-shm gateon_test.db-wal
go run ./tests/e2e/create_user

# 2. Build UI if needed (skipping for now if already built)
# cd ui && bun run build && cd ..
# go run scripts/sync_assets.go

# 3. Build gateon
go build -o gateon ./cmd/gateon

# 4. Run Playwright tests
cd tests/e2e
# bun install
# bun playwright install chromium
rtk bun playwright test
