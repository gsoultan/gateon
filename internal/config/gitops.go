// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/gsoultan/gateon/internal/logger"
	gateonv1 "github.com/gsoultan/gateon/proto/gateon/v1"
)

type GitOpsManager struct {
	mu     sync.Mutex
	config *gateonv1.GitOpsConfig
	store  GlobalConfigStore
	cancel context.CancelFunc
}

func NewGitOpsManager(cfg *gateonv1.GitOpsConfig, store GlobalConfigStore) *GitOpsManager {
	return &GitOpsManager{
		config: cfg,
		store:  store,
	}
}

func (m *GitOpsManager) Start(ctx context.Context) {
	if m.config == nil || !m.config.Enabled {
		return
	}

	ctx, m.cancel = context.WithCancel(ctx)
	interval := time.Duration(m.config.SyncIntervalSeconds) * time.Second
	if interval < 30*time.Second {
		interval = 60 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.Sync(ctx); err != nil {
					logger.L.LogError("gitops: sync failed", "error", err)
				}
			}
		}
	}()
}

func (m *GitOpsManager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *GitOpsManager) Sync(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tempDir, err := os.MkdirTemp("", "gateon-gitops-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)

	cloneOpts := &git.CloneOptions{
		URL:           m.config.RepositoryUrl,
		ReferenceName: plumbing.NewBranchReferenceName(m.config.Branch),
		SingleBranch:  true,
		Depth:         1,
	}

	if m.config.AuthToken != "" {
		cloneOpts.Auth = &http.BasicAuth{
			Username: "token",
			Password: m.config.AuthToken,
		}
	}

	repo, err := git.PlainCloneContext(ctx, tempDir, false, cloneOpts)
	if err != nil {
		return fmt.Errorf("clone failed: %w", err)
	}

	ref, err := repo.Head()
	if err != nil {
		return err
	}
	logger.L.LogInfo("gitops: synced to commit", "hash", ref.Hash().String())

	// filepath.Join cleans as it joins, so a configured Path of "../../etc/shadow"
	// does not produce a path inside tempDir — it produces /etc/shadow, and the
	// read below would succeed and the contents would be reported back through
	// the sync error. GitOps settings arrive over the management API, so this
	// turns "can edit config" into "can read any file the gateway can", which is
	// a different permission than the one that was granted.
	configPath, err := containedPath(tempDir, m.config.Path)
	if err != nil {
		return fmt.Errorf("gitops: %w", err)
	}
	// #nosec G304 -- containedPath has just proved this resolves inside the
	// freshly cloned tempDir.
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file at %s: %w", m.config.Path, err)
	}

	var newConfig gateonv1.GlobalConfig
	if err := json.Unmarshal(data, &newConfig); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Compare and update if different
	current := m.store.Get(ctx)
	if !m.isEqual(current, &newConfig) {
		logger.L.LogInfo("gitops: applying configuration drift resolution")
		return m.store.Update(ctx, &newConfig)
	}

	return nil
}

func (m *GitOpsManager) isEqual(a, b *gateonv1.GlobalConfig) bool {
	// Simple JSON comparison for drift detection
	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)
	return string(aj) == string(bj)
}

// containedPath joins rel onto root and proves the result is still inside root.
//
// filepath.Join cleans the path it builds, which is exactly what makes it
// unsafe with untrusted input: joining "../.." onto a root does not stay under
// the root, it walks out of it. Comparing the cleaned result against the
// cleaned root with a trailing separator is the check that actually holds —
// without the separator, "/tmp/gitops-evil" would pass as being inside
// "/tmp/gitops".
func containedPath(root, rel string) (string, error) {
	cleanRoot := filepath.Clean(root)
	joined := filepath.Join(cleanRoot, rel)
	if joined != cleanRoot && !strings.HasPrefix(joined, cleanRoot+string(os.PathSeparator)) {
		return "", fmt.Errorf("path %q escapes %q", rel, cleanRoot)
	}
	return joined, nil
}
