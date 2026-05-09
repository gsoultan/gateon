package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	configPath := filepath.Join(tempDir, m.config.Path)
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
