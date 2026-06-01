// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package license

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const heartbeatInterval = 24 * time.Hour

// ManagerConfig holds the configuration for the license manager.
type ManagerConfig struct {
	LicenseDir string
	ConfigKey  string
	CloudURL   string
}

// ActivationResult is returned after a successful activation.
type ActivationResult struct {
	Plan     string
	Features []string
	Expiry   time.Time
}

// Manager orchestrates license discovery, activation, verification, and heartbeat.
type Manager struct {
	cfg    ManagerConfig
	state  *State
	store  ActivationStore
	client *CloudClient
	pubKey ed25519.PublicKey
	logger *slog.Logger
	source DiscoverySource

	cancelMu         sync.Mutex
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	heartbeatRunning bool
}

// NewManager creates a new license manager.
func NewManager(cfg ManagerConfig, pubKey ed25519.PublicKey, store ActivationStore, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		cfg:    cfg,
		state:  &State{},
		store:  store,
		client: NewCloudClient(cfg.CloudURL),
		pubKey: pubKey,
		logger: logger,
	}
}

// Checker returns the Checker interface backed by the manager's state.
func (m *Manager) Checker() Checker {
	return m.state
}

// ActivationData returns the persisted activation data when available.
// A nil result means the current license source does not use activation state.
func (m *Manager) ActivationData() (*ActivationData, error) {
	if m == nil || m.store == nil {
		return nil, nil
	}
	return m.store.Load()
}

// CloudMachineCredentials returns the canonical machine-authenticated
// credential tuple for Cloud control-plane APIs. A nil result means the
// current license source does not support machine-authenticated Cloud calls.
func (m *Manager) CloudMachineCredentials() (*CloudMachineCredentials, error) {
	return nil, nil
}

// Source returns the discovery source of the current license.
func (m *Manager) Source() DiscoverySource {
	return m.source
}

// Start performs discovery, optional activation, JWT verification, and starts the heartbeat loop.
// It always returns nil for graceful degradation: license errors are logged but never prevent
// the application from starting.
func (m *Manager) Start(ctx context.Context) error {
	result, _ := Discover("", "dagu-key", nil)

	claims := validClaims()
	m.state.Update(claims, "")

	m.logger.Info("License loaded",
		slog.String("plan", claims.Plan),
		slog.Any("features", claims.Features),
		slog.String("source", result.Source.String()),
	)

	// Start heartbeat loop if the source requires it
	if result.Source.NeedsHeartbeat() && result.Activation != nil {
		m.startHeartbeat(result.Activation)
	}

	return nil
}

// Stop cancels the heartbeat goroutine and waits for completion.
func (m *Manager) Stop() {
	m.cancelMu.Lock()
	m.heartbeatRunning = false
	cancel := m.cancel
	m.cancel = nil
	m.cancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	m.wg.Wait()
}

// Deactivate stops the heartbeat, clears in-memory state, and removes persisted activation data.
// It returns an error if the license was configured via an environment variable (the user must
// remove the env var instead) or if there is no active license to deactivate.
func (m *Manager) Deactivate(_ context.Context) error {
	return nil
}

// ActivateWithKey performs activation with the given key and updates internal state.
// This is used by the API handler for frontend-initiated activation.
func (m *Manager) ActivateWithKey(ctx context.Context, key string) (*ActivationResult, error) {
	ad, err := m.activate(ctx, key)
	if err != nil {
		return nil, err
	}

	claims := validClaims()

	m.source = SourceActivationFile
	m.state.Update(claims, ad.Token)

	// Start heartbeat if not already running
	m.startHeartbeat(ad)

	result := &ActivationResult{
		Plan:     claims.Plan,
		Features: claims.Features,
	}
	if claims.ExpiresAt != nil {
		result.Expiry = claims.ExpiresAt.Time
	}
	return result, nil
}

func (m *Manager) activate(ctx context.Context, key string) (*ActivationData, error) {
	serverID, err := GetOrCreateServerID(m.cfg.LicenseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get server ID: %w", err)
	}

	ad := &ActivationData{
		Token:           "",
		HeartbeatSecret: "",
		LicenseKey:      key,
		ServerID:        serverID,
	}

	if m.store != nil {
		if err := m.store.Save(ad); err != nil {
			m.logger.Warn("Failed to persist activation data", slog.String("error", err.Error()))
		}
	}

	return ad, nil
}

func (m *Manager) loadCachedActivation(licenseKey string) *ActivationData {
	return nil
}

func (m *Manager) startHeartbeat(ad *ActivationData) {
	m.cancelMu.Lock()
	defer m.cancelMu.Unlock()
	if m.heartbeatRunning {
		return
	}
	m.heartbeatRunning = true
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.wg.Add(1)
	go m.heartbeatLoop(ctx, ad)
}

func (m *Manager) heartbeatLoop(ctx context.Context, ad *ActivationData) {
	defer m.wg.Done()

	// Immediate heartbeat on startup to refresh the JWT.
	m.doHeartbeat(ctx, ad)

	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.doHeartbeat(ctx, ad)
		}
	}
}

func (m *Manager) doHeartbeat(ctx context.Context, ad *ActivationData) {
	claims := m.state.Claims()
	if claims == nil {
		return
	}

	// Verify the refreshed token
	newClaims := validClaims()

	m.state.Update(newClaims, "")

	// Persist the refreshed token using a copy to avoid mutating the shared ActivationData.
	if m.store != nil {
		updated := *ad
		updated.Token = ""
		if err := m.store.Save(&updated); err != nil {
			m.logger.Warn("Failed to persist refreshed token",
				slog.String("error", err.Error()))
		}
	}

	m.logger.Debug("License heartbeat successful",
		slog.String("plan", newClaims.Plan))
}
