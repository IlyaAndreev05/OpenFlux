package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"openflux/transport/yandex"
)

var safePoolID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

type Client struct {
	ID        string `json:"id"`
	ClientKey string `json:"client_key"`
}
type Pool struct {
	PoolID          string                    `json:"pool_id"`
	ProtocolVersion byte                      `json:"protocol_version"`
	Strategy        string                    `json:"strategy"`
	Mode            string                    `json:"mode"`
	Documents       []yandex.PoolDocument     `json:"documents"`
	Forward         *yandex.PoolForwardConfig `json:"forward,omitempty"`
	Clients         []Client                  `json:"clients"`
}
type DesiredConfig struct {
	Version int64  `json:"version"`
	Pools   []Pool `json:"pools"`
}
type Child interface{ Close() error }
type Starter interface {
	Start(configPath string) (Child, error)
}

type Manager struct {
	StateDir  string
	Starter   Starter
	mu        sync.Mutex
	version   int64
	children  map[string]Child
	activeDir string
}

func NewManager(stateDir string, starter Starter) (*Manager, error) {
	if stateDir == "" || starter == nil {
		return nil, errors.New("state directory and process starter are required")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{StateDir: stateDir, Starter: starter, children: map[string]Child{}}
	if err := m.restoreLatest(); err != nil {
		return nil, err
	}
	return m, nil
}
func (m *Manager) Version() int64 { m.mu.Lock(); defer m.mu.Unlock(); return m.version }

// Apply validates and starts every pool in a candidate generation before
// retiring the prior generation. The manifest is retained so a restart can
// recover the last successfully applied configuration while Control is down.
func (m *Manager) Apply(ctx context.Context, cfg DesiredConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := normalize(&cfg); err != nil {
		return err
	}
	if cfg.Version < m.version {
		return errors.New("stale node config version")
	}
	if cfg.Version == m.version {
		return nil
	}
	candidateDir := filepath.Join(m.StateDir, fmt.Sprintf("version-%d", cfg.Version))
	if err := os.RemoveAll(candidateDir); err != nil {
		return err
	}
	if err := os.Mkdir(candidateDir, 0700); err != nil {
		return err
	}
	cleanup := func(children map[string]Child) {
		for _, child := range children {
			_ = child.Close()
		}
		_ = os.RemoveAll(candidateDir)
	}
	manifest, err := json.Marshal(cfg)
	if err != nil {
		_ = os.RemoveAll(candidateDir)
		return errors.New("node config could not be encoded")
	}
	if err := writeAtomic(filepath.Join(candidateDir, "manifest.json"), manifest, 0600); err != nil {
		_ = os.RemoveAll(candidateDir)
		return fmt.Errorf("write node config manifest: %w", err)
	}
	candidate, err := m.startGeneration(ctx, cfg, candidateDir)
	if err != nil {
		cleanup(candidate)
		return err
	}
	old := m.children
	oldDir := m.activeDir
	m.children = candidate
	m.activeDir = candidateDir
	m.version = cfg.Version
	for _, child := range old {
		_ = child.Close()
	}
	if oldDir != "" && oldDir != candidateDir {
		_ = os.RemoveAll(oldDir)
	}
	return nil
}

func normalize(cfg *DesiredConfig) error {
	if cfg.Version <= 0 {
		return errors.New("invalid node config version")
	}
	seen := map[string]bool{}
	for i := range cfg.Pools {
		pool := &cfg.Pools[i]
		if !safePoolID.MatchString(pool.PoolID) || seen[pool.PoolID] {
			return errors.New("node config contains an invalid or duplicate pool id")
		}
		seen[pool.PoolID] = true
		if pool.ProtocolVersion == 0 {
			pool.ProtocolVersion = 2
		}
		if pool.ProtocolVersion != 1 && pool.ProtocolVersion != 2 {
			return errors.New("node config has an unsupported pool protocol version")
		}
		if pool.Strategy == "" {
			pool.Strategy = "least-loaded"
		}
		if pool.Mode == "" {
			pool.Mode = "standalone"
		}
		if pool.Mode != "standalone" && pool.Mode != "transport" {
			return errors.New("node config has an invalid pool mode")
		}
		if pool.Mode == "transport" && pool.Forward == nil {
			return errors.New("transport pool is missing its Xray forward route")
		}
		if pool.Mode == "standalone" && pool.Forward != nil {
			return errors.New("standalone pool must not contain an Xray forward route")
		}
		if pool.Strategy != "round-robin" && pool.Strategy != "least-loaded" && pool.Strategy != "sticky" {
			return errors.New("node config has an invalid pool strategy")
		}
		if len(pool.Documents) == 0 || len(pool.Documents) > yandex.MaxPoolDocuments {
			return errors.New("node config contains an invalid document list")
		}
		clientIDs := map[string]bool{}
		for _, client := range pool.Clients {
			if client.ID == "" || len(client.ID) > 64 || len(client.ClientKey) != 64 || clientIDs[client.ID] {
				return errors.New("node config contains an invalid client")
			}
			clientIDs[client.ID] = true
		}
		if len(pool.Clients) > yandex.MaxPoolClients {
			return errors.New("node config contains too many clients")
		}
	}
	return nil
}

func (m *Manager) startGeneration(ctx context.Context, cfg DesiredConfig, dir string) (map[string]Child, error) {
	children := map[string]Child{}
	for _, pool := range cfg.Pools {
		if err := ctx.Err(); err != nil {
			return children, err
		}
		clientKeys := make([]map[string]string, 0, len(pool.Clients))
		for _, client := range pool.Clients {
			clientKeys = append(clientKeys, map[string]string{"id": client.ID, "client_key": client.ClientKey})
		}
		value := map[string]any{"protocol_version": pool.ProtocolVersion, "pool_id": pool.PoolID, "strategy": pool.Strategy, "documents": pool.Documents, "clients": clientKeys}
		if pool.Forward != nil {
			value["forward"] = pool.Forward
		}
		data, err := json.Marshal(value)
		if err != nil {
			return children, errors.New("node pool config could not be encoded")
		}
		path := filepath.Join(dir, pool.PoolID+".json")
		if err := writeAtomic(path, data, 0600); err != nil {
			return children, fmt.Errorf("write candidate pool config: %w", err)
		}
		loaded, err := yandex.LoadPoolConfig(path, "exit")
		if err != nil {
			return children, errors.New("node pool configuration was rejected")
		}
		if len(loaded.Clients) != len(pool.Clients) {
			return children, errors.New("node pool configuration has inconsistent clients")
		}
		child, err := m.Starter.Start(path)
		if err != nil {
			return children, errors.New("OpenFlux rejected the new pool generation")
		}
		children[pool.PoolID] = child
	}
	return children, nil
}

func (m *Manager) restoreLatest() error {
	entries, err := os.ReadDir(m.StateDir)
	if err != nil {
		return err
	}
	type generation struct {
		version int64
		dir     string
	}
	var candidates []generation
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "version-") {
			continue
		}
		version, err := strconv.ParseInt(strings.TrimPrefix(entry.Name(), "version-"), 10, 64)
		if err == nil && version > 0 {
			candidates = append(candidates, generation{version, filepath.Join(m.StateDir, entry.Name())})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].version > candidates[j].version })
	for _, candidate := range candidates {
		data, err := os.ReadFile(filepath.Join(candidate.dir, "manifest.json"))
		if err != nil {
			continue
		}
		var cfg DesiredConfig
		if json.Unmarshal(data, &cfg) != nil || cfg.Version != candidate.version || normalize(&cfg) != nil {
			continue
		}
		children, err := m.startGeneration(context.Background(), cfg, candidate.dir)
		if err != nil {
			for _, child := range children {
				_ = child.Close()
			}
			continue
		}
		m.version = cfg.Version
		m.activeDir = candidate.dir
		m.children = children
		return nil
	}
	return nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var first error
	for _, child := range m.children {
		if err := child.Close(); err != nil && first == nil {
			first = err
		}
	}
	m.children = map[string]Child{}
	m.activeDir = ""
	return first
}
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".openflux-config-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
