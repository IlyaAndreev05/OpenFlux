package nodeagent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"openflux/transport/yandex"
)

type fakeChild struct {
	mu     sync.Mutex
	closed bool
}

func (c *fakeChild) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *fakeChild) isClosed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.closed }

type fakeStarter struct {
	mu       sync.Mutex
	children []*fakeChild
	failNext bool
}

func (s *fakeStarter) Start(configPath string) (Child, error) {
	if _, err := yandex.LoadPoolConfig(configPath, "exit"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failNext {
		s.failNext = false
		return nil, errors.New("simulated startup failure")
	}
	child := &fakeChild{}
	s.children = append(s.children, child)
	return child, nil
}
func (s *fakeStarter) all() []*fakeChild {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*fakeChild(nil), s.children...)
}

func validConfig(version int64) DesiredConfig {
	return DesiredConfig{Version: version, Pools: []Pool{{
		PoolID: "primary", ProtocolVersion: 2, Strategy: "least-loaded", Mode: "standalone",
		Documents: []yandex.PoolDocument{{ID: "doc-a", URL: "https://example.invalid/yandex-doc"}},
		Clients:   []Client{{ID: "device-a", ClientKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
	}}}
}

func TestApplyFailureRetainsPreviousGeneration(t *testing.T) {
	starter := &fakeStarter{}
	manager, err := NewManager(t.TempDir(), starter)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.Apply(context.Background(), validConfig(1)); err != nil {
		t.Fatal(err)
	}
	old := starter.all()[0]
	starter.mu.Lock()
	starter.failNext = true
	starter.mu.Unlock()
	if err := manager.Apply(context.Background(), validConfig(2)); err == nil {
		t.Fatal("accepted failed process start")
	}
	if manager.Version() != 1 || old.isClosed() {
		t.Fatalf("failed apply replaced old generation: version=%d closed=%v", manager.Version(), old.isClosed())
	}
	bad := validConfig(3)
	bad.Pools[0].Clients[0].ClientKey = "not-hex" + "00000000000000000000000000000000000000000000000000000000"
	if err := manager.Apply(context.Background(), bad); err == nil {
		t.Fatal("accepted invalid client key")
	}
	if manager.Version() != 1 || old.isClosed() {
		t.Fatal("invalid config disrupted the old generation")
	}
	if err := manager.Apply(context.Background(), validConfig(4)); err != nil {
		t.Fatal(err)
	}
	if !old.isClosed() || manager.Version() != 4 {
		t.Fatalf("successful generation swap did not retire old child: closed=%v version=%d", old.isClosed(), manager.Version())
	}
}

func TestManagerRestoresLastGenerationAfterRestart(t *testing.T) {
	stateDir := t.TempDir()
	firstStarter := &fakeStarter{}
	manager, err := NewManager(stateDir, firstStarter)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Apply(context.Background(), validConfig(7)); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(stateDir, "version-7", "manifest.json")
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("persistent config manifest missing: %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	secondStarter := &fakeStarter{}
	restarted, err := NewManager(stateDir, secondStarter)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.Version() != 7 || len(secondStarter.all()) != 1 {
		t.Fatalf("last generation not restored: version=%d processes=%d", restarted.Version(), len(secondStarter.all()))
	}
}

func TestApplyCancellationRetainsPreviousGeneration(t *testing.T) {
	starter := &fakeStarter{}
	manager, err := NewManager(t.TempDir(), starter)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.Apply(context.Background(), validConfig(1)); err != nil {
		t.Fatal(err)
	}
	old := starter.all()[0]
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.Apply(ctx, validConfig(2)); err == nil {
		t.Fatal("accepted cancelled apply")
	}
	if manager.Version() != 1 || old.isClosed() {
		t.Fatal("cancelled apply disrupted old generation")
	}
}

func TestAgentAcknowledgesRestoredVersionAsHeartbeat(t *testing.T) {
	starter := &fakeStarter{}
	manager, err := NewManager(t.TempDir(), starter)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := manager.Apply(context.Background(), DesiredConfig{Version: 4}); err != nil {
		t.Fatal(err)
	}
	var gotAck bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer node-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/nodes/node-a/config":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(DesiredConfig{Version: 4})
		case "POST /api/v1/nodes/node-a/ack":
			var body struct {
				Version int64  `json:"version"`
				Error   string `json:"error"`
			}
			if json.NewDecoder(r.Body).Decode(&body) != nil || body.Version != 4 || body.Error != "" {
				http.Error(w, "invalid ack", http.StatusBadRequest)
				return
			}
			gotAck = true
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	agent := &Agent{BaseURL: server.URL, NodeID: "node-a", Token: "node-secret", Manager: manager}
	if err := agent.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !gotAck {
		t.Fatal("restored config did not heartbeat-acknowledge its version")
	}
}

func TestManagerAppliesTransportForwardRoute(t *testing.T) {
	starter := &fakeStarter{}
	manager, err := NewManager(t.TempDir(), starter)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	cfg := validConfig(1)
	cfg.Pools[0].Mode = "transport"
	cfg.Pools[0].Forward = &yandex.PoolForwardConfig{VirtualEndpoint: "10.255.0.1:19000", Target: "remnanode:19000", Unmatched: "deny"}
	if err := manager.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := yandex.LoadPoolConfig(filepath.Join(manager.activeDir, "primary.json"), "exit")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Forward == nil || loaded.Forward.Routes[0].VirtualEndpoint != "10.255.0.1:19000" || loaded.Forward.Routes[0].Target != "remnanode:19000" {
		t.Fatalf("Happ/Xray forwarding route was lost: %#v", loaded.Forward)
	}
}
