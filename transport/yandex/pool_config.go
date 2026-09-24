package yandex

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	MaxPoolDocuments     = 50
	MaxPoolClients       = 1000
	MaxPoolForwardRoutes = 256
)

type PoolDocument struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type PoolClientKey struct {
	ID      string `json:"id"`
	KeyFile string `json:"key_file"`
}

// PoolForwardRoute maps a virtual IPv4 TCP endpoint to a TCP destination.
type PoolForwardRoute struct {
	VirtualEndpoint string `json:"virtual_endpoint"`
	Target          string `json:"target"`
}

// PoolForwardConfig optionally applies exact destination routes on an L4
// pool exit. The singular fields remain supported for existing configs.
type PoolForwardConfig struct {
	VirtualEndpoint string             `json:"virtual_endpoint,omitempty"`
	Target          string             `json:"target,omitempty"`
	Routes          []PoolForwardRoute `json:"routes,omitempty"`
	Unmatched       string             `json:"unmatched,omitempty"`
}

// PoolConfig is role-specific after loading: clients contains secrets only on
// an exit node, while clientID/clientKey are populated on a client.
type PoolConfig struct {
	PoolID    string
	Strategy  string
	Docs      []PoolDocument
	Clients   map[string][32]byte
	ClientID  string
	ClientKey [32]byte
	TCPTarget string
	Forward   *PoolForwardConfig
}

type poolConfigFile struct {
	PoolID    string             `json:"pool_id"`
	Strategy  string             `json:"strategy"`
	Documents []PoolDocument     `json:"documents"`
	ClientID  string             `json:"client_id,omitempty"`
	KeyFile   string             `json:"key_file,omitempty"`
	TCPTarget string             `json:"tcp_target,omitempty"`
	Clients   []PoolClientKey    `json:"clients,omitempty"`
	Forward   *PoolForwardConfig `json:"forward,omitempty"`
}

func LoadPoolConfig(path, role string) (PoolConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return PoolConfig{}, fmt.Errorf("read pool config: %w", err)
	}
	var raw poolConfigFile
	if err := json.Unmarshal(data, &raw); err != nil {
		return PoolConfig{}, fmt.Errorf("parse pool config: %w", err)
	}
	cfg := PoolConfig{
		PoolID:   strings.TrimSpace(raw.PoolID),
		Strategy: strings.TrimSpace(raw.Strategy),
		Docs:     raw.Documents,
	}
	if cfg.PoolID == "" || len(cfg.PoolID) > 64 || strings.ContainsAny(cfg.PoolID, "\x00\r\n") {
		return PoolConfig{}, errors.New("pool_id must contain 1 to 64 characters")
	}
	if len(cfg.Docs) == 0 || len(cfg.Docs) > MaxPoolDocuments {
		return PoolConfig{}, fmt.Errorf("documents must contain 1 to %d entries", MaxPoolDocuments)
	}
	seenDocs := make(map[string]bool, len(cfg.Docs))
	for i := range cfg.Docs {
		d := &cfg.Docs[i]
		d.ID = strings.TrimSpace(d.ID)
		if d.ID == "" || len(d.ID) > 64 || strings.ContainsAny(d.ID, "\x00\r\n") {
			return PoolConfig{}, fmt.Errorf("documents[%d].id must contain 1 to 64 printable characters", i)
		}
		if seenDocs[d.ID] {
			return PoolConfig{}, fmt.Errorf("duplicate document id %q", d.ID)
		}
		seenDocs[d.ID] = true
		u, err := url.ParseRequestURI(d.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return PoolConfig{}, fmt.Errorf("documents[%d].url must be an http or https URL", i)
		}
	}
	baseDir, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return PoolConfig{}, fmt.Errorf("resolve config directory: %w", err)
	}
	switch role {
	case "client":
		if raw.Forward != nil {
			return PoolConfig{}, errors.New("client pool config must not contain forward")
		}
		raw.ClientID = strings.TrimSpace(raw.ClientID)
		if raw.ClientID == "" || len(raw.ClientID) > 64 || strings.ContainsAny(raw.ClientID, "\x00\r\n") {
			return PoolConfig{}, errors.New("client_id must contain 1 to 64 characters")
		}
		if raw.KeyFile == "" {
			return PoolConfig{}, errors.New("key_file is required for client role")
		}
		cfg.ClientID = raw.ClientID
		if target := strings.TrimSpace(raw.TCPTarget); target != "" {
			if err := validatePoolForwardTarget(target); err != nil {
				return PoolConfig{}, fmt.Errorf("tcp_target: %w", err)
			}
			cfg.TCPTarget = target
		}
		cfg.ClientKey, err = readPoolKey(filepath.Join(baseDir, raw.KeyFile))
		if err != nil {
			return PoolConfig{}, fmt.Errorf("read client key: %w", err)
		}
		if raw.Strategy != "" || len(raw.Clients) != 0 {
			return PoolConfig{}, errors.New("client pool config must not contain strategy or clients")
		}
	case "exit":
		if strings.TrimSpace(raw.TCPTarget) != "" {
			return PoolConfig{}, errors.New("exit pool config must not contain tcp_target")
		}
		if raw.Forward != nil {
			routes, err := raw.Forward.normalizedRoutes()
			if err != nil {
				return PoolConfig{}, fmt.Errorf("forward: %w", err)
			}
			policy := strings.TrimSpace(raw.Forward.Unmatched)
			if policy == "" {
				policy = "deny"
			}
			if policy != "deny" && policy != "direct" {
				return PoolConfig{}, fmt.Errorf("forward.unmatched must be deny or direct")
			}
			if err := validatePoolForwardRoutes(routes); err != nil {
				return PoolConfig{}, fmt.Errorf("forward: %w", err)
			}
			cfg.Forward = &PoolForwardConfig{
				VirtualEndpoint: strings.TrimSpace(raw.Forward.VirtualEndpoint),
				Target:          strings.TrimSpace(raw.Forward.Target),
				Routes:          routes,
				Unmatched:       policy,
			}
		}
		if len(raw.Clients) == 0 || len(raw.Clients) > MaxPoolClients {
			return PoolConfig{}, fmt.Errorf("clients must contain 1 to %d entries", MaxPoolClients)
		}
		if cfg.Strategy == "" {
			cfg.Strategy = "least-loaded"
		}
		switch cfg.Strategy {
		case "round-robin", "least-loaded", "sticky":
		default:
			return PoolConfig{}, fmt.Errorf("unknown strategy %q (want round-robin|least-loaded|sticky)", cfg.Strategy)
		}
		cfg.Clients = make(map[string][32]byte, len(raw.Clients))
		for i, c := range raw.Clients {
			c.ID = strings.TrimSpace(c.ID)
			if c.ID == "" || len(c.ID) > 64 || strings.ContainsAny(c.ID, "\x00\r\n") {
				return PoolConfig{}, fmt.Errorf("clients[%d].id must contain 1 to 64 printable characters", i)
			}
			if _, ok := cfg.Clients[c.ID]; ok {
				return PoolConfig{}, fmt.Errorf("duplicate client id %q", c.ID)
			}
			if c.KeyFile == "" {
				return PoolConfig{}, fmt.Errorf("clients[%d].key_file is required", i)
			}
			key, err := readPoolKey(filepath.Join(baseDir, c.KeyFile))
			if err != nil {
				return PoolConfig{}, fmt.Errorf("read key for client %q: %w", c.ID, err)
			}
			cfg.Clients[c.ID] = key
		}
		if raw.ClientID != "" || raw.KeyFile != "" {
			return PoolConfig{}, errors.New("exit pool config must use clients entries, not client_id/key_file")
		}
	default:
		return PoolConfig{}, fmt.Errorf("unknown pool role %q", role)
	}
	return cfg, nil
}

func (f PoolForwardConfig) normalizedRoutes() ([]PoolForwardRoute, error) {
	routes := append([]PoolForwardRoute(nil), f.Routes...)
	if len(routes) != 0 {
		if strings.TrimSpace(f.VirtualEndpoint) != "" || strings.TrimSpace(f.Target) != "" {
			return nil, errors.New("use either routes or the legacy virtual_endpoint/target fields")
		}
		return routes, nil
	}
	virtual, target := strings.TrimSpace(f.VirtualEndpoint), strings.TrimSpace(f.Target)
	if virtual == "" || target == "" {
		return nil, errors.New("configure routes or both virtual_endpoint and target")
	}
	return []PoolForwardRoute{{VirtualEndpoint: virtual, Target: target}}, nil
}

func validatePoolForwardRoutes(routes []PoolForwardRoute) error {
	if len(routes) == 0 || len(routes) > MaxPoolForwardRoutes {
		return fmt.Errorf("routes must contain 1 to %d entries", MaxPoolForwardRoutes)
	}
	seen := make(map[netip.AddrPort]bool, len(routes))
	for i, route := range routes {
		virtual, err := netip.ParseAddrPort(strings.TrimSpace(route.VirtualEndpoint))
		if err != nil || !virtual.Addr().Is4() || virtual.Port() == 0 {
			return fmt.Errorf("routes[%d].virtual_endpoint must be an IPv4 address and port", i)
		}
		if seen[virtual] {
			return fmt.Errorf("routes[%d].virtual_endpoint duplicates %q", i, virtual)
		}
		seen[virtual] = true
		if err := validatePoolForwardTarget(route.Target); err != nil {
			return fmt.Errorf("routes[%d].target: %w", i, err)
		}
	}
	return nil
}

func validatePoolForwardTarget(value string) error {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil || host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "\x00\r\n/?#") {
		return errors.New("must be a host:port TCP destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	return nil
}

func readPoolKey(path string) ([32]byte, error) {
	var key [32]byte
	data, err := os.ReadFile(path)
	if err != nil {
		return key, err
	}
	s := strings.TrimSpace(string(data))
	if decoded, err := hex.DecodeString(s); err == nil && len(decoded) == len(key) {
		copy(key[:], decoded)
		return key, nil
	}
	return key, errors.New("key file must contain a 32-byte key as 64 hex characters")
}
