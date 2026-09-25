package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var safeNodeID = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

type Agent struct {
	BaseURL string
	NodeID  string
	Token   string
	HTTP    *http.Client
	Manager *Manager
}

func (a *Agent) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 20 * time.Second}
}

func (a *Agent) endpoint(suffix string) (string, error) {
	if a.BaseURL == "" || a.NodeID == "" || a.Token == "" || a.Manager == nil || !safeNodeID.MatchString(a.NodeID) {
		return "", errors.New("control URL, node ID, token, and manager are required")
	}
	base, err := url.Parse(strings.TrimSpace(a.BaseURL))
	if err != nil || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || (base.Scheme != "http" && base.Scheme != "https") {
		return "", errors.New("Control URL must be an http(s) URL without credentials or query parameters")
	}
	if base.Scheme != "https" {
		host := base.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("remote node connections to Control require HTTPS")
		}
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/api/v1/nodes/" + url.PathEscape(a.NodeID) + "/" + suffix
	base.RawPath = ""
	return base.String(), nil
}

func (a *Agent) Fetch(ctx context.Context) (DesiredConfig, error) {
	endpoint, err := a.endpoint("config")
	if err != nil {
		return DesiredConfig{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return DesiredConfig{}, errors.New("could not construct Control config request")
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	resp, err := a.client().Do(req)
	if err != nil {
		return DesiredConfig{}, errors.New("Control config request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return DesiredConfig{}, errors.New("could not read Control config response")
	}
	if resp.StatusCode != http.StatusOK {
		return DesiredConfig{}, fmt.Errorf("Control config request returned HTTP %d", resp.StatusCode)
	}
	var cfg DesiredConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return DesiredConfig{}, errors.New("Control returned invalid config JSON")
	}
	return cfg, nil
}

func (a *Agent) Ack(ctx context.Context, version int64, applyErr error) error {
	endpoint, err := a.endpoint("ack")
	if err != nil {
		return err
	}
	message := ""
	if applyErr != nil {
		message = applyErr.Error()
		if len(message) > 512 {
			message = message[:512]
		}
	}
	body, _ := json.Marshal(map[string]any{"version": version, "error": message})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("could not construct Control acknowledgement")
	}
	req.Header.Set("Authorization", "Bearer "+a.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return errors.New("Control acknowledgement request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("Control config acknowledgement returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (a *Agent) Once(ctx context.Context) error {
	cfg, err := a.Fetch(ctx)
	if err != nil {
		return err
	}
	if a.Manager.Version() == cfg.Version {
		return a.Ack(ctx, cfg.Version, nil)
	}
	err = a.Manager.Apply(ctx, cfg)
	ackErr := a.Ack(ctx, cfg.Version, err)
	if ackErr != nil {
		return fmt.Errorf("apply error %v; acknowledgement error: %w", err, ackErr)
	}
	return err
}
func (a *Agent) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	lastLog := time.Time{}
	var lastMessage string
	for {
		if err := a.Once(ctx); err != nil {
			message := err.Error()
			if message != lastMessage || time.Since(lastLog) >= time.Minute {
				log.Printf("node config sync failed: %s", message)
				lastMessage, lastLog = message, time.Now()
			}
		} else {
			lastMessage = ""
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
