package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"openflux/internal/nodeagent"
	"openflux/transport/yandex"
)

type process struct {
	cmd  *exec.Cmd
	done chan error
	once sync.Once
	err  error
}

func (p *process) Close() error {
	p.once.Do(func() {
		if p.cmd == nil || p.cmd.Process == nil {
			return
		}
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case p.err = <-p.done:
		case <-time.After(5 * time.Second):
			_ = p.cmd.Process.Kill()
			p.err = <-p.done
		}
	})
	return p.err
}

type processStarter struct{ binary, mode, codec string }

func (s processStarter) Start(configPath string) (nodeagent.Child, error) {
	args := []string{"--role=exit", "--transport=yandex", "--pool-config=" + configPath, "--mode=" + s.mode, "--codec=" + s.codec}
	loaded, err := yandex.LoadPoolConfig(configPath, "exit")
	if err != nil {
		return nil, errors.New("invalid OpenFlux exit config")
	}
	cmd := exec.Command(s.binary, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &process{cmd: cmd, done: make(chan error, 1)}
	ready := make(chan struct{}, 1)
	redact := func(line string) string {
		for _, doc := range loaded.Docs {
			if doc.URL != "" {
				line = strings.ReplaceAll(line, doc.URL, "[REDACTED_DOCUMENT_URL]")
			}
		}
		return line
	}
	consume := func(reader io.Reader) {
		scanner := bufio.NewScanner(reader)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := redact(scanner.Text())
			_, _ = fmt.Fprintln(os.Stderr, line)
			if strings.Contains(line, "Running as multi-user Yandex Docs EXIT") {
				select {
				case ready <- struct{}{}:
				default:
				}
			}
		}
	}
	go consume(stdout)
	go consume(stderr)
	go func() { p.done <- cmd.Wait() }()
	select {
	case <-ready:
		return p, nil
	case err := <-p.done:
		return nil, fmt.Errorf("OpenFlux exited before readiness (exit=%v)", err)
	case <-time.After(15 * time.Second):
		_ = p.Close()
		return nil, errors.New("OpenFlux did not report ready within 15 seconds")
	}
}
func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}
func run() error {
	controlURL := flag.String("control-url", env("OPENFLUX_CONTROL_URL", ""), "Control base URL")
	nodeID := flag.String("node-id", env("OPENFLUX_NODE_ID", ""), "Node ID from Control")
	token := flag.String("token", os.Getenv("OPENFLUX_NODE_TOKEN"), "Node bearer token")
	stateDir := flag.String("state-dir", env("OPENFLUX_NODE_STATE_DIR", "./node-state"), "Private config directory")
	binary := flag.String("openflux-bin", env("OPENFLUX_BINARY", "./openflux"), "OpenFlux binary path")
	mode := flag.String("mode", env("OPENFLUX_EXIT_MODE", "l4"), "Exit mode l4|l3")
	codec := flag.String("codec", env("OPENFLUX_CODEC", "batched"), "Transport codec")
	poll := flag.Duration("poll", 15*time.Second, "Config poll interval")
	healthAddr := flag.String("health-addr", env("OPENFLUX_NODE_HEALTH_ADDR", "127.0.0.1:8790"), "local health endpoint address")
	flag.Parse()
	if *token == "" {
		return errors.New("set OPENFLUX_NODE_TOKEN or --token")
	}
	if *mode != "l3" && *mode != "l4" {
		return fmt.Errorf("invalid exit mode %q", *mode)
	}
	absState, err := filepath.Abs(*stateDir)
	if err != nil {
		return err
	}
	manager, err := nodeagent.NewManager(absState, processStarter{binary: *binary, mode: *mode, codec: *codec})
	if err != nil {
		return err
	}
	defer manager.Close()
	agent := &nodeagent.Agent{BaseURL: strings.TrimRight(*controlURL, "/"), NodeID: *nodeID, Token: *token}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("OpenFlux node agent %s polling Control", *nodeID)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","applied_version":%d}`, manager.Version())
	})
	health := &http.Server{Addr: *healthAddr, Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	healthErr := make(chan error, 1)
	go func() { healthErr <- health.ListenAndServe() }()
	agentErr := make(chan error, 1)
	go func() { agentErr <- agent.Run(ctx, *poll) }()
	select {
	case err := <-agentErr:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = health.Shutdown(shutdownCtx)
		return err
	case err := <-healthErr:
		if !errors.Is(err, http.ErrServerClosed) {
			stop()
			return fmt.Errorf("health endpoint failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = health.Shutdown(shutdownCtx)
		return ctx.Err()
	}
}
func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
