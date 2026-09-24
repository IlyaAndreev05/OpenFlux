package yandex

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"openflux/transport"
	"openflux/tunnel"
)

// TestLivePoolFailoverPreservesTCP is an opt-in integration test against real
// shared Yandex Docs. It disconnects one exit-side transport in-process and
// verifies that an already-open TCP stream survives reassignment.
func TestLivePoolFailoverPreservesTCP(t *testing.T) {
	if os.Getenv("OPENFLUX_POOL_LIVE") != "1" {
		t.Skip("set OPENFLUX_POOL_LIVE=1 to run the real Yandex Docs failover test")
	}
	urls := []string{
		envOr("OPENFLUX_POOL_DOC1", ""),
		envOr("OPENFLUX_POOL_DOC2", ""),
	}
	if urls[0] == "" || urls[1] == "" {
		t.Fatal("set OPENFLUX_POOL_DOC1 and OPENFLUX_POOL_DOC2 explicitly for live tests")
	}
	bindIP := envOr("OPENFLUX_POOL_TEST_BIND_IP", "172.17.0.1")
	listener, err := net.Listen("tcp", net.JoinHostPort(bindIP, "0"))
	if err != nil {
		t.Fatalf("listen on test bind IP %s: %v", bindIP, err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	var key [32]byte
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	docs := []PoolDocument{{ID: "doc-1", URL: urls[0]}, {ID: "doc-2", URL: urls[1]}}
	poolID := fmt.Sprintf("live-failover-%d", time.Now().UnixNano())
	exitCfg := PoolConfig{PoolID: poolID, Strategy: "least-loaded", Docs: docs, Clients: map[string][32]byte{"live-client": key}}
	clientCfg := PoolConfig{PoolID: poolID, Docs: docs, ClientID: "live-client", ClientKey: key}
	tc := transport.DefaultConfig()
	exitNode, err := tunnel.NewPoolExitNode(tunnel.ExitModeL4)
	if err != nil {
		t.Fatal(err)
	}
	if err := exitNode.Start(); err != nil {
		t.Fatal(err)
	}
	server := NewYandexDocsPoolServer(exitCfg, tc, func(session *PoolSession) {
		batched := transport.NewBatchedTransportWithQueue(session, 32)
		if err := batched.Start(); err != nil {
			t.Errorf("start exit client batching: %v", err)
			return
		}
		if err := exitNode.AddClient(session.ClientID(), batched); err != nil {
			t.Errorf("attach exit client: %v", err)
			_ = batched.Stop()
		}
	}, exitNode.RemoveClient)
	if err := server.Start(); err != nil {
		_ = exitNode.Stop()
		t.Fatal(err)
	}
	defer func() { _ = server.Stop(); _ = exitNode.Stop() }()
	waitFor(t, 90*time.Second, func() bool {
		server.mu.RLock()
		defer server.mu.RUnlock()
		return len(server.docs) == 2 && server.docs[docs[0].ID].IsConnected() && server.docs[docs[1].ID].IsConnected()
	}, "exit transports connected to both documents")

	client, err := NewYandexDocsPoolClient(clientCfg, tc)
	if err != nil {
		t.Fatal(err)
	}
	batchedClient := transport.NewBatchedTransportWithQueue(client, 32)
	clientTunnel := tunnel.NewTCPTunnelMode(batchedClient, false, tunnel.ExitModeL4)
	defer clientTunnel.Close()
	if err := batchedClient.Start(); err != nil {
		t.Fatal(err)
	}
	defer batchedClient.Stop()
	waitFor(t, 90*time.Second, batchedClient.IsConnected, "pool client assigned")

	conn, err := clientTunnel.DialTCP(listener.Addr().String())
	if err != nil {
		t.Fatalf("open TCP stream through pool: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(75 * time.Second))
	reader := bufio.NewReader(conn)
	assertEcho := func(value string) {
		t.Helper()
		if _, err := io.WriteString(conn, value+"\n"); err != nil {
			t.Fatalf("write %q: %v", value, err)
		}
		got, err := reader.ReadString('\n')
		if err != nil || got != value+"\n" {
			t.Fatalf("echo after %q: got %q err=%v", value, got, err)
		}
	}
	assertEcho("before-failover")
	client.mu.RLock()
	failedDoc := client.activeID
	client.mu.RUnlock()
	if failedDoc == "" {
		t.Fatal("client had no active document")
	}
	server.mu.RLock()
	failedRaw := server.docs[failedDoc]
	server.mu.RUnlock()
	if failedRaw == nil {
		t.Fatalf("exit has no raw transport for active document %q", failedDoc)
	}
	if err := failedRaw.Stop(); err != nil {
		t.Fatalf("disconnect active document: %v", err)
	}
	waitFor(t, 75*time.Second, func() bool {
		client.mu.RLock()
		defer client.mu.RUnlock()
		return client.IsConnected() && client.activeID != "" && client.activeID != failedDoc
	}, "client failover to the second document")
	assertEcho("after-failover")
	client.mu.RLock()
	replacement := client.activeID
	client.mu.RUnlock()
	t.Logf("failover %s -> %s preserved the existing TCP stream", failedDoc, replacement)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
