package yandex

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"openflux/transport"
)

func TestPoolFrameEncodeDecode(t *testing.T) {
	in := poolFrame{
		Kind: poolData, Direction: 1, ClientID: "client-a", Epoch: 42,
		DocID: "doc-b", Payload: []byte{0, 1, 2, 255},
	}
	in.SessionID[3] = 99
	encoded, err := encodePoolFrame(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodePoolFrame(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip mismatch:\n got %#v\nwant %#v", got, in)
	}
	for _, malformed := range [][]byte{nil, encoded[:36], append(append([]byte(nil), encoded...), 1)} {
		if _, err := decodePoolFrame(malformed); err == nil {
			t.Fatalf("accepted malformed frame (%d bytes)", len(malformed))
		}
	}
}

func TestPoolCipherDirectionalEncryptionAndReplayProtection(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	client, err := newPoolCipher(key, "pool+docs", "alice", false)
	if err != nil {
		t.Fatal(err)
	}
	exit, err := newPoolCipher(key, "pool+docs", "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("client-specific tunnel packet")
	frame, err := client.seal(poolFrame{Kind: poolData, ClientID: "alice", DocID: "doc-1", Epoch: 7}, plain)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(frame.Payload, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	decoded, err := exit.open(frame)
	if err != nil || !reflect.DeepEqual(decoded, plain) {
		t.Fatalf("exit decrypt: data=%q err=%v", decoded, err)
	}
	if _, err := exit.open(frame); err == nil {
		t.Fatal("replayed ciphertext was accepted")
	}
	badExit, err := newPoolCipher(key, "another-pool", "alice", true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := badExit.open(frame); err == nil {
		t.Fatal("ciphertext decrypted in a different pool context")
	}
}

func TestPoolControlProof(t *testing.T) {
	var key [32]byte
	key[0] = 4
	f := poolFrame{Kind: poolAssign, Direction: 1, ClientID: "alice", DocID: "doc-1", Epoch: 2}
	f.Payload = poolProof(key, "test-pool", f)
	if !verifyPoolProof(key, "test-pool", f) {
		t.Fatal("valid proof did not verify")
	}
	f.DocID = "doc-2"
	if verifyPoolProof(key, "test-pool", f) {
		t.Fatal("proof verified after document id was modified")
	}
}

func TestChoosePoolDocumentStrategies(t *testing.T) {
	docs := []PoolDocument{{ID: "a"}, {ID: "b"}, {ID: "c"}}
	var rr uint64
	for i, want := range []string{"a", "b", "c", "a"} {
		if got := choosePoolDocument("round-robin", "ignored", docs, nil, &rr); got != want {
			t.Fatalf("round-robin[%d]=%q want %q", i, got, want)
		}
	}
	if got := choosePoolDocument("least-loaded", "alice", docs, map[string]int{"a": 2, "b": 0, "c": 1}, &rr); got != "b" {
		t.Fatalf("least-loaded selected %q", got)
	}
	sticky := choosePoolDocument("sticky", "alice", docs, nil, &rr)
	if again := choosePoolDocument("sticky", "alice", docs, nil, &rr); again != sticky {
		t.Fatalf("sticky moved client from %q to %q", sticky, again)
	}
	if got := choosePoolDocument("least-loaded", "alice", docs[:2], map[string]int{"a": 8}, &rr); got != "b" {
		t.Fatalf("least-loaded did not exclude unavailable doc: %q", got)
	}
}

func TestPoolStrategiesAt1000ClientsAnd50Documents(t *testing.T) {
	docs := make([]PoolDocument, MaxPoolDocuments)
	available := make(map[string]*YandexDocsTransport, len(docs))
	for i := range docs {
		docs[i].ID = fmt.Sprintf("doc-%02d", i)
		raw := NewYandexDocsTransport("", transport.DefaultConfig())
		raw.SetConnected(true)
		available[docs[i].ID] = raw
	}
	for _, strategy := range []string{"round-robin", "least-loaded", "sticky"} {
		server := &YandexDocsPoolServer{
			cfg:  PoolConfig{Strategy: strategy, Docs: docs},
			docs: available, sessions: make(map[string]*PoolSession, MaxPoolClients),
		}
		for i := 0; i < MaxPoolClients; i++ {
			id := fmt.Sprintf("client-%04d", i)
			docID := server.chooseDocLocked(id, "")
			if docID == "" {
				t.Fatalf("%s assigned an empty doc at client %d", strategy, i)
			}
			server.sessions[id] = &PoolSession{clientID: id, docID: docID, active: true}
		}
		if len(server.sessions) != MaxPoolClients {
			t.Fatalf("%s retained %d of %d sessions", strategy, len(server.sessions), MaxPoolClients)
		}
		loads := make(map[string]int, len(docs))
		for _, session := range server.sessions {
			loads[session.docID]++
		}
		total, min, max := 0, MaxPoolClients, 0
		for _, n := range loads {
			total += n
			if n < min {
				min = n
			}
			if n > max {
				max = n
			}
		}
		if total != MaxPoolClients {
			t.Fatalf("%s assigned %d of %d clients", strategy, total, MaxPoolClients)
		}
		if strategy != "sticky" && max-min > 1 {
			t.Fatalf("%s distribution skewed: min=%d max=%d", strategy, min, max)
		}
	}
}

func TestLoadPoolConfigPerRole(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "alice.key")
	keyHex := make([]byte, 32)
	for i := range keyHex {
		keyHex[i] = byte(i)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(keyHex)), 0600); err != nil {
		t.Fatal(err)
	}
	writeConfig := func(name string, value any) string {
		t.Helper()
		p := filepath.Join(dir, name)
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	docs := []PoolDocument{{ID: "one", URL: "https://disk.yandex.ru/i/abc"}}
	clientPath := writeConfig("client.json", map[string]any{
		"pool_id": "test", "documents": docs, "client_id": "alice", "key_file": "alice.key",
	})
	client, err := LoadPoolConfig(clientPath, "client")
	if err != nil {
		t.Fatal(err)
	}
	if client.ClientID != "alice" || client.ClientKey[31] != 31 {
		t.Fatalf("bad client config: %#v", client)
	}
	clientTCPPath := writeConfig("client-tcp.json", map[string]any{
		"pool_id": "test", "documents": docs, "client_id": "alice", "key_file": "alice.key",
		"tcp_target": "198.18.10.20:443",
	})
	clientTCP, err := LoadPoolConfig(clientTCPPath, "client")
	if err != nil {
		t.Fatal(err)
	}
	if clientTCP.TCPTarget != "198.18.10.20:443" {
		t.Fatalf("bad client tcp target: %q", clientTCP.TCPTarget)
	}
	invalidClientTCPPath := writeConfig("client-tcp-invalid.json", map[string]any{
		"pool_id": "test", "documents": docs, "client_id": "alice", "key_file": "alice.key",
		"tcp_target": "xray.internal",
	})
	if _, err := LoadPoolConfig(invalidClientTCPPath, "client"); err == nil {
		t.Fatal("accepted client tcp_target without a port")
	}
	exitPath := writeConfig("exit.json", map[string]any{
		"pool_id": "test", "strategy": "round-robin", "documents": docs,
		"clients": []map[string]string{{"id": "alice", "key_file": "alice.key"}},
		"forward": map[string]string{"virtual_endpoint": "198.18.0.1:18443", "target": "127.0.0.1:18443"},
	})
	exit, err := LoadPoolConfig(exitPath, "exit")
	if err != nil {
		t.Fatal(err)
	}
	if exit.Strategy != "round-robin" || exit.Clients["alice"][31] != 31 {
		t.Fatalf("bad exit config: %#v", exit)
	}
	if exit.Forward == nil || exit.Forward.VirtualEndpoint != "198.18.0.1:18443" || exit.Forward.Target != "127.0.0.1:18443" ||
		len(exit.Forward.Routes) != 1 || exit.Forward.Routes[0].Target != "127.0.0.1:18443" || exit.Forward.Unmatched != "deny" {
		t.Fatalf("bad forward route: %#v", exit.Forward)
	}
	multiRoute := writeConfig("multi-route.json", map[string]any{
		"pool_id": "test", "documents": docs,
		"clients": []map[string]string{{"id": "alice", "key_file": "alice.key"}},
		"forward": map[string]any{
			"routes": []map[string]string{
				{"virtual_endpoint": "198.18.0.1:18443", "target": "127.0.0.1:18443"},
				{"virtual_endpoint": "198.18.0.2:443", "target": "xray.example:443"},
			},
			"unmatched": "direct",
		},
	})
	multi, err := LoadPoolConfig(multiRoute, "exit")
	if err != nil {
		t.Fatal(err)
	}
	if multi.Forward == nil || len(multi.Forward.Routes) != 2 || multi.Forward.Unmatched != "direct" {
		t.Fatalf("bad multi-route config: %#v", multi.Forward)
	}
	duplicateRoute := writeConfig("duplicate-route.json", map[string]any{
		"pool_id": "test", "documents": docs,
		"clients": []map[string]string{{"id": "alice", "key_file": "alice.key"}},
		"forward": map[string]any{"routes": []map[string]string{
			{"virtual_endpoint": "198.18.0.1:18443", "target": "127.0.0.1:18443"},
			{"virtual_endpoint": "198.18.0.1:18443", "target": "xray.example:443"},
		}},
	})
	if _, err := LoadPoolConfig(duplicateRoute, "exit"); err == nil {
		t.Fatal("accepted duplicate forward endpoint")
	}
	ambiguousRoute := writeConfig("ambiguous-route.json", map[string]any{
		"pool_id": "test", "documents": docs,
		"clients": []map[string]string{{"id": "alice", "key_file": "alice.key"}},
		"forward": map[string]any{
			"virtual_endpoint": "198.18.0.1:18443", "target": "127.0.0.1:18443",
			"routes": []map[string]string{{"virtual_endpoint": "198.18.0.2:443", "target": "xray.example:443"}},
		},
	})
	if _, err := LoadPoolConfig(ambiguousRoute, "exit"); err == nil {
		t.Fatal("accepted mixed legacy and route-list fields")
	}
	invalidRoute := writeConfig("invalid-route.json", map[string]any{
		"pool_id": "test", "documents": docs,
		"clients": []map[string]string{{"id": "alice", "key_file": "alice.key"}},
		"forward": map[string]string{"virtual_endpoint": "198.18.0.1:18443", "target": "xray.example"},
	})
	if _, err := LoadPoolConfig(invalidRoute, "exit"); err == nil {
		t.Fatal("accepted forward target without a port")
	}
	invalidClientRoute := writeConfig("invalid-client-route.json", map[string]any{
		"pool_id": "test", "documents": docs, "client_id": "alice", "key_file": "alice.key",
		"forward": map[string]string{"virtual_endpoint": "198.18.0.1:18443", "target": "127.0.0.1:18443"},
	})
	if _, err := LoadPoolConfig(invalidClientRoute, "client"); err == nil {
		t.Fatal("accepted exit-only forward route on client config")
	}
	invalid := writeConfig("invalid.json", map[string]any{
		"pool_id": "test", "strategy": "random", "documents": docs,
		"clients": []map[string]string{{"id": "alice", "key_file": "alice.key"}},
	})
	if _, err := LoadPoolConfig(invalid, "exit"); err == nil {
		t.Fatal("accepted unknown strategy")
	}
}

func TestPoolConfigEnforcesClientAndDocumentLimits(t *testing.T) {
	dir := t.TempDir()
	writeConfig := func(value any) string {
		t.Helper()
		p := filepath.Join(dir, "limit.json")
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	clients := make([]map[string]string, MaxPoolClients+1)
	for i := range clients {
		clients[i] = map[string]string{"id": fmt.Sprintf("client-%04d", i), "key_file": "unused.key"}
	}
	oneDoc := []PoolDocument{{ID: "one", URL: "https://disk.yandex.ru/i/abc"}}
	path := writeConfig(map[string]any{"pool_id": "test", "documents": oneDoc, "clients": clients})
	if _, err := LoadPoolConfig(path, "exit"); err == nil {
		t.Fatal("accepted more than 1000 clients")
	}
	manyDocs := make([]PoolDocument, MaxPoolDocuments+1)
	for i := range manyDocs {
		manyDocs[i] = PoolDocument{ID: fmt.Sprintf("doc-%02d", i), URL: "https://disk.yandex.ru/i/abc"}
	}
	path = writeConfig(map[string]any{"pool_id": "test", "documents": manyDocs, "clients": clients[:1]})
	if _, err := LoadPoolConfig(path, "exit"); err == nil {
		t.Fatal("accepted more than 50 documents")
	}
}
