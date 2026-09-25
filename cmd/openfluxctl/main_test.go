package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestRunUpdateUsesControlAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/pools/pool-1" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Fatalf("Authorization header = %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["name"] != "updated" || body["enabled"] != true {
			t.Fatalf("request body = %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"pool-1","name":"updated"}`)
	}))
	defer server.Close()

	captureStdout(t, func() {
		if err := run([]string{"--server", server.URL, "--token", "test-token", "pools", "update", "pool-1", `{"name":"updated","enabled":true}`}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPrintTable(t *testing.T) {
	output := captureStdout(t, func() {
		if !printTable(map[string]any{"users": []any{map[string]any{"id": "u1", "username": "alice", "enabled": true}}}) {
			t.Fatal("expected user list to render as a table")
		}
	})
	if !strings.Contains(output, "USERNAME") || !strings.Contains(output, "alice") {
		t.Fatalf("table output = %q", output)
	}
}

func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	defer func() {
		os.Stdout = old
		_ = writer.Close()
	}()
	f()
	_ = writer.Close()
	os.Stdout = old
	data, err := io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
