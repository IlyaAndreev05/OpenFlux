package control

import (
	"context"
	"os"
	"testing"
)

// Set OPENFLUX_TEST_POSTGRES_DSN to run the same schema and core CRUD checks
// against a disposable PostgreSQL database.
func TestPostgresMigrationsAndControlCRUD(t *testing.T) {
	dsn := os.Getenv("OPENFLUX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set OPENFLUX_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 7)
	}
	store, err := OpenStore("postgres", dsn, key)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var migration int
	if err := store.db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&migration); err != nil || migration < 4 {
		t.Fatalf("PostgreSQL migration version=%d err=%v", migration, err)
	}
	api, err := NewAPI(store, "postgres-test-secret", "https://openflux.example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	user := request(t, api, "POST", "/api/v1/users", "postgres-test-secret", map[string]string{"username": "postgres-test"})
	if user.Code != 201 {
		t.Fatalf("PostgreSQL user create: %d %s", user.Code, user.Body.String())
	}
	userID := decodeMap(t, user)["id"].(string)
	doc := request(t, api, "POST", "/api/v1/documents", "postgres-test-secret", map[string]string{"name": "doc", "url": "https://example.invalid/doc"})
	if doc.Code != 201 {
		t.Fatalf("PostgreSQL document create: %d %s", doc.Code, doc.Body.String())
	}
	docID := decodeMap(t, doc)["id"].(string)
	pool := request(t, api, "POST", "/api/v1/pools", "postgres-test-secret", map[string]any{"name": "transport", "strategy": "sticky", "mode": "transport", "tcp_endpoint": "10.255.0.1:19000", "forward_target": "remnanode:19000", "document_ids": []string{docID}})
	if pool.Code != 201 {
		t.Fatalf("PostgreSQL transport pool create: %d %s", pool.Code, pool.Body.String())
	}
	sub := request(t, api, "POST", "/api/v1/users/"+userID+"/subscription", "postgres-test-secret", map[string]string{})
	if sub.Code != 201 {
		t.Fatalf("PostgreSQL subscription create: %d %s", sub.Code, sub.Body.String())
	}
	if err := store.db.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}
