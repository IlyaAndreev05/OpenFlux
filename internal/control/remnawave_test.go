package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestRemnawaveSyncIsIdempotentAndRevokesOutOfSquadUsers(t *testing.T) {
	store, api, _ := newControlTestAPI(t)
	localReq := request(t, api, "POST", "/api/v1/users", "admin-test-secret", map[string]string{"username": "same-name"})
	if localReq.Code != 201 {
		t.Fatal(localReq.Body.String())
	}
	var versionBefore, versionAfter int64
	if err := store.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	var status atomic.Int32
	status.Store(200)
	var payload atomic.Value
	payload.Store(`{"response":{"users":[{"uuid":"u-1","username":"same-name","status":"ACTIVE","internalSquads":[{"uuid":"sq-a"}]},{"uuid":"u-2","username":"expired","status":"DISABLED","internalSquads":[{"uuid":"sq-a"}]},{"uuid":"u-3","username":"outside","status":"ACTIVE","internalSquads":[{"uuid":"sq-b"}]}]}}`)
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/users" {
			http.NotFound(w, r)
			return
		}
		if status.Load() != 200 {
			http.Error(w, "down", int(status.Load()))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload.Load().(string)))
	}))
	defer panel.Close()
	cfg := remnaConfig{BaseURL: panel.URL, APIVersion: "v2", SelectedSquads: []string{"sq-a"}, Token: "panel-secret"}
	count, err := api.syncRemnawave(context.Background(), cfg)
	if err != nil || count != 2 {
		t.Fatalf("first sync count=%d err=%v", count, err)
	}
	if err := store.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&versionAfter); err != nil || versionAfter != versionBefore+1 {
		t.Fatalf("first sync config version=%d (before %d), err=%v", versionAfter, versionBefore, err)
	}
	versionBefore = versionAfter
	count, err = api.syncRemnawave(context.Background(), cfg)
	if err != nil || count != 2 {
		t.Fatalf("repeat sync count=%d err=%v", count, err)
	}
	if err := store.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&versionAfter); err != nil || versionAfter != versionBefore {
		t.Fatalf("unchanged repeat sync needlessly bumped config version to %d (was %d), err=%v", versionAfter, versionBefore, err)
	}
	var total int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM users WHERE source='remnawave'`).Scan(&total); err != nil || total != 2 {
		t.Fatalf("remnawave users=%d err=%v", total, err)
	}
	var sameCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username='same-name'`).Scan(&sameCount); err != nil || sameCount != 2 {
		t.Fatalf("same-name local+Remnawave rows=%d err=%v", sameCount, err)
	}
	if _, err := store.db.Exec(`INSERT INTO subscriptions(id,user_id,token_hash,created_at) SELECT 'sub-u1',id,'hash-u1',? FROM users WHERE source='remnawave' AND external_id='u-1'`, nowText()); err != nil {
		t.Fatal(err)
	}
	status.Store(503)
	if _, err := api.syncRemnawave(context.Background(), cfg); err == nil {
		t.Fatal("accepted panel API outage")
	}
	var enabled bool
	if err := store.db.QueryRow(`SELECT enabled FROM users WHERE source='remnawave' AND external_id='u-1'`).Scan(&enabled); err != nil || !enabled {
		t.Fatalf("API outage revoked an active user: enabled=%v err=%v", enabled, err)
	}
	payload.Store(`{"users":[{"uuid":"u-1","username":"same-name","status":"ACTIVE","internalSquads":[{"uuid":"sq-b"}]}]}`)
	status.Store(200)
	count, err = api.syncRemnawave(context.Background(), cfg)
	if err != nil || count != 0 {
		t.Fatalf("out-of-squad sync count=%d err=%v", count, err)
	}
	var revoked string
	if err := store.db.QueryRow(`SELECT enabled FROM users WHERE source='remnawave' AND external_id='u-1'`).Scan(&enabled); err != nil || enabled {
		t.Fatalf("out-of-squad user enabled=%v err=%v", enabled, err)
	}
	if err := store.db.QueryRow(`SELECT COALESCE(revoked_at,'') FROM subscriptions WHERE id='sub-u1'`).Scan(&revoked); err != nil || revoked == "" {
		t.Fatalf("subscription not revoked: %q err=%v", revoked, err)
	}
	// Direct edits to imported users are rejected by the public API.
	var id string
	if err := store.db.QueryRow(`SELECT id FROM users WHERE source='remnawave' AND external_id='u-1'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if w := request(t, api, "PATCH", "/api/v1/users/"+id, "admin-test-secret", map[string]bool{"enabled": true}); w.Code != 403 {
		t.Fatalf("Remnawave-owned user patch status=%d", w.Code)
	}
}

func TestRemnawaveV3CursorPagination(t *testing.T) {
	_, api, _ := newControlTestAPI(t)
	panel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var body string
		switch r.URL.Path {
		case "/api/users/stream":
			if r.URL.Query().Get("cursor") == "" {
				body = `{"users":[{"id":41,"username":"one","status":"ACTIVE","internalSquads":[{"uuid":"sq"}]}],"nextCursor":"page-two"}`
			} else {
				body = `{"response":{"users":[{"id":42,"username":"two","status":"ACTIVE","internalSquads":[{"uuid":"sq"}]}],"nextCursor":""}}`
			}
		default:
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer panel.Close()
	users, err := api.fetchRemnawaveUsers(context.Background(), remnaConfig{BaseURL: panel.URL, APIVersion: "v3", Token: "api-token"})
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 2 || remnaExternalID(users[0]) != "41" || remnaExternalID(users[1]) != "42" {
		t.Fatalf("v3 cursor users=%#v", users)
	}
}

func TestRemnawaveWebhookHMAC(t *testing.T) {
	body := []byte(`{"event":"user.updated"}`)
	const signature = "c27dd3f9530b8b3c09ea55f6904d78fcc837c9565170909318d84f5091fac3ab"
	if !VerifyRemnawaveWebhook("secret", body, signature) {
		t.Fatal("rejected the known valid HMAC-SHA256 vector")
	}
	if VerifyRemnawaveWebhook("secret", body, strings.TrimSuffix(signature, "b")+"c") {
		t.Fatal("accepted an invalid signature")
	}
}
