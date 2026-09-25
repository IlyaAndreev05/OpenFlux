package control

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type remnaConfig struct {
	BaseURL        string
	APIVersion     string
	SelectedSquads []string
	Enabled        bool
	Token          string
	WebhookSecret  string
	LastSync       sql.NullString
	LastError      string
}

func (a *API) readRemnawaveConfig(ctx context.Context) (remnaConfig, error) {
	var cfg remnaConfig
	var squads string
	var tokenCipher, secretCipher []byte
	err := a.store.db.QueryRowContext(ctx, `SELECT base_url,api_version,selected_squads,enabled,token_cipher,webhook_secret_cipher,last_sync,last_error FROM remnawave_settings WHERE id=1`).Scan(&cfg.BaseURL, &cfg.APIVersion, &squads, &cfg.Enabled, &tokenCipher, &secretCipher, &cfg.LastSync, &cfg.LastError)
	if err != nil {
		return cfg, err
	}
	if err = json.Unmarshal([]byte(squads), &cfg.SelectedSquads); err != nil {
		return cfg, err
	}
	if b, e := a.store.decrypt(tokenCipher); e == nil {
		cfg.Token = string(b)
	} else {
		return cfg, e
	}
	if b, e := a.store.decrypt(secretCipher); e == nil {
		cfg.WebhookSecret = string(b)
	} else {
		return cfg, e
	}
	return cfg, nil
}

func (a *API) getRemnawaveSettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readRemnawaveConfig(r.Context())
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, 200, map[string]any{"enabled": false, "configured": false, "api_version": "v2", "selected_squads": []string{}})
		return
	}
	if err != nil {
		writeError(w, 500, "integration settings unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": cfg.Enabled, "configured": true, "base_url": cfg.BaseURL, "api_version": cfg.APIVersion, "selected_squads": cfg.SelectedSquads, "token_configured": cfg.Token != "", "webhook_secret_configured": cfg.WebhookSecret != "", "last_sync": nullable(cfg.LastSync), "last_error": cfg.LastError})
}

func (a *API) putRemnawaveSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		BaseURL        string   `json:"base_url"`
		APIVersion     string   `json:"api_version"`
		Token          string   `json:"token"`
		WebhookSecret  string   `json:"webhook_secret"`
		SelectedSquads []string `json:"selected_squads"`
		Enabled        bool     `json:"enabled"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	base, err := url.Parse(strings.TrimSpace(in.BaseURL))
	if err != nil || base.Host == "" || (base.Scheme != "http" && base.Scheme != "https") || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		writeError(w, 400, "base_url must be an http(s) panel URL without credentials or query parameters")
		return
	}
	version := strings.ToLower(strings.TrimSpace(in.APIVersion))
	if version == "" {
		version = "v2"
	}
	if version != "v2" && version != "v3" {
		writeError(w, 400, "api_version must be v2 or v3")
		return
	}
	old, oldErr := a.readRemnawaveConfig(r.Context())
	if oldErr != nil && !errors.Is(oldErr, sql.ErrNoRows) {
		writeError(w, 500, "integration settings unavailable")
		return
	}
	if in.Token == "" {
		in.Token = old.Token
	}
	if in.WebhookSecret == "" {
		in.WebhookSecret = old.WebhookSecret
	}
	if in.Token == "" || in.WebhookSecret == "" || len(in.Token) > 4096 || len(in.WebhookSecret) > 4096 {
		writeError(w, 400, "Remnawave API token and webhook secret are required")
		return
	}
	squads := make([]string, 0, len(in.SelectedSquads))
	seen := map[string]bool{}
	for _, id := range in.SelectedSquads {
		id = strings.TrimSpace(id)
		if id != "" && !seen[id] {
			seen[id] = true
			squads = append(squads, id)
		}
	}
	if in.Enabled && len(squads) == 0 {
		writeError(w, 400, "select at least one Internal Squad before enabling sync")
		return
	}
	squadJSON, _ := json.Marshal(squads)
	tokenCipher, err := a.store.encrypt([]byte(in.Token))
	if err != nil {
		writeError(w, 500, "encryption failed")
		return
	}
	secretCipher, err := a.store.encrypt([]byte(in.WebhookSecret))
	if err != nil {
		writeError(w, 500, "encryption failed")
		return
	}
	_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`INSERT INTO remnawave_settings(id,base_url,api_version,selected_squads,enabled,token_cipher,webhook_secret_cipher,updated_at) VALUES(1,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url,api_version=excluded.api_version,selected_squads=excluded.selected_squads,enabled=excluded.enabled,token_cipher=excluded.token_cipher,webhook_secret_cipher=excluded.webhook_secret_cipher,updated_at=excluded.updated_at`), strings.TrimRight(base.String(), "/"), version, string(squadJSON), in.Enabled, tokenCipher, secretCipher, nowText())
	if err != nil {
		writeError(w, 500, "integration settings could not be saved")
		return
	}
	a.audit(r, "remnawave.configure", "remnawave")
	writeJSON(w, 200, map[string]any{"enabled": in.Enabled, "base_url": strings.TrimRight(base.String(), "/"), "api_version": version, "selected_squads": squads, "token_configured": true, "webhook_secret_configured": true})
}

func (a *API) putSquadPoolMappings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mappings []struct {
			SquadUUID string `json:"squad_uuid"`
			PoolID    string `json:"pool_id"`
		} `json:"mappings"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	tx, err := a.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	if _, err = tx.ExecContext(r.Context(), `DELETE FROM squad_pools`); err == nil {
		for _, m := range in.Mappings {
			m.SquadUUID = strings.TrimSpace(m.SquadUUID)
			m.PoolID = strings.TrimSpace(m.PoolID)
			if m.SquadUUID == "" || m.PoolID == "" {
				err = errors.New("empty mapping")
				break
			}
			if _, err = tx.ExecContext(r.Context(), a.store.bind(`INSERT INTO squad_pools(squad_uuid,pool_id) VALUES(?,?)`), m.SquadUUID, m.PoolID); err != nil {
				break
			}
		}
	}
	if err != nil {
		_ = tx.Rollback()
		writeError(w, 400, "mapping contains an invalid pool or duplicate squad")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "database error")
		return
	}
	a.audit(r, "remnawave.map_squads", "remnawave")
	a.getSquadPoolMappings(w, r)
}
func (a *API) getSquadPoolMappings(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.db.QueryContext(r.Context(), `SELECT squad_uuid,pool_id FROM squad_pools ORDER BY squad_uuid`)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]string{}
	for rows.Next() {
		var squad, pool string
		if err := rows.Scan(&squad, &pool); err != nil {
			writeError(w, 500, "database error")
			return
		}
		items = append(items, map[string]string{"squad_uuid": squad, "pool_id": pool})
	}
	writeJSON(w, 200, map[string]any{"mappings": items})
}

func (a *API) remnawaveSync(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.readRemnawaveConfig(r.Context())
	if errors.Is(err, sql.ErrNoRows) || err == nil && !cfg.Enabled {
		writeError(w, 409, "Remnawave sync is not enabled")
		return
	}
	if err != nil {
		writeError(w, 500, "integration settings unavailable")
		return
	}
	count, err := a.syncRemnawave(r.Context(), cfg)
	if err != nil {
		a.setRemnawaveStatus(r.Context(), err.Error(), false)
		writeError(w, 502, "Remnawave sync failed; last known users were retained")
		return
	}
	a.setRemnawaveStatus(r.Context(), "", true)
	a.audit(r, "remnawave.sync", "remnawave")
	writeJSON(w, 200, map[string]any{"synced_users": count, "completed_at": nowText()})
}

func (a *API) remnawaveWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, 413, "webhook payload too large")
		return
	}
	cfg, err := a.readRemnawaveConfig(r.Context())
	if err != nil || !cfg.Enabled {
		writeError(w, 503, "Remnawave integration unavailable")
		return
	}
	if !VerifyRemnawaveWebhook(cfg.WebhookSecret, body, r.Header.Get("X-Remnawave-Signature")) {
		writeError(w, 401, "invalid webhook signature")
		return
	}
	timestamp := strings.TrimSpace(r.Header.Get("X-Remnawave-Timestamp"))
	if timestamp != "" {
		when, err := time.Parse(time.RFC3339Nano, timestamp)
		if err != nil || time.Since(when) > 5*time.Minute || time.Until(when) > 5*time.Minute {
			writeError(w, 401, "stale webhook")
			return
		}
	}
	eventID := hashToken(r.Header.Get("X-Remnawave-Signature"))
	res, err := a.store.db.ExecContext(r.Context(), a.store.bind(`INSERT INTO remnawave_events(event_id,received_at) VALUES(?,?) ON CONFLICT(event_id) DO NOTHING`), eventID, nowText())
	if err != nil {
		writeError(w, 500, "webhook could not be recorded")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	count, err := a.syncRemnawave(r.Context(), cfg)
	if err != nil {
		a.setRemnawaveStatus(r.Context(), err.Error(), false)
		writeError(w, 502, "webhook accepted but reconciliation failed; existing access was retained")
		return
	}
	a.setRemnawaveStatus(r.Context(), "", true)
	writeJSON(w, 200, map[string]any{"accepted": true, "synced_users": count})
}

func (a *API) setRemnawaveStatus(ctx context.Context, message string, success bool) {
	if success {
		_, _ = a.store.db.ExecContext(ctx, `UPDATE remnawave_settings SET last_sync=?,last_error='',updated_at=? WHERE id=1`, nowText(), nowText())
	} else {
		_, _ = a.store.db.ExecContext(ctx, a.store.bind(`UPDATE remnawave_settings SET last_error=?,updated_at=? WHERE id=1`), truncate(message, 512), nowText())
	}
}
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

type remnaUser struct {
	UUID           string          `json:"uuid"`
	ID             json.RawMessage `json:"id"`
	ShortUUID      string          `json:"shortUuid"`
	Username       string          `json:"username"`
	Status         string          `json:"status"`
	Enabled        *bool           `json:"enabled"`
	InternalSquads []struct {
		UUID string `json:"uuid"`
	} `json:"internalSquads"`
	InternalSquadUUIDs []string `json:"internalSquadUuids"`
}
type remnaPage struct {
	Users      []remnaUser `json:"users"`
	NextCursor string      `json:"nextCursor"`
	Response   struct {
		Users      []remnaUser `json:"users"`
		NextCursor string      `json:"nextCursor"`
	} `json:"response"`
}

func (a *API) fetchRemnawaveUsers(ctx context.Context, cfg remnaConfig) ([]remnaUser, error) {
	base := strings.TrimRight(cfg.BaseURL, "/")
	if !strings.HasSuffix(base, "/api") {
		base += "/api"
	}
	client := &http.Client{Timeout: 15 * time.Second}
	all := []remnaUser{}
	for page := 0; page < 1000; page++ {
		endpoint := base + "/users"
		params := url.Values{}
		size := 1000
		if cfg.APIVersion == "v3" {
			size = 250
			endpoint = base + "/users/stream"
			params.Set("size", strconv.Itoa(size))
		} else {
			params.Set("start", strconv.Itoa(page*size))
			params.Set("size", strconv.Itoa(size))
		}
		if params.Encode() != "" {
			endpoint += "?" + params.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Remnawave API request failed: %w", err)
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("Remnawave API returned HTTP %d", resp.StatusCode)
		}
		var result remnaPage
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, errors.New("Remnawave API returned invalid user JSON")
		}
		items := result.Users
		if items == nil {
			items = result.Response.Users
		}
		if items == nil {
			return nil, errors.New("Remnawave response did not contain a users list")
		}
		next := result.NextCursor
		if next == "" {
			next = result.Response.NextCursor
		}
		all = append(all, items...)
		if cfg.APIVersion == "v3" {
			if next == "" {
				break
			}
			return a.fetchRemnawaveCursorUsers(ctx, cfg, base, client, all, next, page+1)
		}
		if len(items) < size {
			break
		}
		if page == 999 {
			return nil, errors.New("Remnawave pagination limit exceeded")
		}
	}
	return all, nil
}
func (a *API) fetchRemnawaveCursorUsers(ctx context.Context, cfg remnaConfig, base string, client *http.Client, all []remnaUser, cursor string, page int) ([]remnaUser, error) {
	for ; page < 1000; page++ {
		params := url.Values{"size": []string{"250"}, "cursor": []string{cursor}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/users/stream?"+params.Encode(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		req.Header.Set("Accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Remnawave API request failed: %w", err)
		}
		data, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		_ = resp.Body.Close()
		if e != nil {
			return nil, e
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return nil, fmt.Errorf("Remnawave API returned HTTP %d", resp.StatusCode)
		}
		var result remnaPage
		if err := json.Unmarshal(data, &result); err != nil {
			return nil, errors.New("Remnawave API returned invalid user JSON")
		}
		items := result.Users
		if items == nil {
			items = result.Response.Users
		}
		if items == nil {
			return nil, errors.New("Remnawave response did not contain a users list")
		}
		all = append(all, items...)
		next := result.NextCursor
		if next == "" {
			next = result.Response.NextCursor
		}
		if next == "" {
			return all, nil
		}
		if next == cursor {
			return nil, errors.New("Remnawave API repeated a pagination cursor")
		}
		cursor = next
	}
	return nil, errors.New("Remnawave pagination limit exceeded")
}

func remnaExternalID(user remnaUser) string {
	if user.UUID != "" {
		return strings.TrimSpace(user.UUID)
	}
	if len(user.ID) > 0 {
		var id string
		if json.Unmarshal(user.ID, &id) == nil {
			return strings.TrimSpace(id)
		}
		return strings.TrimSpace(string(user.ID))
	}
	return strings.TrimSpace(user.ShortUUID)
}
func remnaUserEnabled(user remnaUser) bool {
	if user.Enabled != nil {
		return *user.Enabled
	}
	status := strings.ToUpper(strings.TrimSpace(user.Status))
	return status == "ACTIVE" || status == "ENABLED"
}
func remnaUserSquads(user remnaUser) []string {
	out := append([]string(nil), user.InternalSquadUUIDs...)
	for _, s := range user.InternalSquads {
		if s.UUID != "" {
			out = append(out, s.UUID)
		}
	}
	return out
}

func (a *API) syncRemnawave(ctx context.Context, cfg remnaConfig) (int, error) {
	if len(cfg.SelectedSquads) == 0 {
		return 0, errors.New("no allowed Internal Squads configured")
	}
	remote, err := a.fetchRemnawaveUsers(ctx, cfg)
	if err != nil {
		return 0, err
	}
	allowed := map[string]bool{}
	for _, id := range cfg.SelectedSquads {
		allowed[id] = true
	}
	type imported struct {
		ID, Name string
		Enabled  bool
		Squads   []string
	}
	selected := map[string]imported{}
	for _, u := range remote {
		id := remnaExternalID(u)
		name := strings.TrimSpace(u.Username)
		if id == "" || name == "" {
			continue
		}
		squads := []string{}
		seenSquads := map[string]bool{}
		for _, squad := range remnaUserSquads(u) {
			if allowed[squad] && !seenSquads[squad] {
				seenSquads[squad] = true
				squads = append(squads, squad)
			}
		}
		if len(squads) == 0 {
			continue
		}
		sort.Strings(squads)
		selected[id] = imported{id, name, remnaUserEnabled(u), squads}
	}
	tx, err := a.store.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	now := nowText()
	type existingUser struct {
		id, name string
		enabled  bool
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,external_id,username,enabled FROM users WHERE source='remnawave'`)
	if err != nil {
		return 0, err
	}
	existing := map[string]existingUser{}
	for rows.Next() {
		var external string
		var user existingUser
		if err := rows.Scan(&user.id, &external, &user.name, &user.enabled); err != nil {
			_ = rows.Close()
			return 0, err
		}
		existing[external] = user
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()

	currentSquads := map[string][]string{}
	rows, err = tx.QueryContext(ctx, `SELECT u.external_id,s.squad_uuid FROM user_squads s JOIN users u ON u.id=s.user_id WHERE u.source='remnawave' ORDER BY u.external_id,s.squad_uuid`)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var external, squad string
		if err := rows.Scan(&external, &squad); err != nil {
			_ = rows.Close()
			return 0, err
		}
		currentSquads[external] = append(currentSquads[external], squad)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return 0, err
	}
	_ = rows.Close()

	changed := false
	for external, desired := range selected {
		current, exists := existing[external]
		if !exists || current.name != desired.Name || current.enabled != desired.Enabled || !sameStrings(currentSquads[external], desired.Squads) {
			changed = true
		}
	}
	for external := range existing {
		if _, remains := selected[external]; !remains {
			changed = true
		}
	}

	for external, u := range selected {
		id := existing[external].id
		if id == "" {
			id = newID()
		}
		_, err = tx.ExecContext(ctx, a.store.bind(`INSERT INTO users(id,source,external_id,username,enabled,created_at,updated_at) VALUES(?,'remnawave',?,?,?,?,?) ON CONFLICT(source,external_id) DO UPDATE SET username=excluded.username,enabled=excluded.enabled,updated_at=excluded.updated_at`), id, external, u.Name, u.Enabled, now, now)
		if err != nil {
			return 0, err
		}
		var actualID string
		if err = tx.QueryRowContext(ctx, a.store.bind(`SELECT id FROM users WHERE source='remnawave' AND external_id=?`), external).Scan(&actualID); err != nil {
			return 0, err
		}
		_, err = tx.ExecContext(ctx, a.store.bind(`DELETE FROM user_squads WHERE user_id=?`), actualID)
		if err != nil {
			return 0, err
		}
		for _, squad := range u.Squads {
			_, err = tx.ExecContext(ctx, a.store.bind(`INSERT INTO user_squads(user_id,squad_uuid) VALUES(?,?)`), actualID, squad)
			if err != nil {
				return 0, err
			}
		}
		if !u.Enabled {
			_, _ = tx.ExecContext(ctx, a.store.bind(`UPDATE subscriptions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), now, actualID)
			_, _ = tx.ExecContext(ctx, a.store.bind(`UPDATE devices SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), now, actualID)
		}
	}
	for external, user := range existing {
		if _, ok := selected[external]; !ok {
			_, err = tx.ExecContext(ctx, a.store.bind(`UPDATE users SET enabled=FALSE,updated_at=? WHERE id=?`), now, user.id)
			if err != nil {
				return 0, err
			}
			_, _ = tx.ExecContext(ctx, a.store.bind(`DELETE FROM user_squads WHERE user_id=?`), user.id)
			_, _ = tx.ExecContext(ctx, a.store.bind(`UPDATE subscriptions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), now, user.id)
			_, _ = tx.ExecContext(ctx, a.store.bind(`UPDATE devices SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), now, user.id)
		}
	}
	if changed {
		if _, err = tx.ExecContext(ctx, `UPDATE settings SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key='config_version'`); err != nil {
			return 0, err
		}
		if _, err = tx.ExecContext(ctx, `UPDATE nodes SET config_version=(SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version')`); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(); err != nil {
		return 0, err
	}
	return len(selected), nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// RunRemnawaveReconciler performs the required full reconciliation every minute.
func (a *API) RunRemnawaveReconciler(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cfg, err := a.readRemnawaveConfig(ctx)
			if err != nil || !cfg.Enabled {
				continue
			}
			if _, err = a.syncRemnawave(ctx, cfg); err != nil {
				a.setRemnawaveStatus(ctx, err.Error(), false)
			} else {
				a.setRemnawaveStatus(ctx, "", true)
			}
		}
	}
}

func VerifyRemnawaveWebhook(secret string, body []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return hmac.Equal([]byte(strings.ToLower(strings.TrimSpace(signature))), []byte(hex.EncodeToString(mac.Sum(nil))))
}
