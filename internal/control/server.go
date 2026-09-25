package control

import (
	"context"
	"crypto/subtle"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/skip2/go-qrcode"

	"openflux/transport/yandex"
)

//go:embed openapi.json
var openAPISpec []byte

type API struct {
	store     *Store
	admin     string
	publicURL string
	mux       *http.ServeMux
}

func NewAPI(store *Store, adminToken, publicURL string) (*API, error) {
	if store == nil {
		return nil, errors.New("control store is required")
	}
	if strings.TrimSpace(adminToken) == "" {
		return nil, errors.New("OPENFLUX_ADMIN_TOKEN is required")
	}
	if strings.TrimSpace(publicURL) == "" {
		publicURL = "http://127.0.0.1:8787"
	}
	a := &API{store: store, admin: adminToken, publicURL: strings.TrimRight(publicURL, "/"), mux: http.NewServeMux()}
	a.routes()
	return a, nil
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

func (a *API) routes() {
	a.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := a.store.db.PingContext(r.Context()); err != nil {
			writeError(w, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	a.mux.HandleFunc("GET /api/v1/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(openAPISpec)
	})
	a.mux.HandleFunc("GET /s/{token}", a.subscriptionProfile)
	a.mux.HandleFunc("POST /api/v1/device/register", a.deviceRegister)
	a.adminRoute("GET /api/v1/users", a.listUsers)
	a.adminRoute("POST /api/v1/users", a.createUser)
	a.adminRoute("GET /api/v1/users/{id}", a.getUser)
	a.adminRoute("PATCH /api/v1/users/{id}", a.patchUser)
	a.adminRoute("DELETE /api/v1/users/{id}", a.deleteUser)
	a.adminRoute("GET /api/v1/users/{id}/devices", a.listDevices)
	a.adminRoute("DELETE /api/v1/devices/{id}", a.revokeDevice)
	a.adminRoute("POST /api/v1/devices/{id}/rotate", a.rotateDevice)
	a.adminRoute("POST /api/v1/users/{id}/subscription", a.issueSubscription)
	a.adminRoute("GET /api/v1/users/{id}/config", a.exportConfig)
	a.adminRoute("GET /api/v1/documents", a.listDocuments)
	a.adminRoute("POST /api/v1/documents", a.createDocument)
	a.adminRoute("GET /api/v1/documents/{id}", a.getDocument)
	a.adminRoute("PUT /api/v1/documents/{id}", a.updateDocument)
	a.adminRoute("DELETE /api/v1/documents/{id}", a.deleteDocument)
	a.adminRoute("GET /api/v1/pools", a.listPools)
	a.adminRoute("POST /api/v1/pools", a.createPool)
	a.adminRoute("GET /api/v1/pools/{id}", a.getPool)
	a.adminRoute("PUT /api/v1/pools/{id}", a.updatePool)
	a.adminRoute("DELETE /api/v1/pools/{id}", a.deletePool)
	a.adminRoute("GET /api/v1/nodes", a.listNodes)
	a.adminRoute("POST /api/v1/nodes", a.createNode)
	a.adminRoute("GET /api/v1/nodes/{id}", a.getNode)
	a.adminRoute("PUT /api/v1/nodes/{id}", a.updateNode)
	a.adminRoute("DELETE /api/v1/nodes/{id}", a.deleteNode)
	a.mux.HandleFunc("GET /api/v1/nodes/{id}/config", a.nodeConfig)
	a.mux.HandleFunc("POST /api/v1/nodes/{id}/ack", a.nodeAck)
	a.adminRoute("GET /api/v1/audit", a.auditList)
	a.adminRoute("GET /api/v1/integrations/remnawave", a.getRemnawaveSettings)
	a.adminRoute("PUT /api/v1/integrations/remnawave", a.putRemnawaveSettings)
	a.adminRoute("PUT /api/v1/integrations/remnawave/squad-pools", a.putSquadPoolMappings)
	a.adminRoute("GET /api/v1/integrations/remnawave/squad-pools", a.getSquadPoolMappings)
	a.adminRoute("POST /api/v1/integrations/remnawave/sync", a.remnawaveSync)
	a.mux.HandleFunc("POST /api/v1/integrations/remnawave/webhook", a.remnawaveWebhook)
}

func (a *API) adminRoute(pattern string, fn http.HandlerFunc) {
	a.mux.Handle(pattern, a.adminOnly(fn))
}

func (a *API) adminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(got) != len(a.admin) || subtle.ConstantTimeCompare([]byte(got), []byte(a.admin)) != 1 {
			writeError(w, 401, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type userDTO struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	ExternalID string `json:"external_id,omitempty"`
	Username   string `json:"username"`
	Enabled    bool   `json:"enabled"`
	CreatedAt  string `json:"created_at"`
}

type documentDTO struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Enabled bool   `json:"enabled"`
}

func validatePoolMode(mode, endpoint, target string) error {
	mode = strings.TrimSpace(mode)
	endpoint = strings.TrimSpace(endpoint)
	target = strings.TrimSpace(target)
	switch mode {
	case "standalone":
		if endpoint != "" || target != "" {
			return errors.New("standalone pools must not set tcp_endpoint or forward_target")
		}
	case "transport":
		host, portText, err := net.SplitHostPort(endpoint)
		port, portErr := strconv.Atoi(portText)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || ip.To4() == nil || portErr != nil || port < 1 || port > 65535 {
			return errors.New("transport pools require an IPv4 tcp_endpoint host:port")
		}
		targetHost, targetPortText, err := net.SplitHostPort(target)
		targetPort, targetPortErr := strconv.Atoi(targetPortText)
		if err != nil || targetHost == "" || strings.ContainsAny(targetHost, "\x00\r\n/?#") || targetPortErr != nil || targetPort < 1 || targetPort > 65535 {
			return errors.New("transport pools require a valid Xray forward_target host:port")
		}
	default:
		return errors.New("pool mode must be standalone or transport")
	}
	return nil
}

func publicPools(pools []poolDTO) []map[string]any {
	out := make([]map[string]any, 0, len(pools))
	for _, p := range pools {
		item := map[string]any{"id": p.ID, "name": p.Name, "strategy": p.Strategy, "mode": p.Mode, "documents": p.Documents, "enabled": p.Enabled}
		if p.TCPEndpoint != "" {
			item["tcp_endpoint"] = p.TCPEndpoint
		}
		out = append(out, item)
	}
	return out
}

type poolDTO struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Strategy      string        `json:"strategy"`
	Mode          string        `json:"mode"`
	TCPEndpoint   string        `json:"tcp_endpoint,omitempty"`
	ForwardTarget string        `json:"forward_target,omitempty"`
	Documents     []documentDTO `json:"documents"`
	Enabled       bool          `json:"enabled"`
}

func decodeJSON(r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func (a *API) audit(r *http.Request, action, target string) {
	actor := "admin"
	if id := r.Header.Get("X-OpenFlux-Actor"); id != "" && len(id) < 128 {
		actor = id
	}
	_, _ = a.store.db.Exec(a.store.bind(`INSERT INTO audit_log(id,actor,action,target,created_at) VALUES(?,?,?,?,?)`), newID(), actor, action, target, nowText())
	_, _ = a.store.db.Exec(a.store.bind(`UPDATE settings SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key='config_version'`))
	_, _ = a.store.db.Exec(`UPDATE nodes SET config_version=(SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version')`)
}

func (a *API) listUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.db.QueryContext(r.Context(), `SELECT id,source,COALESCE(external_id,''),username,enabled,created_at FROM users ORDER BY created_at DESC`)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := make([]userDTO, 0)
	for rows.Next() {
		var u userDTO
		if err := rows.Scan(&u.ID, &u.Source, &u.ExternalID, &u.Username, &u.Enabled, &u.CreatedAt); err != nil {
			writeError(w, 500, "database error")
			return
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]any{"users": items})
}

func (a *API) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if in.Username == "" || len(in.Username) > 128 {
		writeError(w, 400, "username must contain 1 to 128 characters")
		return
	}
	now := nowText()
	u := userDTO{ID: newID(), Source: "local", Username: in.Username, Enabled: true, CreatedAt: now}
	_, err := a.store.db.ExecContext(r.Context(), a.store.bind(`INSERT INTO users(id,source,external_id,username,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?)`), u.ID, u.Source, nil, u.Username, true, now, now)
	if err != nil {
		writeError(w, 409, "username could not be created")
		return
	}
	a.audit(r, "user.create", u.ID)
	writeJSON(w, 201, u)
}

func (a *API) user(ctx context.Context, id string) (userDTO, error) {
	var u userDTO
	err := a.store.db.QueryRowContext(ctx, a.store.bind(`SELECT id,source,COALESCE(external_id,''),username,enabled,created_at FROM users WHERE id=?`), id).Scan(&u.ID, &u.Source, &u.ExternalID, &u.Username, &u.Enabled, &u.CreatedAt)
	return u, err
}
func (a *API) getUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.user(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "user not found")
		return
	}
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, u)
}
func (a *API) patchUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username *string `json:"username"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	u, err := a.user(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "user not found")
		return
	}
	if u.Source != "local" {
		writeError(w, 403, "Remnawave users are managed by Remnawave")
		return
	}
	if in.Username == nil && in.Enabled == nil {
		writeError(w, 400, "no fields to update")
		return
	}
	if in.Username != nil {
		v := strings.TrimSpace(*in.Username)
		if v == "" || len(v) > 128 {
			writeError(w, 400, "invalid username")
			return
		}
		_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE users SET username=?,updated_at=? WHERE id=?`), v, nowText(), u.ID)
		if err != nil {
			writeError(w, 500, "database error")
			return
		}
	}
	if in.Enabled != nil {
		_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE users SET enabled=?,updated_at=? WHERE id=?`), *in.Enabled, nowText(), u.ID)
		if err != nil {
			writeError(w, 500, "database error")
			return
		}
		if !*in.Enabled {
			_, _ = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE subscriptions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), nowText(), u.ID)
			_, _ = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE devices SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), nowText(), u.ID)
		}
	}
	a.audit(r, "user.update", u.ID)
	u, err = a.user(r.Context(), u.ID)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, u)
}
func (a *API) deleteUser(w http.ResponseWriter, r *http.Request) {
	u, err := a.user(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "user not found")
		return
	}
	if u.Source != "local" {
		writeError(w, 403, "Remnawave users are managed by Remnawave")
		return
	}
	a.audit(r, "user.delete", u.ID)
	_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`DELETE FROM users WHERE id=?`), u.ID)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) listDocuments(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.db.QueryContext(r.Context(), `SELECT id,name,url_cipher,enabled FROM documents ORDER BY name`)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []documentDTO{}
	for rows.Next() {
		var d documentDTO
		var enc []byte
		if err := rows.Scan(&d.ID, &d.Name, &enc, &d.Enabled); err != nil {
			writeError(w, 500, "database error")
			return
		}
		b, err := a.store.decrypt(enc)
		if err != nil {
			writeError(w, 500, "secret decryption failed")
			return
		}
		d.URL = string(b)
		items = append(items, d)
	}
	writeJSON(w, 200, map[string]any{"documents": items})
}
func (a *API) createDocument(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	u, err := url.ParseRequestURI(strings.TrimSpace(in.URL))
	if in.Name == "" || len(in.Name) > 128 || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		writeError(w, 400, "document requires a name and http(s) URL")
		return
	}
	enc, err := a.store.encrypt([]byte(u.String()))
	if err != nil {
		writeError(w, 500, "encryption failed")
		return
	}
	d := documentDTO{ID: newID(), Name: in.Name, URL: u.String(), Enabled: true}
	_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`INSERT INTO documents(id,name,url_cipher,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?)`), d.ID, d.Name, enc, true, nowText(), nowText())
	if err != nil {
		writeError(w, 409, "document could not be created")
		return
	}
	a.audit(r, "document.create", d.ID)
	writeJSON(w, 201, d)
}
func (a *API) getDocument(w http.ResponseWriter, r *http.Request) {
	d, err := a.document(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "document not found")
		return
	}
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, d)
}
func (a *API) document(ctx context.Context, id string) (documentDTO, error) {
	var d documentDTO
	var enc []byte
	err := a.store.db.QueryRowContext(ctx, a.store.bind(`SELECT id,name,url_cipher,enabled FROM documents WHERE id=?`), id).Scan(&d.ID, &d.Name, &enc, &d.Enabled)
	if err != nil {
		return d, err
	}
	b, err := a.store.decrypt(enc)
	d.URL = string(b)
	return d, err
}
func (a *API) updateDocument(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name                      *string `json:"name"`
		URL                       *string `json:"url"`
		Enabled                   *bool   `json:"enabled"`
		ConfirmLastWorkingRemoval bool    `json:"confirm_last_working_removal"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	d, err := a.document(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "document not found")
		return
	}
	if in.Name != nil {
		d.Name = strings.TrimSpace(*in.Name)
	}
	if in.URL != nil {
		u, e := url.ParseRequestURI(strings.TrimSpace(*in.URL))
		if e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			writeError(w, 400, "invalid document URL")
			return
		}
		d.URL = u.String()
	}
	if in.Enabled != nil {
		d.Enabled = *in.Enabled
	}
	if d.Name == "" || len(d.Name) > 128 {
		writeError(w, 400, "invalid document name")
		return
	}
	if !d.Enabled {
		var emptyPools int
		err = a.store.db.QueryRowContext(r.Context(), a.store.bind(`SELECT COUNT(*) FROM pools p WHERE p.enabled=TRUE AND EXISTS(SELECT 1 FROM pool_documents pd WHERE pd.pool_id=p.id AND pd.document_id=?) AND NOT EXISTS(SELECT 1 FROM pool_documents pd2 JOIN documents d2 ON d2.id=pd2.document_id WHERE pd2.pool_id=p.id AND pd2.document_id<>? AND d2.enabled=TRUE)`), d.ID, d.ID).Scan(&emptyPools)
		if err != nil {
			writeError(w, 500, "database error")
			return
		}
		if emptyPools > 0 && !in.ConfirmLastWorkingRemoval {
			writeError(w, 409, "this is the last working document in a pool; set confirm_last_working_removal=true to continue")
			return
		}
	}
	enc, err := a.store.encrypt([]byte(d.URL))
	if err != nil {
		writeError(w, 500, "encryption failed")
		return
	}
	_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE documents SET name=?,url_cipher=?,enabled=?,updated_at=? WHERE id=?`), d.Name, enc, d.Enabled, nowText(), d.ID)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	a.audit(r, "document.update", d.ID)
	writeJSON(w, 200, d)
}
func (a *API) deleteDocument(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var count int
	if err := a.store.db.QueryRowContext(r.Context(), a.store.bind(`SELECT COUNT(*) FROM pool_documents WHERE document_id=?`), id).Scan(&count); err != nil {
		writeError(w, 500, "database error")
		return
	}
	if count > 0 {
		writeError(w, 409, "document is assigned to a pool")
		return
	}
	res, err := a.store.db.ExecContext(r.Context(), a.store.bind(`DELETE FROM documents WHERE id=?`), id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeError(w, 404, "document not found")
		return
	}
	a.audit(r, "document.delete", id)
	w.WriteHeader(204)
}

func (a *API) listPools(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.db.QueryContext(r.Context(), `SELECT id,name,strategy,enabled,mode,tcp_endpoint,forward_target FROM pools ORDER BY name`)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	items := []poolDTO{}
	for rows.Next() {
		var p poolDTO
		if err := rows.Scan(&p.ID, &p.Name, &p.Strategy, &p.Enabled, &p.Mode, &p.TCPEndpoint, &p.ForwardTarget); err != nil {
			_ = rows.Close()
			writeError(w, 500, "database error")
			return
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		writeError(w, 500, "database error")
		return
	}
	_ = rows.Close()
	for i := range items {
		items[i].Documents, err = a.poolDocuments(r.Context(), items[i].ID)
		if err != nil {
			writeError(w, 500, "database error")
			return
		}
	}
	writeJSON(w, 200, map[string]any{"pools": items})
}
func (a *API) getPool(w http.ResponseWriter, r *http.Request) {
	p, err := a.pool(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "pool not found")
		return
	}
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, p)
}
func (a *API) pool(ctx context.Context, id string) (poolDTO, error) {
	var p poolDTO
	err := a.store.db.QueryRowContext(ctx, a.store.bind(`SELECT id,name,strategy,enabled,mode,tcp_endpoint,forward_target FROM pools WHERE id=?`), id).Scan(&p.ID, &p.Name, &p.Strategy, &p.Enabled, &p.Mode, &p.TCPEndpoint, &p.ForwardTarget)
	if err != nil {
		return p, err
	}
	p.Documents, err = a.poolDocuments(ctx, p.ID)
	return p, err
}
func (a *API) poolDocuments(ctx context.Context, id string) ([]documentDTO, error) {
	rows, err := a.store.db.QueryContext(ctx, a.store.bind(`SELECT d.id,d.name,d.url_cipher,d.enabled FROM documents d JOIN pool_documents pd ON pd.document_id=d.id WHERE pd.pool_id=? ORDER BY pd.position`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []documentDTO{}
	for rows.Next() {
		var d documentDTO
		var enc []byte
		if err := rows.Scan(&d.ID, &d.Name, &enc, &d.Enabled); err != nil {
			return nil, err
		}
		b, err := a.store.decrypt(enc)
		if err != nil {
			return nil, err
		}
		d.URL = string(b)
		items = append(items, d)
	}
	return items, rows.Err()
}
func (a *API) createPool(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string   `json:"name"`
		Strategy      string   `json:"strategy"`
		Mode          string   `json:"mode"`
		TCPEndpoint   string   `json:"tcp_endpoint"`
		ForwardTarget string   `json:"forward_target"`
		DocumentIDs   []string `json:"document_ids"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Strategy == "" {
		in.Strategy = "least-loaded"
	}
	if in.Name == "" || len(in.Name) > 128 || len(in.DocumentIDs) == 0 {
		writeError(w, 400, "pool requires name and at least one document")
		return
	}
	if in.Strategy != "least-loaded" && in.Strategy != "round-robin" && in.Strategy != "sticky" {
		writeError(w, 400, "invalid pool strategy")
		return
	}
	if in.Mode == "" {
		in.Mode = "standalone"
	}
	if err := validatePoolMode(in.Mode, in.TCPEndpoint, in.ForwardTarget); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	p := poolDTO{ID: newID(), Name: in.Name, Strategy: in.Strategy, Mode: in.Mode, TCPEndpoint: in.TCPEndpoint, ForwardTarget: in.ForwardTarget, Enabled: true}
	tx, err := a.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	if _, err = tx.ExecContext(r.Context(), a.store.bind(`INSERT INTO pools(id,name,strategy,enabled,mode,tcp_endpoint,forward_target,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`), p.ID, p.Name, p.Strategy, true, p.Mode, p.TCPEndpoint, p.ForwardTarget, nowText(), nowText()); err == nil {
		for i, id := range in.DocumentIDs {
			if _, err = tx.ExecContext(r.Context(), a.store.bind(`INSERT INTO pool_documents(pool_id,document_id,position) VALUES(?,?,?)`), p.ID, id, i); err != nil {
				break
			}
		}
	}
	if err != nil {
		_ = tx.Rollback()
		writeError(w, 400, "pool references an invalid or duplicate document")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "database error")
		return
	}
	a.audit(r, "pool.create", p.ID)
	p.Documents, err = a.poolDocuments(r.Context(), p.ID)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 201, p)
}
func (a *API) updatePool(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Name                      *string   `json:"name"`
		Strategy                  *string   `json:"strategy"`
		Mode                      *string   `json:"mode"`
		TCPEndpoint               *string   `json:"tcp_endpoint"`
		ForwardTarget             *string   `json:"forward_target"`
		DocumentIDs               *[]string `json:"document_ids"`
		Enabled                   *bool     `json:"enabled"`
		ConfirmLastWorkingRemoval bool      `json:"confirm_last_working_removal"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	p, err := a.pool(r.Context(), id)
	if err != nil {
		writeError(w, 404, "pool not found")
		return
	}
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Strategy != nil {
		p.Strategy = *in.Strategy
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if in.Mode != nil {
		p.Mode = *in.Mode
	}
	if in.TCPEndpoint != nil {
		p.TCPEndpoint = strings.TrimSpace(*in.TCPEndpoint)
	}
	if in.ForwardTarget != nil {
		p.ForwardTarget = strings.TrimSpace(*in.ForwardTarget)
	}
	if p.Name == "" || len(p.Name) > 128 || (p.Strategy != "least-loaded" && p.Strategy != "round-robin" && p.Strategy != "sticky") {
		writeError(w, 400, "invalid pool fields")
		return
	}
	if err := validatePoolMode(p.Mode, p.TCPEndpoint, p.ForwardTarget); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	tx, err := a.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	var previouslyWorking int
	_ = tx.QueryRowContext(r.Context(), a.store.bind(`SELECT COUNT(*) FROM pool_documents pd JOIN documents d ON d.id=pd.document_id WHERE pd.pool_id=? AND d.enabled=TRUE`), id).Scan(&previouslyWorking)
	_, err = tx.ExecContext(r.Context(), a.store.bind(`UPDATE pools SET name=?,strategy=?,enabled=?,mode=?,tcp_endpoint=?,forward_target=?,updated_at=? WHERE id=?`), p.Name, p.Strategy, p.Enabled, p.Mode, p.TCPEndpoint, p.ForwardTarget, nowText(), id)
	if err == nil && in.DocumentIDs != nil {
		if len(*in.DocumentIDs) == 0 {
			err = errors.New("empty document set")
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), a.store.bind(`DELETE FROM pool_documents WHERE pool_id=?`), id)
		}
		for i, doc := range *in.DocumentIDs {
			if err != nil {
				break
			}
			_, err = tx.ExecContext(r.Context(), a.store.bind(`INSERT INTO pool_documents(pool_id,document_id,position) VALUES(?,?,?)`), id, doc, i)
		}
	}
	if err == nil && p.Enabled {
		var working int
		err = tx.QueryRowContext(r.Context(), a.store.bind(`SELECT COUNT(*) FROM pool_documents pd JOIN documents d ON d.id=pd.document_id WHERE pd.pool_id=? AND d.enabled=TRUE`), id).Scan(&working)
		if err == nil && previouslyWorking > 0 && working == 0 && !in.ConfirmLastWorkingRemoval {
			err = errors.New("last working document removal requires confirmation")
		}
	}
	if err != nil {
		_ = tx.Rollback()
		if strings.Contains(err.Error(), "confirmation") {
			writeError(w, 409, "this update removes the last working document; set confirm_last_working_removal=true to continue")
			return
		}
		writeError(w, 400, "pool update failed; documents must exist and at least one must remain")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "database error")
		return
	}
	a.audit(r, "pool.update", id)
	p, err = a.pool(r.Context(), id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, p)
}
func (a *API) deletePool(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := a.store.db.ExecContext(r.Context(), a.store.bind(`DELETE FROM pools WHERE id=?`), id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeError(w, 404, "pool not found")
		return
	}
	a.audit(r, "pool.delete", id)
	w.WriteHeader(204)
}

func (a *API) createNode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Role    string `json:"role"`
		Address string `json:"address"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Address = strings.TrimSpace(in.Address)
	if in.Name == "" || in.Address == "" || (in.Role != "exit" && in.Role != "transport") {
		writeError(w, 400, "node requires name, address and role exit|transport")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, 500, "credential generation failed")
		return
	}
	id := newID()
	_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`INSERT INTO nodes(id,name,role,address,token_hash,enabled,created_at) VALUES(?,?,?,?,?,?,?)`), id, in.Name, in.Role, in.Address, hashToken(token), true, nowText())
	if err != nil {
		writeError(w, 409, "node could not be created")
		return
	}
	a.audit(r, "node.create", id)
	writeJSON(w, 201, map[string]any{"id": id, "name": in.Name, "role": in.Role, "address": in.Address, "token": token})
}
func (a *API) nodeRows(ctx context.Context, id string) (map[string]any, error) {
	var name, role, address, errText string
	var enabled bool
	var current, applied int64
	var last sql.NullString
	err := a.store.db.QueryRowContext(ctx, a.store.bind(`SELECT name,role,address,enabled,config_version,applied_version,apply_error,last_seen FROM nodes WHERE id=?`), id).Scan(&name, &role, &address, &enabled, &current, &applied, &errText, &last)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name, "role": role, "address": address, "enabled": enabled, "config_version": current, "applied_version": applied, "apply_error": errText, "last_seen": nullable(last)}, nil
}
func nullable(v sql.NullString) any {
	if !v.Valid {
		return nil
	}
	return v.String
}
func (a *API) listNodes(w http.ResponseWriter, r *http.Request) {
	rows, err := a.store.db.QueryContext(r.Context(), `SELECT id FROM nodes ORDER BY name`)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			writeError(w, 500, "database error")
			return
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		writeError(w, 500, "database error")
		return
	}
	_ = rows.Close()
	items := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		item, err := a.nodeRows(r.Context(), id)
		if err != nil {
			writeError(w, 500, "database error")
			return
		}
		items = append(items, item)
	}
	writeJSON(w, 200, map[string]any{"nodes": items})
}
func (a *API) getNode(w http.ResponseWriter, r *http.Request) {
	v, err := a.nodeRows(r.Context(), r.PathValue("id"))
	if errors.Is(err, sql.ErrNoRows) {
		writeError(w, 404, "node not found")
		return
	}
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, v)
}
func (a *API) updateNode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    *string `json:"name"`
		Role    *string `json:"role"`
		Address *string `json:"address"`
		Enabled *bool   `json:"enabled"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	id := r.PathValue("id")
	v, err := a.nodeRows(r.Context(), id)
	if err != nil {
		writeError(w, 404, "node not found")
		return
	}
	name, role, address := v["name"].(string), v["role"].(string), v["address"].(string)
	enabled := v["enabled"].(bool)
	if in.Name != nil {
		name = strings.TrimSpace(*in.Name)
	}
	if in.Role != nil {
		role = *in.Role
	}
	if in.Address != nil {
		address = strings.TrimSpace(*in.Address)
	}
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	if name == "" || address == "" || (role != "transport" && role != "exit") {
		writeError(w, 400, "invalid node fields")
		return
	}
	_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE nodes SET name=?,role=?,address=?,enabled=? WHERE id=?`), name, role, address, enabled, id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	a.audit(r, "node.update", id)
	v, err = a.nodeRows(r.Context(), id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, v)
}
func (a *API) deleteNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := a.store.db.ExecContext(r.Context(), a.store.bind(`DELETE FROM nodes WHERE id=?`), id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeError(w, 404, "node not found")
		return
	}
	a.audit(r, "node.delete", id)
	w.WriteHeader(204)
}

func (a *API) issueSubscription(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	u, err := a.user(r.Context(), id)
	if err != nil {
		writeError(w, 404, "user not found")
		return
	}
	if !u.Enabled {
		writeError(w, 409, "disabled user cannot receive a subscription")
		return
	}
	token, err := randomToken(32)
	if err != nil {
		writeError(w, 500, "token generation failed")
		return
	}
	tx, err := a.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	_, _ = tx.ExecContext(r.Context(), a.store.bind(`UPDATE subscriptions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), nowText(), id)
	subID := newID()
	_, err = tx.ExecContext(r.Context(), a.store.bind(`INSERT INTO subscriptions(id,user_id,token_hash,created_at) VALUES(?,?,?,?)`), subID, id, hashToken(token), nowText())
	if err != nil {
		_ = tx.Rollback()
		writeError(w, 500, "subscription could not be issued")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "database error")
		return
	}
	link := a.publicURL + "/s/" + token
	qr, err := qrcode.Encode(link, qrcode.Medium, 256)
	if err != nil {
		writeError(w, 500, "QR generation failed")
		return
	}
	a.audit(r, "subscription.issue", subID)
	writeJSON(w, 201, map[string]any{"id": subID, "url": link, "qr_png_base64": base64.StdEncoding.EncodeToString(qr), "created_at": nowText()})
}
func (a *API) subscriptionProfile(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if len(token) < 32 || len(token) > 128 {
		writeError(w, 404, "subscription not found")
		return
	}
	var uid, revoked string
	err := a.store.db.QueryRowContext(r.Context(), a.store.bind(`SELECT user_id,COALESCE(revoked_at,'') FROM subscriptions WHERE token_hash=?`), hashToken(token)).Scan(&uid, &revoked)
	if err != nil || revoked != "" {
		writeError(w, 404, "subscription revoked or not found")
		return
	}
	u, err := a.user(r.Context(), uid)
	if err != nil || !u.Enabled {
		writeError(w, 410, "subscription disabled")
		return
	}
	pools, err := a.userPools(r.Context(), uid)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	if len(pools) == 0 {
		writeError(w, 410, "subscription has no enabled pool access")
		return
	}
	writeJSON(w, 200, map[string]any{"schema_version": 1, "user": u, "device_registration_url": a.publicURL + "/api/v1/device/register", "pools": publicPools(pools), "fetched_at": nowText()})
}
func (a *API) userPools(ctx context.Context, userID string) ([]poolDTO, error) {
	u, err := a.user(ctx, userID)
	if err != nil {
		return nil, err
	}
	var rows *sql.Rows
	if u.Source == "remnawave" {
		rows, err = a.store.db.QueryContext(ctx, a.store.bind(`SELECT DISTINCT p.id,p.name,p.strategy,p.enabled,p.mode,p.tcp_endpoint,p.forward_target FROM pools p JOIN squad_pools sp ON sp.pool_id=p.id JOIN user_squads us ON us.squad_uuid=sp.squad_uuid WHERE us.user_id=? AND p.enabled=TRUE ORDER BY p.name`), userID)
	} else {
		rows, err = a.store.db.QueryContext(ctx, `SELECT id,name,strategy,enabled,mode,tcp_endpoint,forward_target FROM pools WHERE enabled=TRUE ORDER BY name`)
	}
	if err != nil {
		return nil, err
	}
	out := []poolDTO{}
	for rows.Next() {
		var p poolDTO
		if err := rows.Scan(&p.ID, &p.Name, &p.Strategy, &p.Enabled, &p.Mode, &p.TCPEndpoint, &p.ForwardTarget); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	for i := range out {
		out[i].Documents, err = a.poolDocuments(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (a *API) deviceRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		SubscriptionToken string `json:"subscription_token"`
		Name              string `json:"name"`
		Platform          string `json:"platform"`
		DeviceID          string `json:"device_id"`
		Credential        string `json:"credential"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Platform = strings.ToLower(strings.TrimSpace(in.Platform))
	if in.Name == "" || len(in.Name) > 128 || in.SubscriptionToken == "" {
		writeError(w, 400, "subscription_token and device name are required")
		return
	}
	var uid string
	var revoked string
	err := a.store.db.QueryRowContext(r.Context(), a.store.bind(`SELECT user_id,COALESCE(revoked_at,'') FROM subscriptions WHERE token_hash=?`), hashToken(in.SubscriptionToken)).Scan(&uid, &revoked)
	if err != nil || revoked != "" {
		writeError(w, 403, "subscription invalid or revoked")
		return
	}
	u, err := a.user(r.Context(), uid)
	if err != nil || !u.Enabled {
		writeError(w, 403, "user disabled")
		return
	}
	credential := strings.TrimSpace(in.Credential)
	id := strings.TrimSpace(in.DeviceID)
	created := id == "" && credential == ""
	if !created && (id == "" || credential == "" || len(credential) != 64) {
		writeError(w, 403, "device credentials invalid or revoked")
		return
	}
	now := nowText()
	if created {
		credential, err = randomDeviceKey()
		if err != nil {
			writeError(w, 500, "credential generation failed")
			return
		}
		credentialCipher, err := a.store.encrypt([]byte(credential))
		if err != nil {
			writeError(w, 500, "credential encryption failed")
			return
		}
		id = newID()
		_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`INSERT INTO devices(id,user_id,name,platform,credential_hash,credential_cipher,created_at) VALUES(?,?,?,?,?,?,?)`), id, uid, in.Name, in.Platform, hashToken(credential), credentialCipher, now)
		if err != nil {
			writeError(w, 500, "device registration failed")
			return
		}
		a.audit(r, "device.register", id)
	} else {
		var deviceUser, savedHash string
		var deviceRevoked sql.NullString
		err = a.store.db.QueryRowContext(r.Context(), a.store.bind(`SELECT user_id,credential_hash,revoked_at FROM devices WHERE id=?`), id).Scan(&deviceUser, &savedHash, &deviceRevoked)
		if err != nil || deviceUser != uid || deviceRevoked.Valid || subtle.ConstantTimeCompare([]byte(savedHash), []byte(hashToken(credential))) != 1 {
			writeError(w, 403, "device credentials invalid or revoked")
			return
		}
		_, err = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE devices SET name=?,platform=?,last_seen=? WHERE id=?`), in.Name, in.Platform, now, id)
		if err != nil {
			writeError(w, 500, "device update failed")
			return
		}
	}
	pools, err := a.userPools(r.Context(), uid)
	if err != nil {
		writeError(w, 500, "profile generation failed")
		return
	}
	if len(pools) == 0 {
		writeError(w, 410, "subscription has no enabled pool access")
		return
	}
	configs := make([]map[string]any, 0, len(pools))
	for _, pool := range pools {
		config := map[string]any{"schema_version": 1, "mode": pool.Mode, "protocol_version": 2, "pool_id": pool.ID, "documents": pool.Documents, "client_id": id, "client_key": credential}
		if pool.Mode == "transport" {
			config["tcp_target"] = pool.TCPEndpoint
		}
		configs = append(configs, config)
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"device_id": id, "credential": credential, "credential_type": "openflux-pool-v2", "client_configs": configs, "created_at": now, "refreshed_at": now})
}
func (a *API) listDevices(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("id")
	if _, err := a.user(r.Context(), uid); err != nil {
		writeError(w, 404, "user not found")
		return
	}
	rows, err := a.store.db.QueryContext(r.Context(), a.store.bind(`SELECT id,name,platform,created_at,last_seen,revoked_at FROM devices WHERE user_id=? ORDER BY created_at DESC`), uid)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, platform, created string
		var last, revoked sql.NullString
		if err := rows.Scan(&id, &name, &platform, &created, &last, &revoked); err != nil {
			writeError(w, 500, "database error")
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "platform": platform, "created_at": created, "last_seen": nullable(last), "revoked_at": nullable(revoked)})
	}
	writeJSON(w, 200, map[string]any{"devices": items})
}
func (a *API) exportConfig(w http.ResponseWriter, r *http.Request) {
	u, err := a.user(r.Context(), r.PathValue("id"))
	if err != nil || !u.Enabled {
		writeError(w, 404, "active user not found")
		return
	}
	subToken, err := randomToken(32)
	if err != nil {
		writeError(w, 500, "token generation failed")
		return
	}
	subscriptionURL := a.publicURL + "/s/" + subToken
	deviceCred, err := randomDeviceKey()
	if err != nil {
		writeError(w, 500, "credential generation failed")
		return
	}
	deviceID := newID()
	now := nowText()
	tx, err := a.store.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	_, _ = tx.ExecContext(r.Context(), a.store.bind(`UPDATE subscriptions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL`), now, u.ID)
	_, err = tx.ExecContext(r.Context(), a.store.bind(`INSERT INTO subscriptions(id,user_id,token_hash,created_at) VALUES(?,?,?,?)`), newID(), u.ID, hashToken(subToken), now)
	if err == nil {
		var credCipher []byte
		credCipher, err = a.store.encrypt([]byte(deviceCred))
		if err == nil {
			_, err = tx.ExecContext(r.Context(), a.store.bind(`INSERT INTO devices(id,user_id,name,platform,credential_hash,credential_cipher,created_at) VALUES(?,?,?,?,?,?,?)`), deviceID, u.ID, "exported-config", "unknown", hashToken(deviceCred), credCipher, now)
		}
	}
	if err != nil {
		_ = tx.Rollback()
		writeError(w, 500, "config export failed")
		return
	}
	if err = tx.Commit(); err != nil {
		writeError(w, 500, "database error")
		return
	}
	pools, err := a.userPools(r.Context(), u.ID)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	a.audit(r, "config.export", u.ID)
	configs := make([]map[string]any, 0, len(pools))
	for _, pool := range pools {
		config := map[string]any{"schema_version": 1, "mode": pool.Mode, "protocol_version": 2, "pool_id": pool.ID, "documents": pool.Documents, "client_id": deviceID, "client_key": deviceCred}
		if pool.Mode == "transport" {
			config["tcp_target"] = pool.TCPEndpoint
		}
		configs = append(configs, config)
	}
	qrPayload, _ := json.Marshal(map[string]any{"schema_version": 1, "device_id": deviceID, "device_credential": deviceCred, "subscription_url": subscriptionURL, "client_configs": configs})
	qr, qrErr := qrcode.Encode(string(qrPayload), qrcode.Medium, 256)
	qrBase64, qrMessage := "", ""
	if qrErr != nil {
		qrMessage = "Configuration is too large for a QR code; import the JSON file instead"
	} else {
		qrBase64 = base64.StdEncoding.EncodeToString(qr)
	}
	writeJSON(w, 200, map[string]any{"schema_version": 1, "user_id": u.ID, "device_id": deviceID, "device_credential": deviceCred, "subscription_url": subscriptionURL, "qr_png_base64": qrBase64, "qr_error": qrMessage, "pools": publicPools(pools), "client_configs": configs, "created_at": now})
}

func (a *API) nodeAuth(w http.ResponseWriter, r *http.Request, id string) (map[string]any, bool) {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	var hash string
	var enabled bool
	err := a.store.db.QueryRowContext(r.Context(), a.store.bind(`SELECT token_hash,enabled FROM nodes WHERE id=?`), id).Scan(&hash, &enabled)
	if err != nil || !enabled || subtle.ConstantTimeCompare([]byte(hash), []byte(hashToken(got))) != 1 {
		writeError(w, 401, "invalid node token")
		return nil, false
	}
	v, err := a.nodeRows(r.Context(), id)
	if err != nil {
		writeError(w, 404, "node not found")
		return nil, false
	}
	return v, true
}
func (a *API) nodeConfig(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	node, ok := a.nodeAuth(w, r, id)
	if !ok {
		return
	}
	var version int64
	_ = a.store.db.QueryRowContext(r.Context(), `SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&version)
	includeClientKeys := node["role"] == "exit"
	pools, err := a.nodePoolValues(r.Context(), includeClientKeys)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	_, _ = a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE nodes SET last_seen=? WHERE id=?`), nowText(), id)
	writeJSON(w, 200, map[string]any{"version": version, "pools": pools, "generated_at": nowText()})
}

type nodeClientDTO struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Key      string `json:"client_key"`
}
type nodePoolDTO struct {
	poolDTO
	PoolID          string                    `json:"pool_id"`
	ProtocolVersion int                       `json:"protocol_version"`
	Forward         *yandex.PoolForwardConfig `json:"forward,omitempty"`
	Clients         []nodeClientDTO           `json:"clients"`
}

func (a *API) nodePoolValues(ctx context.Context, includeKeys bool) ([]nodePoolDTO, error) {
	pools, err := a.listPoolValues(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]nodePoolDTO, 0, len(pools))
	for _, p := range pools {
		n := nodePoolDTO{poolDTO: p, PoolID: p.ID, ProtocolVersion: 2, Clients: []nodeClientDTO{}}
		if p.Mode == "transport" {
			n.Forward = &yandex.PoolForwardConfig{VirtualEndpoint: p.TCPEndpoint, Target: p.ForwardTarget, Unmatched: "deny"}
		}
		if includeKeys {
			rows, err := a.store.db.QueryContext(ctx, a.store.bind(`SELECT d.id,u.id,u.username,d.credential_cipher FROM devices d JOIN users u ON u.id=d.user_id WHERE u.enabled=TRUE AND d.revoked_at IS NULL AND d.credential_cipher IS NOT NULL AND (u.source='local' OR EXISTS(SELECT 1 FROM user_squads us JOIN squad_pools sp ON sp.squad_uuid=us.squad_uuid WHERE us.user_id=u.id AND sp.pool_id=?)) ORDER BY u.username,d.created_at`), p.ID)
			if err != nil {
				return nil, err
			}
			for rows.Next() {
				var c nodeClientDTO
				var enc []byte
				if err := rows.Scan(&c.ID, &c.UserID, &c.Username, &enc); err != nil {
					_ = rows.Close()
					return nil, err
				}
				key, err := a.store.decrypt(enc)
				if err != nil {
					_ = rows.Close()
					return nil, err
				}
				c.Key = string(key)
				n.Clients = append(n.Clients, c)
			}
			if err := rows.Err(); err != nil {
				_ = rows.Close()
				return nil, err
			}
			_ = rows.Close()
		}
		out = append(out, n)
	}
	return out, nil
}

func (a *API) revokeDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	res, err := a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL`), nowText(), id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeError(w, 404, "active device not found")
		return
	}
	a.audit(r, "device.revoke", id)
	w.WriteHeader(http.StatusNoContent)
}
func (a *API) rotateDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	credential, err := randomDeviceKey()
	if err != nil {
		writeError(w, 500, "credential generation failed")
		return
	}
	enc, err := a.store.encrypt([]byte(credential))
	if err != nil {
		writeError(w, 500, "credential encryption failed")
		return
	}
	res, err := a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE devices SET credential_hash=?,credential_cipher=?,last_seen=NULL WHERE id=? AND revoked_at IS NULL`), hashToken(credential), enc, id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeError(w, 404, "active device not found")
		return
	}
	a.audit(r, "device.rotate", id)
	writeJSON(w, 200, map[string]string{"device_id": id, "credential": credential})
}

func (a *API) listPoolValues(ctx context.Context) ([]poolDTO, error) {
	rows, err := a.store.db.QueryContext(ctx, `SELECT id,name,strategy,enabled,mode,tcp_endpoint,forward_target FROM pools WHERE enabled=TRUE ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := []poolDTO{}
	for rows.Next() {
		var p poolDTO
		if err := rows.Scan(&p.ID, &p.Name, &p.Strategy, &p.Enabled, &p.Mode, &p.TCPEndpoint, &p.ForwardTarget); err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	_ = rows.Close()
	for i := range out {
		out[i].Documents, err = a.poolDocuments(ctx, out[i].ID)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
func (a *API) nodeAck(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := a.nodeAuth(w, r, id); !ok {
		return
	}
	var in struct {
		Version int64  `json:"version"`
		Error   string `json:"error"`
	}
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, 400, "invalid JSON")
		return
	}
	if len(in.Error) > 2048 {
		writeError(w, 400, "error too long")
		return
	}
	var current int64
	if err := a.store.db.QueryRowContext(r.Context(), `SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&current); err != nil {
		writeError(w, 500, "database error")
		return
	}
	if in.Version < 0 || in.Version > current {
		writeError(w, 400, "unknown config version")
		return
	}
	_, err := a.store.db.ExecContext(r.Context(), a.store.bind(`UPDATE nodes SET applied_version=CASE WHEN ?='' THEN ? ELSE applied_version END,apply_error=?,last_seen=? WHERE id=?`), in.Error, in.Version, in.Error, nowText(), id)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	writeJSON(w, 200, map[string]any{"acknowledged": in.Error == "", "version": in.Version})
}
func (a *API) auditList(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, e := strconv.Atoi(q); e == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	rows, err := a.store.db.QueryContext(r.Context(), a.store.bind(`SELECT actor,action,target,created_at FROM audit_log ORDER BY created_at DESC LIMIT ?`), limit)
	if err != nil {
		writeError(w, 500, "database error")
		return
	}
	defer rows.Close()
	items := []map[string]string{}
	for rows.Next() {
		var actor, action, target, at string
		if err := rows.Scan(&actor, &action, &target, &at); err != nil {
			writeError(w, 500, "database error")
			return
		}
		items = append(items, map[string]string{"actor": actor, "action": action, "target": target, "created_at": at})
	}
	writeJSON(w, 200, map[string]any{"events": items})
}
