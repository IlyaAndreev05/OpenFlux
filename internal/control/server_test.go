package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func newControlTestAPI(t *testing.T) (*Store, *API, [32]byte) {
	t.Helper()
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := OpenStore("sqlite", ":memory:", key)
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPI(store, "admin-test-secret", "https://of.example")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, api, key
}

func request(t *testing.T, api http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	return w
}
func decodeMap(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response %q: %v", w.Body.String(), err)
	}
	return v
}

func TestControlUsersSubscriptionsDevicesAndRevocation(t *testing.T) {
	store, api, _ := newControlTestAPI(t)
	if got := request(t, api, "GET", "/api/v1/users", "", nil).Code; got != 401 {
		t.Fatalf("unauthorized status=%d", got)
	}
	w := request(t, api, "POST", "/api/v1/users", "admin-test-secret", map[string]string{"username": "alice"})
	if w.Code != 201 {
		t.Fatalf("create user=%d %s", w.Code, w.Body.String())
	}
	u := decodeMap(t, w)
	id := u["id"].(string)
	// Locally managed users can use every enabled pool. A subscription without
	// any enabled pool must be rejected, so provision one for this happy path.
	w = request(t, api, "POST", "/api/v1/documents", "admin-test-secret", map[string]string{
		"name": "test document",
		"url":  "https://example.com/subscription",
	})
	if w.Code != 201 {
		t.Fatalf("create document=%d %s", w.Code, w.Body.String())
	}
	documentID := decodeMap(t, w)["id"].(string)
	w = request(t, api, "POST", "/api/v1/pools", "admin-test-secret", map[string]any{
		"name":         "test pool",
		"document_ids": []string{documentID},
	})
	if w.Code != 201 {
		t.Fatalf("create pool=%d %s", w.Code, w.Body.String())
	}
	w = request(t, api, "POST", "/api/v1/users/"+id+"/subscription", "admin-test-secret", map[string]string{})
	if w.Code != 201 {
		t.Fatalf("issue subscription=%d %s", w.Code, w.Body.String())
	}
	sub := decodeMap(t, w)
	token := strings.TrimPrefix(sub["url"].(string), "https://of.example/s/")
	var versionBefore, versionAfter int64
	if err := store.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&versionBefore); err != nil {
		t.Fatal(err)
	}
	png, err := base64.StdEncoding.DecodeString(sub["qr_png_base64"].(string))
	if err != nil || len(png) < 100 {
		t.Fatalf("QR invalid: %v bytes=%d", err, len(png))
	}
	w = request(t, api, "GET", "/s/"+token, "", nil)
	if w.Code != 200 {
		t.Fatalf("fetch subscription=%d %s", w.Code, w.Body.String())
	}
	w = request(t, api, "POST", "/api/v1/device/register", "", map[string]string{"subscription_token": token, "name": "Pixel 9", "platform": "android"})
	if w.Code != 201 {
		t.Fatalf("register device=%d %s", w.Code, w.Body.String())
	}
	device := decodeMap(t, w)
	credential := device["credential"].(string)
	if credential == "" {
		t.Fatal("device credential missing")
	}
	if err := store.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&versionAfter); err != nil || versionAfter != versionBefore+1 {
		t.Fatalf("device registration config version=%d (before %d), err=%v", versionAfter, versionBefore, err)
	}
	var stored string
	if err := store.db.QueryRowContext(context.Background(), `SELECT credential_hash FROM devices WHERE id=?`, device["device_id"]).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == credential {
		t.Fatal("raw credential was stored in the database")
	}
	w = request(t, api, "POST", "/api/v1/device/register", "", map[string]string{"subscription_token": token, "device_id": device["device_id"].(string), "credential": credential, "name": "Pixel 9 renamed", "platform": "android"})
	if w.Code != 200 || decodeMap(t, w)["device_id"] != device["device_id"] {
		t.Fatalf("device refresh was not idempotent: %d %s", w.Code, w.Body.String())
	}
	var deviceCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM devices WHERE user_id=?`, id).Scan(&deviceCount); err != nil || deviceCount != 1 {
		t.Fatalf("device refresh created duplicate devices: count=%d err=%v", deviceCount, err)
	}
	if err := store.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM settings WHERE key='config_version'`).Scan(&versionAfter); err != nil || versionAfter != versionBefore+1 {
		t.Fatalf("device refresh unexpectedly changed node config version: %d, err=%v", versionAfter, err)
	}
	w = request(t, api, "POST", "/api/v1/device/register", "", map[string]string{"subscription_token": token, "device_id": device["device_id"].(string), "credential": strings.Repeat("0", 64), "name": "forged", "platform": "android"})
	if w.Code != 403 {
		t.Fatalf("forged device credential status=%d", w.Code)
	}
	w = request(t, api, "PATCH", "/api/v1/users/"+id, "admin-test-secret", map[string]bool{"enabled": false})
	if w.Code != 200 {
		t.Fatalf("disable user=%d %s", w.Code, w.Body.String())
	}
	if got := request(t, api, "GET", "/s/"+token, "", nil).Code; got != 404 {
		t.Fatalf("revoked subscription status=%d", got)
	}
	if got := request(t, api, "POST", "/api/v1/device/register", "", map[string]string{"subscription_token": token, "name": "second"}).Code; got != 403 {
		t.Fatalf("revoked device registration status=%d", got)
	}
	var events int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&events); err != nil || events < 3 {
		t.Fatalf("audit events=%d err=%v", events, err)
	}
}

func TestControlEncryptedDocumentsPoolsAndNodeConfig(t *testing.T) {
	store, api, _ := newControlTestAPI(t)
	w := request(t, api, "POST", "/api/v1/users", "admin-test-secret", map[string]string{"username": "bob"})
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	user := decodeMap(t, w)
	userID := user["id"].(string)
	w = request(t, api, "POST", "/api/v1/users/"+userID+"/subscription", "admin-test-secret", map[string]string{})
	if w.Code != 201 {
		t.Fatalf("issue subscription=%d %s", w.Code, w.Body.String())
	}
	subToken := strings.TrimPrefix(decodeMap(t, w)["url"].(string), "https://of.example/s/")
	if profile := request(t, api, "GET", "/s/"+subToken, "", nil); profile.Code != 410 {
		t.Fatalf("subscription without pool access should be explicitly blocked: %d %s", profile.Code, profile.Body.String())
	}

	w = request(t, api, "POST", "/api/v1/documents", "admin-test-secret", map[string]string{"name": "doc-a", "url": "https://disk.yandex.ru/i/opaque"})
	if w.Code != 201 {
		t.Fatalf("create document=%d %s", w.Code, w.Body.String())
	}
	doc := decodeMap(t, w)
	var encrypted []byte
	if err := store.db.QueryRow(`SELECT url_cipher FROM documents WHERE id=?`, doc["id"]).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted, []byte("disk.yandex.ru")) {
		t.Fatal("document URL is stored in plaintext")
	}
	w = request(t, api, "POST", "/api/v1/pools", "admin-test-secret", map[string]any{"name": "primary", "strategy": "least-loaded", "document_ids": []string{doc["id"].(string)}})
	if w.Code != 201 {
		t.Fatalf("create pool=%d %s", w.Code, w.Body.String())
	}
	if profile := request(t, api, "GET", "/s/"+subToken, "", nil); profile.Code != 200 {
		t.Fatalf("subscription with an enabled pool should be available: %d %s", profile.Code, profile.Body.String())
	}
	w = request(t, api, "POST", "/api/v1/device/register", "", map[string]string{"subscription_token": subToken, "name": "desktop", "platform": "linux"})
	if w.Code != 201 {
		t.Fatalf("register device=%d %s", w.Code, w.Body.String())
	}
	device := decodeMap(t, w)
	deviceID := device["device_id"].(string)
	clientKey := device["credential"].(string)
	var cipherBytes []byte
	if err := store.db.QueryRow(`SELECT credential_cipher FROM devices WHERE id=?`, deviceID).Scan(&cipherBytes); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipherBytes, []byte(clientKey)) {
		t.Fatal("device client key is stored in plaintext")
	}
	configs := device["client_configs"].([]any)
	if len(configs) != 1 || configs[0].(map[string]any)["client_key"] != clientKey {
		t.Fatalf("device client config missing key: %#v", configs)
	}
	w = request(t, api, "POST", "/api/v1/nodes", "admin-test-secret", map[string]string{"name": "exit-a", "role": "exit", "address": "exit.example:8443"})
	if w.Code != 201 {
		t.Fatalf("create node=%d %s", w.Code, w.Body.String())
	}
	node := decodeMap(t, w)
	token := node["token"].(string)
	w = request(t, api, "GET", "/api/v1/nodes/"+node["id"].(string), "admin-test-secret", nil)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if bytes.Contains(w.Body.Bytes(), []byte(token)) {
		t.Fatal("node API leaked saved token")
	}
	req := httptest.NewRequest("GET", "/api/v1/nodes/"+node["id"].(string)+"/config", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("node config=%d %s", w.Code, w.Body.String())
	}
	cfg := decodeMap(t, w)
	if cfg["version"].(float64) < 1 {
		t.Fatalf("config version not initialized: %#v", cfg)
	}
	poolConfigs := cfg["pools"].([]any)
	if len(poolConfigs) != 1 {
		t.Fatalf("node pools=%#v", poolConfigs)
	}
	clients := poolConfigs[0].(map[string]any)["clients"].([]any)
	if len(clients) != 1 || clients[0].(map[string]any)["client_key"] != clientKey {
		t.Fatalf("exit node missing active per-device key: %#v", clients)
	}
	transportNode := request(t, api, "POST", "/api/v1/nodes", "admin-test-secret", map[string]string{"name": "transport-a", "role": "transport", "address": "transport.example:8443"})
	if transportNode.Code != 201 {
		t.Fatalf("create transport node=%d %s", transportNode.Code, transportNode.Body.String())
	}
	node2 := decodeMap(t, transportNode)
	req2 := httptest.NewRequest("GET", "/api/v1/nodes/"+node2["id"].(string)+"/config", nil)
	req2.Header.Set("Authorization", "Bearer "+node2["token"].(string))
	w2 := httptest.NewRecorder()
	api.ServeHTTP(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("transport node config=%d %s", w2.Code, w2.Body.String())
	}
	transportPools := decodeMap(t, w2)["pools"].([]any)
	if got := len(transportPools[0].(map[string]any)["clients"].([]any)); got != 0 {
		t.Fatalf("non-exit node received client secrets: %d", got)
	}
	desiredVersion := int64(cfg["version"].(float64))
	ackPath := "/api/v1/nodes/" + node["id"].(string) + "/ack"
	ackReq := httptest.NewRequest("POST", ackPath, strings.NewReader(`{"version":`+strconv.FormatInt(desiredVersion, 10)+`,"error":"simulated invalid config"}`))
	ackReq.Header.Set("Authorization", "Bearer "+token)
	ackReq.Header.Set("Content-Type", "application/json")
	ackRes := httptest.NewRecorder()
	api.ServeHTTP(ackRes, ackReq)
	if ackRes.Code != 200 || decodeMap(t, ackRes)["acknowledged"] != false {
		t.Fatalf("failed apply was acknowledged as success: %d %s", ackRes.Code, ackRes.Body.String())
	}
	failedStatus := request(t, api, "GET", "/api/v1/nodes/"+node["id"].(string), "admin-test-secret", nil)
	failedNode := decodeMap(t, failedStatus)
	if failedNode["applied_version"].(float64) != 0 || failedNode["apply_error"] != "simulated invalid config" {
		t.Fatalf("failed apply status incorrect: %#v", failedNode)
	}
	ackReq = httptest.NewRequest("POST", ackPath, strings.NewReader(`{"version":`+strconv.FormatInt(desiredVersion, 10)+`,"error":""}`))
	ackReq.Header.Set("Authorization", "Bearer "+token)
	ackReq.Header.Set("Content-Type", "application/json")
	ackRes = httptest.NewRecorder()
	api.ServeHTTP(ackRes, ackReq)
	if ackRes.Code != 200 || decodeMap(t, ackRes)["acknowledged"] != true {
		t.Fatalf("successful config apply was not acknowledged: %d %s", ackRes.Code, ackRes.Body.String())
	}
	successStatus := decodeMap(t, request(t, api, "GET", "/api/v1/nodes/"+node["id"].(string), "admin-test-secret", nil))
	if successStatus["applied_version"].(float64) != float64(desiredVersion) || successStatus["apply_error"] != "" {
		t.Fatalf("successful apply status incorrect: %#v", successStatus)
	}
	w = request(t, api, "DELETE", "/api/v1/devices/"+deviceID, "admin-test-secret", nil)
	if w.Code != 204 {
		t.Fatalf("revoke device=%d %s", w.Code, w.Body.String())
	}
	w = request(t, api, "PUT", "/api/v1/documents/"+doc["id"].(string), "admin-test-secret", map[string]any{"enabled": false})
	if w.Code != 409 {
		t.Fatalf("disabled last working document without confirmation: %d %s", w.Code, w.Body.String())
	}
	w = request(t, api, "PUT", "/api/v1/documents/"+doc["id"].(string), "admin-test-secret", map[string]any{"enabled": false, "confirm_last_working_removal": true})
	if w.Code != 200 {
		t.Fatalf("explicitly confirmed last-document removal: %d %s", w.Code, w.Body.String())
	}
	qrUser := request(t, api, "POST", "/api/v1/users", "admin-test-secret", map[string]string{"username": "qr-user"})
	qrUserID := decodeMap(t, qrUser)["id"].(string)
	exported := request(t, api, "GET", "/api/v1/users/"+qrUserID+"/config", "admin-test-secret", nil)
	if exported.Code != 200 {
		t.Fatalf("config export=%d %s", exported.Code, exported.Body.String())
	}
	exportValue := decodeMap(t, exported)
	if !strings.Contains(exportValue["subscription_url"].(string), "/s/") {
		t.Fatalf("config export has no subscription URL: %#v", exportValue)
	}
	png, err := base64.StdEncoding.DecodeString(exportValue["qr_png_base64"].(string))
	if err != nil || len(png) < 8 || !bytes.Equal(png[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}) {
		t.Fatalf("config export QR is not a PNG: len=%d err=%v", len(png), err)
	}
}

func TestTransportPoolExposesOnlyClientRouteAndConfiguresExitXrayForward(t *testing.T) {
	_, api, _ := newControlTestAPI(t)
	userRes := request(t, api, "POST", "/api/v1/users", "admin-test-secret", map[string]string{"username": "happ-user"})
	if userRes.Code != http.StatusCreated {
		t.Fatal(userRes.Body.String())
	}
	userID := decodeMap(t, userRes)["id"].(string)
	subRes := request(t, api, "POST", "/api/v1/users/"+userID+"/subscription", "admin-test-secret", map[string]string{})
	if subRes.Code != http.StatusCreated {
		t.Fatal(subRes.Body.String())
	}
	subscriptionToken := strings.TrimPrefix(decodeMap(t, subRes)["url"].(string), "https://of.example/s/")
	docRes := request(t, api, "POST", "/api/v1/documents", "admin-test-secret", map[string]string{"name": "transport-doc", "url": "https://example.invalid/shared-document"})
	if docRes.Code != http.StatusCreated {
		t.Fatal(docRes.Body.String())
	}
	docID := decodeMap(t, docRes)["id"].(string)
	poolRes := request(t, api, "POST", "/api/v1/pools", "admin-test-secret", map[string]any{
		"name": "remna-xray", "strategy": "least-loaded", "mode": "transport",
		"tcp_endpoint": "10.255.0.1:19000", "forward_target": "remnanode:19000", "document_ids": []string{docID},
	})
	if poolRes.Code != http.StatusCreated {
		t.Fatalf("create transport pool: %d %s", poolRes.Code, poolRes.Body.String())
	}
	profileRes := request(t, api, "GET", "/s/"+subscriptionToken, "", nil)
	if profileRes.Code != http.StatusOK {
		t.Fatalf("subscription profile: %d %s", profileRes.Code, profileRes.Body.String())
	}
	profile := decodeMap(t, profileRes)
	pool := profile["pools"].([]any)[0].(map[string]any)
	if pool["mode"] != "transport" || pool["tcp_endpoint"] != "10.255.0.1:19000" {
		t.Fatalf("transport profile missing localhost route target: %#v", pool)
	}
	if strings.Contains(profileRes.Body.String(), "forward_target") || strings.Contains(profileRes.Body.String(), "remnanode:19000") {
		t.Fatal("public subscription disclosed the private Xray target")
	}
	deviceRes := request(t, api, "POST", "/api/v1/device/register", "", map[string]string{"subscription_token": subscriptionToken, "name": "Happ phone", "platform": "android"})
	if deviceRes.Code != http.StatusCreated {
		t.Fatalf("register transport client: %d %s", deviceRes.Code, deviceRes.Body.String())
	}
	deviceConfig := decodeMap(t, deviceRes)["client_configs"].([]any)[0].(map[string]any)
	if deviceConfig["mode"] != "transport" || deviceConfig["tcp_target"] != "10.255.0.1:19000" {
		t.Fatalf("client config missing Happ transport route: %#v", deviceConfig)
	}
	nodeRes := request(t, api, "POST", "/api/v1/nodes", "admin-test-secret", map[string]string{"name": "exit", "role": "exit", "address": "exit.example:443"})
	if nodeRes.Code != http.StatusCreated {
		t.Fatal(nodeRes.Body.String())
	}
	node := decodeMap(t, nodeRes)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes/"+node["id"].(string)+"/config", nil)
	req.Header.Set("Authorization", "Bearer "+node["token"].(string))
	w := httptest.NewRecorder()
	api.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("exit config: %d %s", w.Code, w.Body.String())
	}
	exitPool := decodeMap(t, w)["pools"].([]any)[0].(map[string]any)
	forward := exitPool["forward"].(map[string]any)
	if forward["virtual_endpoint"] != "10.255.0.1:19000" || forward["target"] != "remnanode:19000" || forward["unmatched"] != "deny" {
		t.Fatalf("exit node missing deny-by-default Xray forwarding: %#v", forward)
	}
}

func TestEmbeddedOpenAPIIsValidJSON(t *testing.T) {
	if !json.Valid(openAPISpec) {
		t.Fatal("embedded OpenAPI document is not valid JSON")
	}
	var spec struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/device/register", "/api/v1/integrations/remnawave/webhook", "/api/v1/nodes/{id}/ack"} {
		if len(spec.Paths[path]) == 0 {
			t.Fatalf("OpenAPI is missing path %s", path)
		}
	}
}
