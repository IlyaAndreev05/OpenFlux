package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type client struct {
	base, token string
	http        *http.Client
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openfluxctl:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	fs := flag.NewFlagSet("openfluxctl", flag.ContinueOnError)
	base := fs.String("server", env("OPENFLUX_CONTROL_URL", "http://127.0.0.1:8787"), "Control API base URL")
	token := fs.String("token", os.Getenv("OPENFLUX_ADMIN_TOKEN"), "admin API token")
	asJSON := fs.Bool("json", false, "print machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("usage: openfluxctl [flags] users|documents|pools|nodes|subscription|config ...")
	}
	c := client{base: strings.TrimRight(*base, "/"), token: *token, http: &http.Client{Timeout: 20 * time.Second}}
	var method, path string
	var body any
	switch argv[0] {
	case "users":
		if len(argv) < 2 {
			return errors.New("users list|create NAME|show ID|update ID JSON|enable ID|disable ID|delete ID")
		}
		switch argv[1] {
		case "list":
			method, path = "GET", "/api/v1/users"
		case "create":
			if len(argv) != 3 {
				return errors.New("users create NAME")
			}
			method, path, body = "POST", "/api/v1/users", map[string]string{"username": argv[2]}
		case "show":
			if len(argv) != 3 {
				return errors.New("users show ID")
			}
			method, path = "GET", "/api/v1/users/"+argv[2]
		case "update":
			if len(argv) != 4 {
				return errors.New("users update ID JSON")
			}
			method, path = "PATCH", "/api/v1/users/"+argv[2]
			if err := json.Unmarshal([]byte(argv[3]), &body); err != nil {
				return errors.New("users update requires a JSON object")
			}
		case "enable", "disable":
			if len(argv) != 3 {
				return errors.New("users enable|disable ID")
			}
			v := argv[1] == "enable"
			method, path, body = "PATCH", "/api/v1/users/"+argv[2], map[string]bool{"enabled": v}
		case "delete":
			if len(argv) != 3 {
				return errors.New("users delete ID")
			}
			method, path = "DELETE", "/api/v1/users/"+argv[2]
		default:
			return errors.New("unknown users command")
		}
	case "documents":
		if len(argv) < 2 {
			return errors.New("documents list|show ID|create NAME URL|update ID JSON|delete ID")
		}
		switch argv[1] {
		case "list":
			method, path = "GET", "/api/v1/documents"
		case "show":
			if len(argv) != 3 {
				return errors.New("documents show ID")
			}
			method, path = "GET", "/api/v1/documents/"+argv[2]
		case "create":
			if len(argv) != 4 {
				return errors.New("documents create NAME URL")
			}
			method, path, body = "POST", "/api/v1/documents", map[string]string{"name": argv[2], "url": argv[3]}
		case "update":
			if len(argv) != 4 {
				return errors.New("documents update ID JSON")
			}
			method, path = "PUT", "/api/v1/documents/"+argv[2]
			if err := json.Unmarshal([]byte(argv[3]), &body); err != nil {
				return errors.New("documents update requires a JSON object")
			}
		case "delete":
			if len(argv) != 3 {
				return errors.New("documents delete ID")
			}
			method, path = "DELETE", "/api/v1/documents/"+argv[2]
		default:
			return errors.New("unknown documents command")
		}
	case "pools":
		if len(argv) < 2 {
			return errors.New("pools list|create NAME STRATEGY DOC_IDS [MODE TCP_ENDPOINT FORWARD_TARGET]|show ID|update ID JSON|delete ID")
		}
		switch argv[1] {
		case "list":
			method, path = "GET", "/api/v1/pools"
		case "show":
			if len(argv) != 3 {
				return errors.New("pools show ID")
			}
			method, path = "GET", "/api/v1/pools/"+argv[2]
		case "delete":
			if len(argv) != 3 {
				return errors.New("pools delete ID")
			}
			method, path = "DELETE", "/api/v1/pools/"+argv[2]
		case "update":
			if len(argv) != 4 {
				return errors.New("pools update ID JSON")
			}
			method, path = "PUT", "/api/v1/pools/"+argv[2]
			if err := json.Unmarshal([]byte(argv[3]), &body); err != nil {
				return errors.New("pools update requires a JSON object")
			}
		case "create":
			if len(argv) != 5 && len(argv) != 6 && len(argv) != 8 {
				return errors.New("pools create NAME STRATEGY DOC_IDS [MODE TCP_ENDPOINT FORWARD_TARGET]")
			}
			value := map[string]any{"name": argv[2], "strategy": argv[3], "document_ids": strings.Split(argv[4], ",")}
			if len(argv) >= 6 {
				value["mode"] = argv[5]
			}
			if len(argv) == 8 {
				value["tcp_endpoint"], value["forward_target"] = argv[6], argv[7]
			}
			method, path, body = "POST", "/api/v1/pools", value
		default:
			return errors.New("unknown pools command")
		}
	case "nodes":
		if len(argv) < 2 {
			return errors.New("nodes list|create NAME ROLE ADDRESS|show ID|update ID JSON|delete ID")
		}
		switch argv[1] {
		case "list":
			method, path = "GET", "/api/v1/nodes"
		case "show":
			if len(argv) != 3 {
				return errors.New("nodes show ID")
			}
			method, path = "GET", "/api/v1/nodes/"+argv[2]
		case "delete":
			if len(argv) != 3 {
				return errors.New("nodes delete ID")
			}
			method, path = "DELETE", "/api/v1/nodes/"+argv[2]
		case "update":
			if len(argv) != 4 {
				return errors.New("nodes update ID JSON")
			}
			method, path = "PUT", "/api/v1/nodes/"+argv[2]
			if err := json.Unmarshal([]byte(argv[3]), &body); err != nil {
				return errors.New("nodes update requires a JSON object")
			}
		case "create":
			if len(argv) != 5 {
				return errors.New("nodes create NAME ROLE ADDRESS")
			}
			method, path, body = "POST", "/api/v1/nodes", map[string]string{"name": argv[2], "role": argv[3], "address": argv[4]}
		default:
			return errors.New("unknown nodes command")
		}
	case "subscription":
		if len(argv) != 3 || argv[1] != "issue" {
			return errors.New("subscription issue USER_ID")
		}
		method, path = "POST", "/api/v1/users/"+argv[2]+"/subscription"
	case "config":
		if len(argv) != 3 || argv[1] != "export" {
			return errors.New("config export USER_ID")
		}
		method, path = "GET", "/api/v1/users/"+argv[2]+"/config"
	case "devices":
		if len(argv) < 2 {
			return errors.New("devices list USER_ID|revoke DEVICE_ID|rotate DEVICE_ID")
		}
		switch argv[1] {
		case "list":
			if len(argv) != 3 {
				return errors.New("devices list USER_ID")
			}
			method, path = "GET", "/api/v1/users/"+argv[2]+"/devices"
		case "revoke":
			if len(argv) != 3 {
				return errors.New("devices revoke DEVICE_ID")
			}
			method, path = "DELETE", "/api/v1/devices/"+argv[2]
		case "rotate":
			if len(argv) != 3 {
				return errors.New("devices rotate DEVICE_ID")
			}
			method, path = "POST", "/api/v1/devices/"+argv[2]+"/rotate"
		default:
			return errors.New("unknown devices command")
		}
	case "remnawave":
		if len(argv) != 2 || argv[1] != "sync" {
			return errors.New("remnawave sync")
		}
		method, path, body = "POST", "/api/v1/integrations/remnawave/sync", map[string]any{}
	case "squad-pools":
		if len(argv) < 2 {
			return errors.New("squad-pools list|set JSON")
		}
		switch argv[1] {
		case "list":
			method, path = "GET", "/api/v1/integrations/remnawave/squad-pools"
		case "set":
			if len(argv) != 3 {
				return errors.New("squad-pools set JSON")
			}
			method, path = "PUT", "/api/v1/integrations/remnawave/squad-pools"
			if err := json.Unmarshal([]byte(argv[2]), &body); err != nil {
				return errors.New("squad-pools set requires a JSON object")
			}
		default:
			return errors.New("unknown squad-pools command")
		}
	case "audit":
		method, path = "GET", "/api/v1/audit"
	default:
		return fmt.Errorf("unknown command %q", argv[0])
	}
	if c.token == "" {
		return errors.New("set OPENFLUX_ADMIN_TOKEN or --token")
	}
	result, status, err := c.request(method, path, body)
	if err != nil {
		return err
	}
	if status == http.StatusNoContent {
		fmt.Println("OK")
		return nil
	}
	if *asJSON {
		var pretty bytes.Buffer
		if err := json.Indent(&pretty, result, "", "  "); err == nil {
			fmt.Println(pretty.String())
			return nil
		}
		fmt.Println(string(result))
		return nil
	}
	return printResult(argv, result)
}
func (c client) request(method, path string, body any) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("API %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return b, resp.StatusCode, nil
}
func printResult(args []string, b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	if args[0] == "subscription" || args[0] == "config" {
		var out struct {
			URL             string `json:"url"`
			SubscriptionURL string `json:"subscription_url"`
			QR              string `json:"qr_png_base64"`
			QRError         string `json:"qr_error"`
		}
		_ = json.Unmarshal(b, &out)
		if out.URL == "" {
			out.URL = out.SubscriptionURL
		}
		if args[0] == "config" {
			var config map[string]any
			if err := json.Unmarshal(b, &config); err != nil {
				return err
			}
			fmt.Println("Subscription:", out.URL)
			delete(config, "qr_png_base64")
			pretty, _ := json.MarshalIndent(config, "", "  ")
			fmt.Println("Client config:")
			fmt.Println(string(pretty))
		} else {
			fmt.Println("Subscription:", out.URL)
		}
		if path := os.Getenv("OPENFLUX_QR_FILE"); path != "" {
			if out.QR == "" {
				return errors.New(out.QRError)
			}
			decoded, e := base64.StdEncoding.DecodeString(out.QR)
			if e != nil {
				return e
			}
			if e = os.WriteFile(path, decoded, 0600); e != nil {
				return e
			}
			fmt.Println("QR saved:", path)
			return nil
		}
		fmt.Println("QR PNG (base64):", out.QR)
		return nil
	}
	if args[0] == "nodes" && len(args) > 1 && args[1] == "create" {
		m := v.(map[string]any)
		fmt.Printf("Node %v created. Save this token now: %v\n", m["id"], m["token"])
		return nil
	}
	if printTable(v) {
		return nil
	}
	pretty, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(pretty))
	return nil
}

func printTable(value any) bool {
	root, ok := value.(map[string]any)
	if !ok {
		return false
	}
	var rows []any
	for _, key := range []string{"users", "documents", "pools", "nodes", "devices", "events", "mappings"} {
		if candidate, ok := root[key].([]any); ok {
			rows = candidate
			break
		}
	}
	if rows == nil {
		return false
	}
	if len(rows) == 0 {
		fmt.Println("No records.")
		return true
	}
	preferred := []string{"id", "username", "name", "source", "role", "platform", "enabled", "strategy", "mode", "tcp_endpoint", "forward_target", "last_seen", "applied_version", "config_version", "apply_error", "created_at", "action", "target", "squad_uuid", "pool_id"}
	first, ok := rows[0].(map[string]any)
	if !ok {
		return false
	}
	columns := make([]string, 0, len(preferred))
	for _, key := range preferred {
		if _, exists := first[key]; exists {
			columns = append(columns, key)
		}
	}
	if len(columns) == 0 {
		return false
	}
	w := new(tabwriter.Writer)
	w.Init(os.Stdout, 0, 4, 2, ' ', 0)
	for i, key := range columns {
		if i > 0 {
			fmt.Fprint(w, "\t")
		}
		fmt.Fprint(w, strings.ToUpper(key))
	}
	fmt.Fprintln(w)
	for _, row := range rows {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		for i, key := range columns {
			if i > 0 {
				fmt.Fprint(w, "\t")
			}
			value := m[key]
			if value == nil {
				fmt.Fprint(w, "-")
				continue
			}
			if key == "apply_error" {
				fmt.Fprint(w, strings.ReplaceAll(fmt.Sprint(value), "\n", " "))
				continue
			}
			fmt.Fprint(w, value)
		}
		fmt.Fprintln(w)
	}
	_ = w.Flush()
	return true
}
func env(k, d string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return d
}
