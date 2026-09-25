package control

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	dialect string
	key     [32]byte
}

func OpenStore(driver, dsn string, key [32]byte) (*Store, error) {
	driver = strings.ToLower(strings.TrimSpace(driver))
	if driver == "" || driver == "sqlite" || driver == "sqlite3" {
		driver = "sqlite"
		if strings.TrimSpace(dsn) == "" {
			dsn = "./data/openflux-control.db"
		}
		if dsn != ":memory:" && !strings.HasPrefix(dsn, "file:") {
			if err := os.MkdirAll(filepath.Dir(dsn), 0700); err != nil {
				return nil, fmt.Errorf("create database directory: %w", err)
			}
			f, err := os.OpenFile(dsn, os.O_CREATE|os.O_RDWR, 0600)
			if err != nil {
				return nil, fmt.Errorf("create SQLite database file: %w", err)
			}
			if err := f.Chmod(0600); err != nil {
				_ = f.Close()
				return nil, err
			}
			if err := f.Close(); err != nil {
				return nil, err
			}
		}
	} else if driver == "postgres" || driver == "postgresql" || driver == "pgx" {
		driver = "pgx"
		if strings.TrimSpace(dsn) == "" {
			return nil, errors.New("OPENFLUX_DATABASE_URL is required for PostgreSQL")
		}
	} else {
		return nil, fmt.Errorf("unsupported database driver %q", driver)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
		for _, pragma := range []string{"PRAGMA foreign_keys = ON", "PRAGMA busy_timeout = 5000", "PRAGMA journal_mode = WAL"} {
			if _, err := db.Exec(pragma); err != nil {
				_ = db.Close()
				return nil, fmt.Errorf("configure SQLite: %w", err)
			}
		}
	} else {
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(5)
		db.SetConnMaxLifetime(30 * time.Minute)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("connect database: %w", err)
	}
	s := &Store{db: db, dialect: driver, key: key}
	if err := s.migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) DB() *sql.DB  { return s.db }

func (s *Store) bind(query string) string {
	if s.dialect != "pgx" {
		return query
	}
	var out strings.Builder
	n := 0
	for _, r := range query {
		if r == '?' {
			n++
			fmt.Fprintf(&out, "$%d", n)
		} else {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func (s *Store) migrate(ctx context.Context) error {
	idType, blobType, boolType := "TEXT", "BLOB", "BOOLEAN"
	if s.dialect == "pgx" {
		blobType = "BYTEA"
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS users (id ` + idType + ` PRIMARY KEY, source TEXT NOT NULL CHECK(source IN ('local','remnawave')), external_id TEXT, username TEXT NOT NULL, enabled ` + boolType + ` NOT NULL DEFAULT TRUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(source, external_id))`,
		`CREATE TABLE IF NOT EXISTS devices (id ` + idType + ` PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, platform TEXT NOT NULL, credential_hash TEXT NOT NULL UNIQUE, credential_cipher ` + blobType + `, revoked_at TEXT, created_at TEXT NOT NULL, last_seen TEXT)`,
		`CREATE TABLE IF NOT EXISTS documents (id ` + idType + ` PRIMARY KEY, name TEXT NOT NULL, url_cipher ` + blobType + ` NOT NULL, enabled ` + boolType + ` NOT NULL DEFAULT TRUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS pools (id ` + idType + ` PRIMARY KEY, name TEXT NOT NULL, strategy TEXT NOT NULL, enabled ` + boolType + ` NOT NULL DEFAULT TRUE, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS pool_documents (pool_id TEXT NOT NULL REFERENCES pools(id) ON DELETE CASCADE, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE RESTRICT, position INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(pool_id, document_id))`,
		`CREATE TABLE IF NOT EXISTS nodes (id ` + idType + ` PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, address TEXT NOT NULL, token_hash TEXT NOT NULL, enabled ` + boolType + ` NOT NULL DEFAULT TRUE, config_version INTEGER NOT NULL DEFAULT 0, applied_version INTEGER NOT NULL DEFAULT 0, apply_error TEXT NOT NULL DEFAULT '', last_seen TEXT, created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS subscriptions (id ` + idType + ` PRIMARY KEY, user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, revoked_at TEXT, created_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS squad_pools (squad_uuid TEXT NOT NULL, pool_id TEXT NOT NULL REFERENCES pools(id) ON DELETE CASCADE, PRIMARY KEY(squad_uuid, pool_id))`,
		`CREATE TABLE IF NOT EXISTS user_squads (user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, squad_uuid TEXT NOT NULL, PRIMARY KEY(user_id, squad_uuid))`,
		`CREATE TABLE IF NOT EXISTS remnawave_settings (id INTEGER PRIMARY KEY, base_url TEXT NOT NULL, api_version TEXT NOT NULL DEFAULT 'v2', selected_squads TEXT NOT NULL DEFAULT '[]', enabled ` + boolType + ` NOT NULL DEFAULT FALSE, token_cipher ` + blobType + ` NOT NULL, webhook_secret_cipher ` + blobType + ` NOT NULL, last_sync TEXT, last_error TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS remnawave_events (event_id TEXT PRIMARY KEY, received_at TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS audit_log (id ` + idType + ` PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL)`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("apply control schema: %w", err)
		}
	}
	// Migration 2 extends Remnawave settings without requiring database resets.
	columns := map[string]string{
		"api_version":     "TEXT NOT NULL DEFAULT 'v2'",
		"selected_squads": "TEXT NOT NULL DEFAULT '[]'",
		"enabled":         boolType + " NOT NULL DEFAULT FALSE",
		"last_sync":       "TEXT",
		"last_error":      "TEXT NOT NULL DEFAULT ''",
	}
	for name, definition := range columns {
		exists, err := s.hasColumn(ctx, "remnawave_settings", name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.ExecContext(ctx, `ALTER TABLE remnawave_settings ADD COLUMN `+name+` `+definition); err != nil {
				return fmt.Errorf("migrate Remnawave settings column %s: %w", name, err)
			}
		}
	}
	exists, err := s.hasColumn(ctx, "devices", "credential_cipher")
	if err != nil {
		return err
	}
	if !exists {
		if _, err := s.db.ExecContext(ctx, `ALTER TABLE devices ADD COLUMN credential_cipher `+blobType); err != nil {
			return fmt.Errorf("migrate encrypted device credentials: %w", err)
		}
	}
	poolColumns := map[string]string{
		"mode":           "TEXT NOT NULL DEFAULT 'standalone'",
		"tcp_endpoint":   "TEXT NOT NULL DEFAULT ''",
		"forward_target": "TEXT NOT NULL DEFAULT ''",
	}
	for name, definition := range poolColumns {
		exists, err := s.hasColumn(ctx, "pools", name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := s.db.ExecContext(ctx, `ALTER TABLE pools ADD COLUMN `+name+` `+definition); err != nil {
				return fmt.Errorf("migrate pool %s column: %w", name, err)
			}
		}
	}
	for _, version := range []int{1, 2, 3, 4} {
		if _, err := s.db.ExecContext(ctx, s.bind(`INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?) ON CONFLICT(version) DO NOTHING`), version, nowText()); err != nil {
			return fmt.Errorf("record migration %d: %w", version, err)
		}
	}
	_, _ = s.db.ExecContext(ctx, s.bind(`INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO NOTHING`), "config_version", "1")
	return nil
}

func (s *Store) hasColumn(ctx context.Context, table, column string) (bool, error) {
	if s.dialect == "sqlite" {
		rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, typ string
			var notnull, pk int
			var defaultValue any
			if err := rows.Scan(&cid, &name, &typ, &notnull, &defaultValue, &pk); err != nil {
				return false, err
			}
			if name == column {
				return true, nil
			}
		}
		return false, rows.Err()
	}
	var exists bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2)`, table, column).Scan(&exists)
	return exists, err
}

func nowText() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func hashToken(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *Store) encrypt(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, []byte("openflux-control-v1")), nil
}

func (s *Store) decrypt(value []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(value) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("encrypted value is truncated")
	}
	nonce := value[:aead.NonceSize()]
	return aead.Open(nil, nonce, value[aead.NonceSize():], []byte("openflux-control-v1"))
}

func loadInstallKey(path, encoded string) ([32]byte, error) {
	var key [32]byte
	encoded = strings.TrimSpace(encoded)
	if encoded != "" {
		b, err := hex.DecodeString(encoded)
		if err != nil || len(b) != len(key) {
			return key, errors.New("OPENFLUX_INSTALLATION_KEY must be 64 hex characters")
		}
		copy(key[:], b)
		return key, nil
	}
	if path == "" {
		path = "./data/installation.key"
	}
	if b, err := os.ReadFile(path); err == nil {
		if len(b) != len(key) {
			return key, errors.New("installation key file must contain exactly 32 bytes")
		}
		copy(key[:], b)
		return key, nil
	} else if !os.IsNotExist(err) {
		return key, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return key, err
	}
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return key, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return key, err
	}
	if _, err := f.Write(key[:]); err != nil {
		_ = f.Close()
		return key, err
	}
	if err := f.Close(); err != nil {
		return key, err
	}
	return key, nil
}

func newID() string { return uuid.NewString() }

// LoadInstallationKey loads the encryption key from OPENFLUX_INSTALLATION_KEY
// or creates a private 0600 key file for a single-node installation.
func LoadInstallationKey(path, encoded string) ([32]byte, error) {
	return loadInstallKey(path, encoded)
}

func randomDeviceKey() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
