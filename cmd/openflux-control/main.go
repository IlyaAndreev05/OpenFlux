package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"openflux/internal/control"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	driver := strings.TrimSpace(os.Getenv("OPENFLUX_DB_DRIVER"))
	dsn := strings.TrimSpace(os.Getenv("OPENFLUX_DATABASE_URL"))
	if driver == "" {
		driver = "sqlite"
	}
	if driver == "sqlite" && dsn == "" {
		dsn = valueOr("OPENFLUX_SQLITE_PATH", "./data/openflux-control.db")
	}
	key, err := control.LoadInstallationKey(valueOr("OPENFLUX_INSTALLATION_KEY_FILE", "./data/installation.key"), os.Getenv("OPENFLUX_INSTALLATION_KEY"))
	if err != nil {
		return err
	}
	store, err := control.OpenStore(driver, dsn, key)
	if err != nil {
		return err
	}
	defer store.Close()
	api, err := control.NewAPI(store, os.Getenv("OPENFLUX_ADMIN_TOKEN"), os.Getenv("OPENFLUX_PUBLIC_URL"))
	if err != nil {
		return err
	}
	reconcilerCtx, cancelReconciler := context.WithCancel(context.Background())
	defer cancelReconciler()
	go api.RunRemnawaveReconciler(reconcilerCtx)
	addr := valueOr("OPENFLUX_CONTROL_ADDR", ":8787")
	srv := &http.Server{Addr: addr, Handler: api, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	stopCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { log.Printf("OpenFlux Control listening on %s", addr); result <- srv.ListenAndServe() }()
	select {
	case <-stopCtx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func valueOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
