// Command protosource-auth runs the shadow-token authentication and
// authorization service.
//
// Configuration is read from environment variables — see the app package
// for the full list. At minimum set:
//
//	PROTOSOURCE_AUTH_LOCAL_MASTER_KEY   base64(32 random bytes)
//	PROTOSOURCE_AUTH_ISSUER_ISS         JWT "iss" claim (e.g. https://auth.example.com)
//
// Optional:
//
//	PROTOSOURCE_AUTH_LISTEN_ADDR        default ":8080"
//	PROTOSOURCE_AUTH_BOOTSTRAP_EMAIL    creates an admin user on startup
//	PROTOSOURCE_AUTH_BOOTSTRAP_PASSWORD (required when BOOTSTRAP_EMAIL is set)
//
// Phase 7 uses memorystore — state is lost on process exit and startup
// bootstrap runs every time.
package main

import (
	"context"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/funinthecloud/protosource-auth/app"
)

func main() {
	cfg, err := app.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	instance, err := app.Run(ctx, cfg)
	if err != nil {
		log.Fatalf("run: %v", err)
	}
	defer func() {
		if err := instance.Close(); err != nil {
			log.Printf("close: %v", err)
		}
	}()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           instance.Handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown: %v", err)
		}
	}()

	log.Printf("protosource-auth listening on %s (issuer=%s)", cfg.ListenAddr, cfg.IssuerIss)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("listen: %v", err)
	}
	log.Println("server stopped")
}
