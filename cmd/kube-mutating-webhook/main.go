package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jacobbrewer1/web"
	"github.com/jacobbrewer1/web/logging"
)

const (
	// appName is the name of the application.
	appName = "kube-mutating-webhook"
)

type (
	// AppConfig is the configuration for the app.
	AppConfig struct {
		// activeCert is the current active certificate.
		activeCert atomic.Value
	}

	// App is the main application struct.
	App struct {
		// base is the base web application.
		base *web.App

		// config is the application configuration.
		config *AppConfig
	}
)

// NewApp creates a new App instance with the given logger.
func NewApp(l *slog.Logger) (*App, error) {
	base, err := web.NewApp(l)
	if err != nil {
		return nil, fmt.Errorf("failed to create base app: %w", err)
	}

	cfg := new(AppConfig)

	return &App{
		base:   base,
		config: cfg,
	}, nil
}

// Start initializes the app and starts the base application.
func (a *App) Start() error {
	if err := a.base.Start(
		web.WithViperConfig(),
		web.WithConfigWatchers(func() {
			a.Shutdown()
		}),
		web.WithIndefiniteAsyncTask("reload-pem", a.waitForPemExpiry(logging.LoggerWithComponent(a.base.Logger(), "reload-pem"))),
	); err != nil {
		return fmt.Errorf("failed to start base app: %w", err)
	}

	server, err := a.buildSecureServer()
	if err != nil {
		return fmt.Errorf("failed to build secure server: %w", err)
	}

	if err := a.base.StartServer("webhook-server", server); err != nil {
		return fmt.Errorf("failed to start webhook server: %w", err)
	}

	return nil
}

func (a *App) buildSecureServer() (*http.Server, error) {
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Is the current certificate still valid?
			activeCertVal := a.config.activeCert.Load()
			if activeCertVal == nil {
				return nil, errors.New("no active certificate found")
			}

			activeCert, ok := activeCertVal.(*tls.Certificate)
			if !ok {
				return nil, errors.New("failed to cast active certificate")
			}

			return activeCert, nil
		},
		MinVersion: tls.VersionTLS13,
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
		Handler: func() http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) {
				a.base.Logger().Debug("received request")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("Hello, world!"))
			}
		}(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	return server, nil
}

// WaitForEnd waits for the application to finish.
func (a *App) WaitForEnd() {
	a.base.WaitForEnd(a.Shutdown)
}

// Shutdown is called to shut down all running services.
func (a *App) Shutdown() {
	a.base.Shutdown()
}

func main() {
	l := logging.NewLogger(
		logging.WithAppName(appName),
	)

	app, err := NewApp(l)
	if err != nil {
		panic(fmt.Errorf("failed to create app: %w", err))
	}

	if err := app.Start(); err != nil {
		panic(fmt.Errorf("failed to start app: %w", err))
	}

	app.WaitForEnd()
}
