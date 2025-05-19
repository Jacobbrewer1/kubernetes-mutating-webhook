package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net/http"

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
		// pemCert is the PEM certificate for the webhook.
		PemCert []byte

		// pemKey is the PEM key for the webhook.
		PemKey []byte

		PemCA []byte
	}

	// App is the main application struct.
	App struct {
		// base is the base web application.
		base *web.App

		// config is the application configuration.
		config *AppConfig

		// certPool is the certificate pool for the webhook.
		certPool *x509.CertPool
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
		base:     base,
		config:   cfg,
		certPool: x509.NewCertPool(),
	}, nil
}

// Start initializes the app and starts the base application.
func (a *App) Start() error {
	if err := a.base.Start(
		web.WithViperConfig(),
		web.WithConfigWatchers(func() {
			a.Shutdown()
		}),
		web.WithVaultClient(),
		web.WithInClusterKubeClient(),
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
	// Load the PEM certificate and key from the config.
	if a.config.PemCert == nil || a.config.PemKey == nil {
		return nil, fmt.Errorf("PEM certificate or key not found")
	}

	// Add the PEM certificate to the cert pool.
	if !a.certPool.AppendCertsFromPEM(a.config.PemCA) {
		return nil, fmt.Errorf("failed to append PEM certificate to cert pool")
	}

	tlsCert, err := tls.X509KeyPair(a.config.PemCert, a.config.PemKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load PEM certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    a.certPool,
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
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
}
