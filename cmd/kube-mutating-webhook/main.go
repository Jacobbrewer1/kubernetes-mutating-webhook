package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/jacobbrewer1/kubernetes-mutating-webhook/cmd/kube-mutating-webhook/api/openapi"
	"github.com/jacobbrewer1/kubernetes-mutating-webhook/cmd/kube-mutating-webhook/service"
	"github.com/jacobbrewer1/web"
	"github.com/jacobbrewer1/web/k8s"
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
	var apiServer *http.Server
	if err := a.base.Start(
		web.WithViperConfig(),
		web.WithConfigWatchers(func() {
			a.Shutdown()
		}),
		web.WithIndefiniteAsyncTask("reload-pem", a.waitForPemExpiry(logging.LoggerWithComponent(a.base.Logger(), "reload-pem"))),
		web.WithInClusterKubeClient(),
		web.WithDependencyBootstrap(func(ctx context.Context) (err error) {
			apiServer, err = a.buildSecureServer()
			if err != nil {
				return fmt.Errorf("failed to build secure server: %w", err)
			}
			apiService := service.NewService(logging.LoggerWithComponent(a.base.Logger(), "api-service"))

			r := mux.NewRouter()
			openapi.RegisterUnauthedHandlers(r, apiService,
				openapi.WithLogger(logging.LoggerWithComponent(a.base.Logger(), "openapi")),
			)
			apiServer.Handler = r
			return nil
		}),
		web.WithDependencyBootstrap(func(ctx context.Context) (err error) {
			timeoutCtx, cancel := a.base.TimeoutContext(60 * time.Second)
			defer cancel()

			webhook, err := a.base.KubeClient().AdmissionregistrationV1().MutatingWebhookConfigurations().Get(timeoutCtx, appName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get webhook configuration: %w", err)
			}

			activeCertVal := a.config.activeCert.Load()
			if activeCertVal == nil {
				return errors.New("no active certificate found")
			}

			activeCert, ok := activeCertVal.(*tls.Certificate)
			if !ok {
				return errors.New("failed to cast active certificate")
			}

			w := bytes.NewBuffer(nil)
			_ = pem.Encode(w, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: activeCert.Certificate[0],
			})

			// Update the CA bundle in the webhook configuration
			for i := range webhook.Webhooks {
				webhook.Webhooks[i].ClientConfig.CABundle = w.Bytes()
			}

			if webhook == nil {
				// Create the webhook configuration if it doesn't exist
				webhook = &admissionregistrationv1.MutatingWebhookConfiguration{
					ObjectMeta: metav1.ObjectMeta{
						Name: appName,
					},
					Webhooks: []admissionregistrationv1.MutatingWebhook{
						{
							Name: appName,
							ClientConfig: admissionregistrationv1.WebhookClientConfig{
								Service: &admissionregistrationv1.ServiceReference{
									Namespace: k8s.DeployedNamespace(),
									Name:      appName,
								},
								CABundle: w.Bytes(),
							},
						},
					},
				}

				if _, err = a.base.KubeClient().AdmissionregistrationV1().MutatingWebhookConfigurations().Create(timeoutCtx, webhook, metav1.CreateOptions{}); err != nil {
					return fmt.Errorf("failed to create webhook configuration: %w", err)
				}
			} else {
				if _, err = a.base.KubeClient().AdmissionregistrationV1().MutatingWebhookConfigurations().Update(timeoutCtx, webhook, metav1.UpdateOptions{}); err != nil {
					return fmt.Errorf("failed to update webhook configuration: %w", err)
				}
			}

			a.base.Logger().Info("webhook configuration updated", slog.String("webhook-name", appName))
			return nil
		}),
	); err != nil {
		return fmt.Errorf("failed to start base app: %w", err)
	}

	if err := a.base.StartServer("webhook-server", apiServer); err != nil {
		return fmt.Errorf("failed to start webhook server: %w", err)
	}

	return nil
}

func (a *App) buildSecureServer() (*http.Server, error) {
	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			a.base.Logger().Debug("finding TLS certificate")

			// Is the current certificate still valid?
			activeCertVal := a.config.activeCert.Load()
			if activeCertVal == nil {
				a.base.Logger().Error("no active certificate found")
				return nil, errors.New("no active certificate found")
			}

			activeCert, ok := activeCertVal.(*tls.Certificate)
			if !ok {
				a.base.Logger().Error("failed to cast active certificate")
				return nil, errors.New("failed to cast active certificate")
			}

			a.base.Logger().Debug("serving TLS certificate")
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
