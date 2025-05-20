package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jacobbrewer1/vaulty"
	"github.com/jacobbrewer1/web"
	"github.com/jacobbrewer1/web/k8s"
	"github.com/jacobbrewer1/web/logging"
)

const (
	// vaultPemExpiry is the lease duration that the PEM certificate is valid for.
	vaultPemExpiry = 24 * time.Hour
)

// waitForPemExpiry is a task that monitors the expiry of the PEM certificate.
func (a *App) waitForPemExpiry(l *slog.Logger) web.AsyncTaskFunc {
	return func(ctx context.Context) {
		l.Info("monitoring pem expiry")

		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				l.Debug("context cancelled, stopping pem expiry monitoring")
				return
			case <-ticker.C:
				// Check if the PEM certificate is about to expire
				if err := a.reloadPemIfNeeded(
					ctx,
					l,
					a.base.VaultClient(),
					a.base.Viper().GetString("vault.pem.path"),
					vaultPemExpiry/2, // Give a window to reload the certificate in-case of server failures, etc.
				); err != nil {
					l.Error("failed to reload pem certificate", slog.String(logging.KeyError, err.Error()))
					continue
				}
			}
		}
	}
}

// reloadPemIfNeeded checks if the PEM certificate is about to expire and reloads it if necessary.
func (a *App) reloadPemIfNeeded(
	ctx context.Context,
	l *slog.Logger,
	vaultClient vaulty.Client,
	pemPath string,
	refreshThreshold time.Duration,
) error {
	// When does the pem expire?
	activeCertVal := a.config.activeCert.Load()
	if activeCertVal != nil {
		activeCert, ok := activeCertVal.(*tls.Certificate)
		if !ok {
			return errors.New("active certificate is not of type *tls.Certificate")
		}

		cert, err := x509.ParseCertificate(activeCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("failed to parse pem certificate: %w", err)
		}

		// Check if the certificate is about to expire
		if time.Until(cert.NotAfter) >= refreshThreshold {
			l.Debug("pem certificate is still valid")
			return nil
		}

		l.Info("pem certificate is about to expire, reloading")
	} else {
		l.Info("pem certificate not set, loading new one")
	}

	tlsCert, err := loadNewPem(ctx, vaultClient, pemPath)
	if err != nil {
		return fmt.Errorf("failed to reload pem certificate: %w", err)
	}
	l.Info("pem certificate reloaded successfully")

	a.config.activeCert.Store(tlsCert)

	return nil
}

// loadNewPem loads a new PEM certificate from Vault and updates the app configuration.
func loadNewPem(
	ctx context.Context,
	vaultClient vaulty.Client,
	pemPath string,
) (*tls.Certificate, error) {
	vc := vaultClient.Client()

	secret, err := vc.Logical().WriteWithContext(ctx, pemPath, map[string]any{
		"common_name": fmt.Sprintf("%s.%s.svc", appName, k8s.DeployedNamespace()),
		"ttl":         vaultPemExpiry.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to write pem secret: %w", err)
	}

	pemCert, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("pem_cert not found in secret data")
	}

	pemKey, ok := secret.Data["private_key"].(string)
	if !ok {
		return nil, errors.New("pem_key not found in secret data")
	}

	tlsCert, err := tls.X509KeyPair([]byte(pemCert), []byte(pemKey))
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 key pair: %w", err)
	}

	return &tlsCert, nil
}
