package main

import (
	"context"
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

		ticker := time.NewTicker(15 * time.Second)
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
					a.base.Viper().GetString("pem_path"),
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
	// Get the current pem certificate
	currentPemCert := a.config.PemCert
	currentPemKey := a.config.PemKey
	currentPemCA := a.config.PemCA
	if currentPemCert == nil || currentPemKey == nil || currentPemCA == nil {
		return errors.New("pem certificate not found")
	}

	// When does the pem expire?
	cert, err := x509.ParseCertificate(currentPemCert)
	if err != nil {
		return fmt.Errorf("failed to parse pem certificate: %w", err)
	}

	// Check if the certificate is about to expire
	if time.Until(cert.NotAfter) >= refreshThreshold {
		l.Debug("pem certificate is still valid")
		return nil
	}

	l.Info("pem certificate is about to expire, reloading")
	if err := a.loadNewPem(ctx, vaultClient, pemPath); err != nil {
		return fmt.Errorf("failed to reload pem certificate: %w", err)
	}
	l.Info("pem certificate reloaded successfully")

	return nil
}

// loadNewPem loads a new PEM certificate from Vault and updates the app configuration.
func (a *App) loadNewPem(
	ctx context.Context,
	vaultClient vaulty.Client,
	pemPath string,
) error {
	vc := vaultClient.Client()

	secret, err := vc.Logical().WriteWithContext(ctx, pemPath, map[string]any{
		"common_name": fmt.Sprintf("%s.%s.svc", appName, k8s.DeployedNamespace()),
		"ttl":         vaultPemExpiry.String(),
	})
	if err != nil {
		return fmt.Errorf("failed to write pem secret: %w", err)
	}

	pemCert, ok := secret.Data["pem_cert"].(string)
	if !ok {
		return errors.New("pem_cert not found in secret data")
	}

	pemKey, ok := secret.Data["pem_key"].(string)
	if !ok {
		return errors.New("pem_key not found in secret data")
	}

	ca, ok := secret.Data["issuing_ca"].(string)

	a.config.PemCert = []byte(pemCert)
	a.config.PemKey = []byte(pemKey)
	a.config.PemCA = []byte(ca)

	return nil
}
