package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/spf13/viper"

	"github.com/jacobbrewer1/web"
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
					l,
					a.base.Viper(),
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
	l *slog.Logger,
	viper *viper.Viper,
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
			l.Debug("pem certificate is still valid", slog.String("remaining", time.Until(cert.NotAfter).String()))
			return nil
		}

		l.Info("pem certificate is about to expire, reloading")
	} else {
		l.Info("pem certificate not set, loading new one")
	}

	tlsCert, err := loadNewPem(viper.GetStringSlice("dns.names"), viper.GetString("dns.common_name"))
	if err != nil {
		return fmt.Errorf("failed to reload pem certificate: %w", err)
	}
	l.Info("pem certificate reloaded successfully")

	a.config.activeCert.Store(tlsCert)

	return nil
}

// loadNewPem loads a new PEM certificate from Vault and updates the app configuration.
func loadNewPem(dnsNames []string, commonName string) (*tls.Certificate, error) {
	// CA configuration
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization: []string{"velotio.com"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// CA private key
	caPrivateKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// Self-signed CA certificate
	caBytes, err := x509.CreateCertificate(cryptorand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		fmt.Println(err)
	}

	caPEM := bytes.NewBuffer(nil)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	// Server cert config
	cert := &x509.Certificate{
		DNSNames:     dnsNames,
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	// Server private key
	serverPrivKey, err := rsa.GenerateKey(cryptorand.Reader, 4096)
	if err != nil {
		fmt.Println(err)
	}

	// sign the server cert
	serverCertBytes, err := x509.CreateCertificate(cryptorand.Reader, cert, ca, &serverPrivKey.PublicKey, caPrivateKey)
	if err != nil {
		fmt.Println(err)
	}

	// PEM encode the  server cert and key
	serverCertPEM := new(bytes.Buffer)
	_ = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: serverCertBytes,
	})

	serverPrivateKeyPEM := bytes.NewBuffer(nil)
	_ = pem.Encode(serverPrivateKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(serverPrivKey),
	})

	// Create the TLS certificate
	tlsCert, err := tls.X509KeyPair(serverCertPEM.Bytes(), serverPrivateKeyPEM.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	return &tlsCert, nil
}
