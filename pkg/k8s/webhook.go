package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	// ErrWebhookAlreadyInitialized is returned when the webhook has already been initialized.
	ErrWebhookAlreadyInitialized = errors.New("webhook already initialized")
)

type Webhook struct {
	l                         *slog.Logger
	kubeClient                kubernetes.Interface
	tlsCertificate            *tls.Certificate
	webhookName               string
	webhookNamespace          string
	requestMutationAnnotation string
	mutatedAnnotation         string
	isInitialized             bool
	waitInterval              time.Duration
	apiCallTimeout            time.Duration
	refreshInterval           time.Duration
}

// NewWebhook creates a new instance of Webhook. The webhook implementation must utilise
func NewWebhook(
	l *slog.Logger,
	kubeClient kubernetes.Interface,
	tlsCertificate *tls.Certificate,
	webhookName string,
	webhookNamespace string,
	requestMutationAnnotation string,
	mutatedAnnotation string,
) *Webhook {
	return &Webhook{
		l:                         l,
		kubeClient:                kubeClient,
		tlsCertificate:            tlsCertificate,
		webhookName:               webhookName,
		webhookNamespace:          webhookNamespace,
		requestMutationAnnotation: requestMutationAnnotation,
		mutatedAnnotation:         mutatedAnnotation,
		waitInterval:              10 * time.Second,
		apiCallTimeout:            10 * time.Second,
		refreshInterval:           time.Minute,
	}
}

// Init initializes the webhook, bootstrapping the Kubernetes Mutating Webhook configuration and also deleting
func (w *Webhook) Init(ctx context.Context) error {
	if w.isInitialized {
		return ErrWebhookAlreadyInitialized
	}

	// Initialize the webhook configuration and delete unhooked pods if necessary
	if err := w.updateMutatingWebhookConfiguration(ctx); err != nil {
		return err
	}

	if err := w.waitForWebhookRouting(ctx); err != nil {
		return fmt.Errorf("failed to wait for webhook routing: %w", err)
	}

	w.isInitialized = true
	w.l.Info("Webhook initialized successfully", "webhookName", w.webhookName, "webhookNamespace", w.webhookNamespace)
	return nil
}

// updateMutatingWebhookConfiguration updates the MutatingWebhookConfiguration with the current TLS certificate.
func (w *Webhook) updateMutatingWebhookConfiguration(ctx context.Context) error {
	ctx2, cancel := context.WithTimeout(ctx, w.apiCallTimeout)
	defer cancel()

	webhook, err := w.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Get(ctx2, w.webhookName, v1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get mutating webhook configuration: %w", err)
	}

	buffer := bytes.NewBuffer(nil)
	if err := pem.Encode(buffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: w.tlsCertificate.Certificate[0],
	}); err != nil {
		return fmt.Errorf("failed to encode certificate: %w", err)
	}

	for i := range webhook.Webhooks {
		webhook.Webhooks[i].ClientConfig.CABundle = buffer.Bytes()
	}

	_, updateErr := w.kubeClient.AdmissionregistrationV1().MutatingWebhookConfigurations().Update(ctx2, webhook, v1.UpdateOptions{})
	return updateErr
}

// waitForWebhookRouting waits for the webhook service to have endpoints associated with it.
func (w *Webhook) waitForWebhookRouting(ctx context.Context) error {
	attempts := 0
	tick := time.NewTicker(w.waitInterval)
	defer tick.Stop()

	for range tick.C {
		attempts++

		if attempts > 3 {
			return fmt.Errorf("timed out waiting for webhook routing")
		}

		ctx2, cancel := context.WithTimeout(ctx, w.apiCallTimeout)
		endpoints, err := w.kubeClient.CoreV1().Endpoints(w.webhookNamespace).Get(ctx2, w.webhookName, v1.GetOptions{})
		if err != nil {
			cancel()
			continue
		}

		if len(endpoints.Subsets) == 0 {
			cancel()
			continue
		}

		if len(endpoints.Subsets[0].Addresses) == 0 {
			cancel()
			continue
		}

		cancel()
		break
	}

	return nil
}
