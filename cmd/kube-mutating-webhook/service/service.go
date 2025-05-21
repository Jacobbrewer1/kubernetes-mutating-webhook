package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	admissionv1 "k8s.io/api/admission/v1"

	"github.com/jacobbrewer1/kubernetes-mutating-webhook/cmd/kube-mutating-webhook/api/openapi"
	"github.com/jacobbrewer1/uhttp"
)

var _ openapi.ServerInterface = (*Service)(nil)

type Service struct {
	l *slog.Logger
}

func NewService(
	l *slog.Logger,
) *Service {
	return &Service{
		l: l,
	}
}

func (s *Service) PostMutate(ctx context.Context, l *slog.Logger, r *http.Request, body *openapi.PostMutateJSONBody) (*admissionv1.AdmissionReview, error) {
	l.Debug("PostMutate called")
	switch {
	case isPodResource((*body).Request.Resource):
		fallthrough
	default:
		return nil, uhttp.NewHTTPError(http.StatusNotImplemented, fmt.Errorf("unsupported resource: %s", (*body).Request.Resource))
	}
}
