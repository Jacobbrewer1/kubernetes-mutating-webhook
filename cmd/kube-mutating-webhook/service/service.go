package service

import (
	"context"
	"log/slog"

	admissionv1 "k8s.io/api/admission/v1"

	"github.com/jacobbrewer1/kubernetes-mutating-webhook/cmd/kube-mutating-webhook/api/openapi"
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

func (s Service) PostMutate(ctx context.Context, l *slog.Logger, body0 *openapi.PostMutateJSONBody) (*admissionv1.AdmissionReview, error) {
	//TODO implement me
	panic("implement me")
}
