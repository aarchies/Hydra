package vlun

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
)

type Handler struct {
	svc *internal.ServiceContext
	ctx context.Context
}

func (h *Handler) Handle(result *model.ConsumerData) {

}

func NewHandler(ctx context.Context, svc *internal.ServiceContext) *Handler {
	return &Handler{
		svc: svc,
		ctx: ctx,
	}
}
