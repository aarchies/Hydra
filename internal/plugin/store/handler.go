package store

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
	"sync"
	"time"
)

var maxBatchSize = 2000

type Handler struct {
	svc  *internal.ServiceContext
	ctx  context.Context
	list []*model.ConsumerData
	sync.Mutex
}

func NewHandler(ctx context.Context, svc *internal.ServiceContext) *Handler {

	h := &Handler{
		svc:  svc,
		ctx:  ctx,
		list: make([]*model.ConsumerData, 0, maxBatchSize),
	}

	go h.Start()
	return h
}

func (h *Handler) Handle(data *model.ConsumerData) {
	h.list = append(h.list, data)
}

func (h *Handler) Start() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			h.flush()
			return
		case <-ticker.C:
			h.flush()
		default:
			if len(h.list) >= maxBatchSize {
				h.flush()
			} else {
				time.Sleep(300 * time.Millisecond) // 防止长空转
			}
		}
	}
}

func (h *Handler) flush() {
	if len(h.list) == 0 {
		return
	}

	h.Lock()
	defer h.Unlock()

	if err := h.svc.ClickHouseDB.CreateInBatches(h.list, len(h.list)).Error; err == nil {
		h.list = make([]*model.ConsumerData, 0, maxBatchSize)
	}
}
