package exception

import (
	"dissect/internal"
	"dissect/internal/core"
	"dissect/internal/model"
	"dissect/internal/plugin"
	"strings"
)

type Handler struct {
	svc *internal.ServiceContext
}

var errMap = map[string]ErrType{
	"[Malformed Packet: length of contained item exceeds length of containing item]": ErrTotalLengthError,
}

func init() {
	core.RegisterPlugin("exception", func(c *core.Controller) plugin.Handler {
		return &Handler{
			svc: c.ServiceContext(),
		}
	})
}

// Handle implements plugin.Handler.
func (h *Handler) Handle(result *model.ConsumerData) {
	for i := 0; i < len(result.Meta); i++ {
		if result.Meta[i].N == "_ws.malformed" {
			for key, value := range errMap {
				if strings.Contains(result.Action, key) {
					result.Action = strings.Replace(result.Action, key, "", -1)
					result.ErrType = uint8(value)
					result.Meta = append(result.Meta[:i], result.Meta[i+1:]...)
					return
				}
			}
			result.ErrType = uint8(ErrFieldIdentifierError)
			return
		}

		var et ErrType
		for j := 0; j < len(result.Meta[i].F); j++ {
			if errs := et.GetErrType(result.Meta[i].F[j].Sh); errs != 0 {
				result.ErrType = uint8(errs)
				return
			}
		}
	}
}
