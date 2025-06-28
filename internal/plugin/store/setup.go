package store

import (
	"dissect/internal/core"
	"dissect/internal/plugin"
)

func init() {
	core.RegisterPlugin("store", func(c *core.Controller) plugin.Handler {
		return NewHandler(c.Context(), c.ServiceContext())
	})
}
