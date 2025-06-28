package vlun

import (
	"dissect/internal/core"
	"dissect/internal/plugin"
)

func init() {
	core.RegisterPlugin("vlun", func(c *core.Controller) plugin.Handler {
		return NewHandler(c.Context(), c.ServiceContext())
	})
}
