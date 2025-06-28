package warn

import (
	"dissect/internal/core"
	"dissect/internal/plugin"
)

func init() {
	core.RegisterPlugin("warn", func(c *core.Controller) plugin.Handler {
		return NewHandler(c.Context(), c.ServiceContext())
	})
}
