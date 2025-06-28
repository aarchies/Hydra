package offline

import (
	"dissect/internal/core"
	"dissect/internal/plugin"
)

func init() {
	core.RegisterPlugin("offline", func(c *core.Controller) plugin.Handler {
		return NewHandler(c.Context(), c.ServiceContext())
	})
}
