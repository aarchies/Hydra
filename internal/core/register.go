package core

import "dissect/internal/plugin"

var Plugins = make(map[string]SetupFunc)

type (
	SetupFunc func(c *Controller) plugin.Handler
)

func RegisterPlugin(serverType string, action SetupFunc) {
	if serverType == "" {
		panic("plugin must have a name")
	}
	if _, ok := Plugins[serverType]; !ok {
		Plugins[serverType] = action
	}
}
