package main

import (
	"dissect/config"
	"dissect/internal"
	"dissect/internal/core"
	_ "dissect/internal/module"
)

//go:generate go run internal/module/directives_generate.go
func main() {
	core.Run(internal.NewServiceContext(config.MustLoad()))
}
