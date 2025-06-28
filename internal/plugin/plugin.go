package plugin

import (
	"dissect/internal/model"
)

type (
	Plugin  func(Handler) Handler
	Handler interface {
		Handle(result *model.ConsumerData)
	}
)
