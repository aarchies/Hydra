package sniffer

import (
	"dissect/internal/core"
	"dissect/internal/model"
	"dissect/internal/plugin"
	"fmt"

	"github.com/sirupsen/logrus"
)

func init() {
	core.RegisterPlugin("sniffer", func(c *core.Controller) plugin.Handler {
		c.OnStartup(func() error {
			fmt.Println("init sniffer")
			return nil
		})
		c.Completed(func(result *model.ConsumerData) error {
			logrus.Infoln("已完成", result)
			return nil
		})
		return &H{}
	})
}
