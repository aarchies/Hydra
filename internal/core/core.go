package core

import (
	"context"
	"dissect/export"
	"dissect/internal"
	"dissect/internal/core/runtime"
	"fmt"
	"os/signal"

	"syscall"

	"dissect/utils"
	"os"

	"github.com/sirupsen/logrus"
)

var (
	sigCh       = make(chan os.Signal, 1)
	ctx, cancel = context.WithCancel(context.Background())
)

func init() {
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
}

var count = 0

func Run(svc *internal.ServiceContext) {

	runtime.Init(ctx)

	Initcontrl(ctx, svc)

	go func() {
		for {
			select {
			case <-sigCh:
				logrus.Infoln("stopping all instances...")
				// todo 顺序优雅关闭
				cancel()
				return
			case buffer := <-runtime.G_output():
				count++
				fmt.Printf("core Received: %d \n", count)
				_ = buffer
				//	Start(buffer)
			}
		}
	}()

	for data := range utils.OpenOffline("test/asset_mqtt.pcap") {
		for i := 0; i < 10000; i++ {
			export.EntranceByte(data, "1", "", 1, 0, 1, "", "")
		}
	}
}
