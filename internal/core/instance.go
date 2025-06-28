package core

import (
	"context"
	"dissect/internal"

	"dissect/internal/model"
	"dissect/internal/plugin"
	"sync"

	"github.com/sirupsen/logrus"
)

type Instance struct {
	ServerType      string                      // server name
	Context         context.Context             // ctx
	Svc             *internal.ServiceContext    // global context
	Handler         plugin.Handler              // plugin
	OnFirstStartup  []func() error              // starting, not as part of a restart
	OnStartup       []func() error              // starting, even as part of a restart
	OnRestart       []func() error              // before restart commences
	OnRestartFailed []func() error              // if restart failed
	OnShutdown      []func() error              // stopping, even as part of a restart
	OnFinalShutdown []func() error              // stopping, not as part of a restart
	CompletedData   *model.ConsumerData         //
	Storage         map[interface{}]interface{} // plugin:db
	wg              *sync.WaitGroup
	StorageMu       sync.RWMutex
}

func (i *Instance) Wait() {
	i.wg.Wait()
}

func (i *Instance) Run() {

	if i.Startup() != nil {
		return
	}

	logrus.Infof("started %s instance \n", i.ServerType)
	go func() {
		for {
			<-i.Context.Done()
			i.Shutdown()
			logrus.Infof("stoping %s instance \n", i.ServerType)
			return
		}
	}()
}

func (i *Instance) Send(result *model.ConsumerData) {
	i.Handler.Handle(result)
}

func (i *Instance) Startup() error {
	for _, action := range i.OnStartup {
		err := action()
		if err != nil {
			logrus.Errorf("startup %s instance error: %v\n", i.ServerType, err)
			return err
		}
	}
	return nil
}

func (i *Instance) RestartFailed() {
	for _, action := range i.OnRestartFailed {
		action()
	}
}

func (i *Instance) FinalShutdown() {
	for _, action := range i.OnFinalShutdown {
		action()
	}
}

func (i *Instance) Shutdown() error {
	errs := 0
	for _, action := range i.OnShutdown {
		if err := action(); err != nil {
			errs++
		}
	}

	if errs > 0 {
		i.FinalShutdown()
	}

	return nil
}

func (i *Instance) Completed(result *model.ConsumerData) {
	i.CompletedData = result
}
