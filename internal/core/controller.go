package core

import (
	"context"
	"dissect/config"
	"dissect/internal"
	"dissect/internal/model"
	"dissect/internal/model/pb"
	"runtime"
	"time"

	"google.golang.org/protobuf/proto"
)

var (
	controllers []*Controller
)

type (
	Controller struct {
		config.Dispenser
		instance *Instance
	}
)

func Initcontrl(ctx context.Context, svc *internal.ServiceContext) {
	for _, i := range Directives {
		action, ok := Plugins[i]
		if !ok {
			continue
		}

		c := new(i, ctx, svc)
		c.instance.Handler = action(c)
		c.instance.Run()
		controllers = append(controllers, c)
	}
	go gc(ctx)
}

func new(serverType string, ctx context.Context, svc *internal.ServiceContext) *Controller {
	c := &Controller{
		instance: &Instance{
			ServerType: serverType,
			Svc:        svc,
			Context:    ctx,
		},
	}
	return c
}

func (c *Controller) ServerType() string {
	return c.instance.ServerType
}

func (c *Controller) OnFirstStartup(fn func() error) {
	c.instance.OnFirstStartup = append(c.instance.OnFirstStartup, fn)
}

func (c *Controller) OnStartup(fn func() error) {
	c.instance.OnStartup = append(c.instance.OnStartup, fn)
}

func (c *Controller) OnRestart(fn func() error) {
	c.instance.OnRestart = append(c.instance.OnRestart, fn)
}

func (c *Controller) OnRestartFailed(fn func() error) {
	c.instance.OnRestartFailed = append(c.instance.OnRestartFailed, fn)
}

func (c *Controller) OnShutdown(fn func() error) {
	c.instance.OnShutdown = append(c.instance.OnShutdown, fn)
}

func (c *Controller) OnFinalShutdown(fn func() error) {
	c.instance.OnFinalShutdown = append(c.instance.OnFinalShutdown, fn)
}

func (c *Controller) Completed(fn func(result *model.ConsumerData) error) {
}

func (c *Controller) Context() context.Context {
	return c.instance.Context
}

func (c *Controller) ServiceContext() *internal.ServiceContext {
	return c.instance.Svc
}

func (c *Controller) Get(key interface{}) interface{} {
	c.instance.StorageMu.RLock()
	defer c.instance.StorageMu.RUnlock()
	return c.instance.Storage[key]
}

func (c *Controller) Set(key, val interface{}) {
	c.instance.StorageMu.Lock()
	c.instance.Storage[key] = val
	c.instance.StorageMu.Unlock()
}

func (c *Controller) FindController(plugin string) *Controller {
	for _, c := range controllers {
		if c.ServerType() == plugin {
			return c
		}
	}

	return nil
}

func (c *Controller) FindInstance(plugin string) *Instance {
	for _, c := range controllers {
		if c.ServerType() == plugin {
			return c.instance
		}
	}

	return nil
}

func gc(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runtime.GC()
		}
	}
}

func Start(buffer []byte) {
	// convert protomodel
	result := &pb.ConsumerData{}
	proto.Unmarshal(buffer, result)

	//convert model
	entity := &model.ConsumerData{
		NegTimestamp:   result.NegTimestamp,
		TaskID:         result.TaskId,
		LineNo:         result.LineNo,
		DataByte:       result.DataByte,
		CreateTime:     result.CreateTime.AsTime(),
		Direction:      uint8(result.Direction),
		SrcMac:         result.SrcMac,
		SrcIP:          result.SrcIP,
		SrcPort:        uint16(result.SrcPort),
		DstMac:         result.DstMac,
		DstIP:          result.DstIP,
		DstPort:        uint16(result.DstPort),
		Protocol:       result.Protocol,
		ProtocolType:   uint8(result.ProtocolType),
		TransportLayer: result.TransportLayer,
		EThType:        result.EThType,
		IPVersion:      result.IPVersion,
		Action:         result.Action,
		SID:            int(result.SId),
		EventType:      result.EventType,
		EventDesc:      result.EventDesc,
		IsAttack:       result.IsAttack,
		ErrType:        uint8(result.ErrType),
		Meta:           make([]model.ProtocolData, len(result.Meta)),
	}

	for i := 0; i < len(result.Meta); i++ {
		entity.Meta[i] = model.ProtocolData{
			N:  result.Meta[i].N,
			SN: result.Meta[i].Sn,
			Sz: result.Meta[i].Sz,
			Ps: result.Meta[i].Ps,
			F:  make([]model.ProtocolField, len(result.Meta[i].F)),
			FL: int(result.Meta[i].Fl),
		}
		for j := 0; j < len(result.Meta[i].F); j++ {
			entity.Meta[i].F[j] = model.ProtocolField{
				N:  result.Meta[i].F[j].N,
				SN: result.Meta[i].F[j].Sn,
				Sz: result.Meta[i].F[j].Sz,
				Ps: result.Meta[i].F[j].Ps,
				Sh: result.Meta[i].F[j].Sh,
				V:  result.Meta[i].F[j].V,
			}
		}
	}

	buffer = nil
	result = nil

	// invoke
	for _, c := range controllers {
		if c.instance != nil {
			c.instance.Send(entity)
		}
	}
	entity = nil
}
