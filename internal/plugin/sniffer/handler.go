package sniffer

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
	"fmt"
	"log"

	"strings"
	"sync"

	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

var snapLen = int32(65535)

type (
	H struct {
		svc *internal.ServiceContext
		sync.WaitGroup
		Iface      string
		FilterRule string
	}
	CaptureJob struct {
		Interface string
		Filter    string
	}
)

func (c *H) Handle(result *model.ConsumerData) {
	logrus.Infoln("handle", result)
}

func (c *H) Start(ctx context.Context, svc *internal.ServiceContext) {
	c.svc = svc
	defer func() {
		logrus.Debugln("实例已停止!")
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
		}
	}()

	// go func() {
	// 	for {
	// 		select {
	// 		case <-ctx.Done():
	// 			return
	// 		case i := <-c.svc.ResultCh:
	// 			data, err := json.Marshal(i)
	// 			if err != nil {
	// 				logrus.Debugln("error marshall to json", err.Error())
	// 				return
	// 			}
	// 			logrus.Debugln(string(data))
	// 		}
	// 	}
	// }()

	//抓包解析过程
	//go data_process.ConsumerMainV2()

	for _, job := range c.ReadConfig() {
		c.Add(1)
		go func(job CaptureJob) {
			defer c.Done()
			fmt.Printf("Starting capture on interface %s with filter %s\n", job.Interface, job.Filter)

			handle, err := pcap.OpenLive(job.Interface, snapLen, true, pcap.BlockForever)
			if err != nil {
				log.Printf("Error opening interface %s: %v", job.Interface, err)
				return
			}
			defer handle.Close()

			if job.Filter != "" {
				if err := handle.SetBPFFilter(job.Filter); err != nil {
					log.Printf("Error setting BPF filter %s: %v", job.Filter, err)
					return
				}
			}

			// for {
			// 	select {
			// 	case <-ctx.Done():
			// 		return
			// 	default:
			// 		// data, _, err := handle.ZeroCopyReadPacketData()
			// 		// if err != nil {
			// 		// 	log.Printf("Error reading packet data: %v", err)
			// 		// 	continue
			// 		// }

			// 		// if len(data) > 0 {
			// 		// 	select {
			// 		// 	case c.svc.BufferCh <- &pb.ProducerData{

			// 		// 		DataByte: data,
			// 		// 	}:
			// 		// 		fmt.Printf("Producer: %s\n", data)
			// 		// 	default:
			// 		// 	}
			// 		// }
			// 	}
			// }
		}(job)
	}

	c.Wait()
}

func (c *H) ReadConfig() []CaptureJob {
	var captureJobs []CaptureJob
	for _, part := range strings.Split(c.Iface, ",") {
		captureJobs = append(captureJobs, CaptureJob{
			Interface: part,
			Filter:    c.FilterRule,
		})
	}

	return captureJobs
}
