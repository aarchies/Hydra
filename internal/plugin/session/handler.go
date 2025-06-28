package session

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"

	"github.com/sirupsen/logrus"
)

type Handler struct {
	svc *internal.ServiceContext
	ctx context.Context
	sync.Map
}

var (
	conf           *Config
	handlers       *Handler
	serviceContext *internal.ServiceContext
	kafkaProducer  *kafka.Writer
	maps           = make(map[string]uint)
	lock           sync.Mutex
)

func NewHandler(ctx context.Context, svc *internal.ServiceContext, config *Config) *Handler {
	serviceContext = svc
	handlers = &Handler{svc, ctx, sync.Map{}}
	conf = config

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				timingSave(svc)
			}
		}
	}()

	return handlers
}

func (d *Handler) match(data *model.ConsumerData) (string, string, *Session) {

	if sv, sOk := d.Load(data.SrcTuple()); sOk {
		return data.SrcAppTuple(), data.SrcTuple(), sv.(*Session)
	}
	if dv, Dok := d.Load(data.DistTuple()); Dok {
		return data.DistAppTuple(), data.DistTuple(), dv.(*Session)
	}

	return data.SrcAppTuple(), data.SrcTuple(), nil
}

func (h *Handler) Handle(result *model.ConsumerData) {

	// 允许所有常态流量
	if result.SrcIP == "" || result.SrcPort == 0 || result.DstIP == "" || result.DstPort == 0 || result.TransportLayer == "" {
		return
	}

	key, tuple, session := h.match(result)
	if session == nil {
		session = newSession(result, filepath.Join(h.svc.Config.Session.RootPath, h.svc.Config.Session.PcapPath), key, tuple, time.Duration(h.svc.Config.Session.Expired)*time.Second)
		h.Store(tuple, session)
	} else {
		session.renewal(time.Duration(h.svc.Config.Session.Expired))
		session.appendSession(result)
	}
	result.SessionID = session.Id
}

func newSession(data *model.ConsumerData, path, key, tuple string, interval time.Duration) *Session {

	var s Session
	s.Id = uuid.New().String()
	s.Interval = interval
	s.Start = time.Now()
	s.key = key
	s.tuple = tuple
	s.renewalCh = make(chan struct{}, 1)
	s.Src = data.SrcIP
	s.SrcPort = data.SrcPort
	s.Dst = data.DstIP
	s.DstPort = data.DstPort
	s.Protocol = data.Protocol
	s.List = make([]*model.ConsumerData, 0)

	// 按时间分层
	path = filepath.Join(path, fmt.Sprintf("/%s", time.Now().Format("20060102")))

	// 判断路径是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		os.MkdirAll(path, 0744)
	}

	if runtime.GOOS == "windows" {
		path = uuid.NewString() + "-" + key + ".pcap"
		path = filepath.Join("pcap", path)
		if _, err := os.Stat("pcap"); os.IsNotExist(err) {
			os.MkdirAll("pcap", 0744)
		}
	} else {
		path = filepath.Join(path, key+".pcap")
	}

	fd, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0744)
	if err != nil {
		logrus.Errorln("seesion-> open file failed: ", err)
	}
	w := pcapgo.NewWriter(fd)
	w.WriteFileHeader(65535, layers.LinkTypeEthernet) // 设置文件头部

	s.fd = fd
	s.w = w
	s.Path = path
	s.appendSession(data)

	go s.runJanitor()
	return &s
}

func (s *Session) appendSession(data *model.ConsumerData) {
	if len(data.DataByte) < 16 {
		logrus.Errorln("session-> evict write packet failed: ", "data is nil")
		return
	}
	if data.DataByte[0] == 0x00 && data.DataByte[1] == 0x00 {
		logrus.Errorln("session-> evict write packet failed: ", "data is nil")
		return
	}

	err := s.w.WritePacket(gopacket.CaptureInfo{
		Timestamp:      time.Now(),
		CaptureLength:  len(data.DataByte),
		Length:         len(data.DataByte),
		InterfaceIndex: 0,
	}, data.DataByte)

	if err != nil {
		logrus.Errorln("session-> evict write packet failed: ", err)
		return
	}
	s.appendList(data)
}

func (s *Session) appendList(data *model.ConsumerData) {

	s.List = append(s.List, &model.ConsumerData{
		CreateTime:      data.CreateTime,
		SrcIP:           data.SrcIP,
		SrcPort:         data.SrcPort,
		DstIP:           data.DstIP,
		DstPort:         data.DstPort,
		TransportLayer:  data.TransportLayer,
		Protocol:        data.Protocol,
		ProtocolType:    data.ProtocolType,
		SrcCountry:      data.SrcCountry,
		SrcProvince:     data.SrcProvince,
		SrcCity:         data.SrcCity,
		DstCountry:      data.DstCountry,
		DstProvince:     data.DstProvince,
		DstCity:         data.DstCity,
		ErrType:         data.ErrType,
		Action:          data.Action,
		ActionClassCode: data.ActionClassCode,
		Vendor:          data.Vendor,
		Model:           data.Model,
		DeviceType:      data.DeviceType,
		EventType:       data.EventType,
		LineNo:          data.LineNo,
		EventID:         data.EventID,
		VictimID:        data.VictimID,
		SrcMac:          data.SrcMac,
		DstMac:          data.DstMac,
		EThType:         data.EThType,
		IPVersion:       data.IPVersion,
		SID:             data.SID,
		EventDesc:       data.EventDesc,
		IsAttack:        data.IsAttack,
		Direction:       data.Direction,
		IsKey:           data.IsKey,
		IsVul:           data.IsVul,
		EventLevel:      data.EventLevel,
		Vul:             data.Vul,
		LatitudeSrc:     data.LatitudeSrc,
		LongitudeSrc:    data.LongitudeSrc,
		LatitudeDst:     data.LatitudeDst,
		LongitudeDst:    data.LongitudeDst,
		Meta:            data.Meta,
	})
}

func (s *Session) renewal(interval time.Duration) {
	s.Interval = time.Second * interval
	s.renewalCh <- struct{}{}
}

func (s *Session) runJanitor() {
	for {
		t := time.NewTicker(s.Interval)
		select {
		case <-t.C:
			s.End = time.Now()
			s.evict()
			t.Stop()
			return
		case <-s.renewalCh: // 续约
			t.Stop()
		}
	}
}

func (s *Session) evict() {

	s.fd.Close()

	// Modbus/TCP协议类型 特殊处理
	for _, item := range s.List {
		if s.Protocol == "TCP" && item.Protocol != s.Protocol {
			newPath := strings.Replace(s.Path, s.Protocol, item.Protocol, 1)
			if err := os.Rename(s.Path, newPath); err != nil {
				logrus.Errorln("session-> evict rename file failed: ", err)
				return
			}
			s.Protocol = item.Protocol
			s.Path = newPath
			break
		}
	}

	if err := serviceContext.ClickHouseDB.Model(&Session{}).Create(&s).Error; err != nil {
		logrus.Errorln("session-> evict db store failed: ", err)
	}

	logrus.Debugln("session-> evict is complated. ", s.Path)

	// clear session
	handlers.Delete(s.tuple)
	s.List = nil
	s = nil
}
