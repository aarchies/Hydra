package session

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
	push_model "dissect/internal/plugin/session/pb"
	base "dissect/internal/plugin/session/pb/base"
	message "dissect/internal/plugin/session/pb/message"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/duke-git/lancet/v2/condition"
	"github.com/duke-git/lancet/v2/cryptor"
	"github.com/duke-git/lancet/v2/pointer"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"google.golang.org/protobuf/proto"

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

	// send to sessionchan
	for _, item := range s.List {
		if item.ProtocolType != 2 && item.ProtocolType != 3 {
			continue
		}
		alertLog := makeAlertLog(item, serviceContext, conf)
		alertLog.RawData = pointer.Of(path.Join("/mnt", s.Path))
		sendMessage(alertLog)
	}

	logrus.Debugln("session-> evict is complated. ", s.Path)

	// clear session
	handlers.Delete(s.tuple)
	s.List = nil
	s = nil
}

func makeAlertLog(data *model.ConsumerData, svc *internal.ServiceContext, conf *Config) *push_model.ALERT_LOG {

	var alertLog push_model.ALERT_LOG
	alertLog.Guid = pointer.Of(cryptor.Sha256(svc.Config.Session.Push.IP + strconv.FormatInt(time.Now().UnixMilli(), 10)))
	alertLog.Time = pointer.Of(data.CreateTime.Format("2006-01-02 15:04:05.000"))
	alertLog.LineInfo = pointer.Of(svc.Config.Session.Push.LineInfo)
	alertLog.LineInfo = pointer.Of(data.LineNo)

	//默认值
	baseIpInfo := base.IP_INFO{
		Ip:          pointer.Of(""),
		Port:        pointer.Of(uint32(0)),
		IpCountry:   pointer.Of(""),
		IpStat:      pointer.Of(""),
		IpCity:      pointer.Of(""),
		IpOrg:       pointer.Of(""),
		IpLongitude: pointer.Of(0.0),
		IpLatitude:  pointer.Of(0.0),
		IpIsp:       pointer.Of(""),
		IpAsn:       pointer.Of(""),
	}
	alertLog.Sip = &base.IP_INFO{
		Ip:          pointer.Of(data.SrcIP),
		Port:        pointer.Of(uint32(data.SrcPort)),
		IpCountry:   pointer.Of(data.SrcCountry),
		IpStat:      pointer.Of(data.SrcProvince),
		IpCity:      pointer.Of(data.SrcCity),
		IpOrg:       pointer.Of(""),
		IpLongitude: pointer.Of(float64(data.LongitudeSrc)),
		IpLatitude:  pointer.Of(float64(data.LatitudeSrc)),
		IpIsp:       pointer.Of(""),
		IpAsn:       pointer.Of(""),
	}
	alertLog.Dip = &base.IP_INFO{
		Ip:          pointer.Of(data.DstIP),
		Port:        pointer.Of(uint32(data.DstPort)),
		IpCountry:   pointer.Of(data.DstCountry),
		IpStat:      pointer.Of(data.DstProvince),
		IpCity:      pointer.Of(data.DstCity),
		IpOrg:       pointer.Of(""),
		IpLongitude: pointer.Of(float64(data.LongitudeDst)),
		IpLatitude:  pointer.Of(float64(data.LatitudeDst)),
		IpIsp:       pointer.Of(""),
		IpAsn:       pointer.Of(""),
	}
	alertLog.Aip = &baseIpInfo
	alertLog.Vip = &baseIpInfo
	alertLog.IiotAlertInfo = new(message.IIOT_ALERT_INFO)
	alertLog.Severity = pointer.Of(uint32(0))
	alertLog.KillChain = pointer.Of("")
	alertLog.Tactic = pointer.Of("")
	alertLog.Technique = pointer.Of("")
	alertLog.Confidence = pointer.Of("")
	alertLog.IiotAlertInfo.IiotRuleId = pointer.Of(int32(0))
	alertLog.IiotAlertInfo.IiotName = pointer.Of("")
	alertLog.IiotAlertInfo.IiotVul = pointer.Of("")
	alertLog.IiotAlertInfo.IiotRefer = pointer.Of("")
	alertLog.IiotAlertInfo.IiotDetailInfo = pointer.Of("")
	alertLog.IiotAlertInfo.IiotAbnormalType = pointer.Of(int32(0))
	alertLog.SensorIp = pointer.Of(svc.Config.Session.Push.SensorIp)
	alertLog.VendorId = pointer.Of(svc.Config.Session.Push.VendorId)
	alertLog.LRAggregateValue = pointer.Of("")
	alertLog.LRFirstAlertDate = pointer.Of(uint64(time.Now().UnixMilli()))
	alertLog.LRLastAlertDate = pointer.Of(uint64(time.Now().UnixMilli()))
	alertLog.LRAlertTimes = pointer.Of(uint32(1))

	if rule, ok := svc.Cache.SuricataRuleMap[data.SID]; ok {
		var srcIpInfo = base.IP_INFO{
			Ip:          pointer.Of(data.SrcIP),
			Port:        pointer.Of(uint32(data.SrcPort)),
			IpStat:      pointer.Of(data.SrcProvince),
			IpCity:      pointer.Of(data.SrcCity),
			IpCountry:   pointer.Of(data.SrcCountry),
			IpLongitude: pointer.Of(float64(data.LongitudeSrc)),
			IpLatitude:  pointer.Of(float64(data.LatitudeSrc)),
			IpOrg:       pointer.Of(""),
			IpIsp:       pointer.Of(""),
			IpAsn:       pointer.Of(""),
		}
		var dstIpInfo = base.IP_INFO{
			Ip:          pointer.Of(data.DstIP),
			Port:        pointer.Of(uint32(data.DstPort)),
			IpStat:      pointer.Of(data.DstProvince),
			IpCity:      pointer.Of(data.DstCity),
			IpCountry:   pointer.Of(data.DstCountry),
			IpLongitude: pointer.Of(float64(data.LongitudeDst)),
			IpLatitude:  pointer.Of(float64(data.LatitudeDst)),
			IpOrg:       pointer.Of(""),
			IpIsp:       pointer.Of(""),
			IpAsn:       pointer.Of(""),
		}
		//确定受害者和攻击者
		if rule.IsAttack {
			alertLog.Aip = &srcIpInfo
			alertLog.Vip = &dstIpInfo
		} else {
			alertLog.Aip = &dstIpInfo
			alertLog.Vip = &srcIpInfo
		}

		alertLog.Severity = pointer.Of(uint32(rule.Level))
		alertLog.KillChain = pointer.Of(rule.KillChain)
		alertLog.Tactic = pointer.Of(rule.AttackTactic)
		alertLog.Technique = pointer.Of(rule.AttackTechnique)
		alertLog.Confidence = convertConfidence(rule.Confidence)
		alertLog.IiotAlertInfo.IiotRuleId = pointer.Of(int32(data.SID))
		alertLog.IiotAlertInfo.IiotName = pointer.Of(rule.RName)
		if vul, ok := conf.VulnerabilityMap[rule.CorrVuln]; ok {
			alertLog.IiotAlertInfo.IiotVul = pointer.Of(vul.CveCode)
			alertLog.IiotAlertInfo.IiotRefer = pointer.Of(vul.Url)
			alertLog.IiotAlertInfo.IiotDetailInfo = pointer.Of(rule.ThreatDetail + ";" + vul.Detail + ";" + vul.Solution)
		} else {
			alertLog.IiotAlertInfo.IiotRefer = pointer.Of("")
			alertLog.IiotAlertInfo.IiotDetailInfo = pointer.Of("")
		}
		alertLog.IiotAlertInfo.IiotAbnormalType = pointer.Of(int32(data.ErrType))
	}

	alertLog.DetectType = pointer.Of(uint32(103)) //工业控制检测
	alertLog.ThreatType = ThreatType[data.EventType]
	if alertLog.ThreatType == nil {
		alertLog.ThreatType = proto.Uint32(0)
	}
	alertLog.TranProto = pointer.Of(data.TransportLayer)
	alertLog.AppProto = pointer.Of(data.Protocol)
	alertLog.IiotAlertInfo.IiotVendor = pointer.Of(data.Vendor)
	alertLog.IiotAlertInfo.IiotDeviceType = pointer.Of(data.DeviceType)
	alertLog.IiotAlertInfo.IiotModel = pointer.Of(data.Model)

	metaData := fillMetaData(data, conf)
	if metaData != nil {
		marshal, err := proto.Marshal(metaData)
		if err == nil {
			alertLog.MetaData = marshal
		}
	}

	alertLog.IiotAlertInfo.IiotAlertType = convertAlertType(data.ProtocolType)
	alertLog.IiotAlertInfo.IiotAnalysis = pointer.Of(data.Action)
	alertLog.IiotAlertInfo.IiotActionType = convertActionType(data.ActionClassCode)
	return &alertLog
}

func updateStatisticMap(successOrFail bool) {
	lock.Lock()
	key := condition.TernaryOperator(successOrFail, "push_success", "push_fail")
	_, ok := maps[key]
	if !ok {
		maps[key] = 1
	} else {
		maps[key] += 1
	}
	lock.Unlock()
}

func convertAlertType(protocolType uint8) *int32 {
	var r int32
	if protocolType == 1 {
		r = 2
	} else if protocolType == 2 {
		r = 3
	} else {
		r = 1
	}
	return &r
}

func convertConfidence(ruleConfidence int) *string {
	var result string
	if ruleConfidence >= 80 {
		result = "高"
	} else if ruleConfidence >= 60 {
		result = "中"
	} else {
		result = "低"
	}
	return &result
}

func convertActionType(actionClassCode int32) *int32 {
	var result int32
	if actionClassCode != 0 {
		result = actionClassCode
	} else {
		result = 99
	}
	return &result
}

func sendMessage(alertLog *push_model.ALERT_LOG) {
	data, err := proto.Marshal(alertLog)
	if err != nil {
		logrus.Errorln("protobuf marshal error:", err.Error())
		updateStatisticMap(false)
		return
	}

	if err = kafkaProducer.WriteMessages(context.Background(), kafka.Message{Value: data}); err != nil {
		logrus.Errorln("kafka send message error:", err.Error())
		updateStatisticMap(false)
	} else {
		updateStatisticMap(true)
	}
}

func timingSave(svc *internal.ServiceContext) {
	lock.Lock()
	s := maps["push_success"]
	f := maps["push_fail"]
	maps["push_success"] = 0
	maps["push_fail"] = 0
	lock.Unlock()
	if s == 0 && f == 0 {
		return
	}

	if err := svc.DB.Create(&DataPushStatistics{
		ID:       nil,
		SendTime: time.Now(),
		Success:  s,
		Fail:     f,
		DataType: "聚合告警日志",
	}).Error; err != nil {
		logrus.Errorln("[聚合告警日志]外部推送统计结果入库失败!", err.Error())
		return
	}
	svc.DB.Model(&DataPushConfig{}).Where("data_type = ? and status = ?", "聚合告警日志", "1").Update("send_last_time", time.Now())
}
