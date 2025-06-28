package model

import (
	"dissect/utils"
	"encoding/json"
	"strconv"
	"time"

	"gorm.io/gorm"
)

var ProtocolMap = make(map[string]string)

func init() {
	ProtocolMap["? KNXnet/IP"] = "KNXnet/IP"
}

type ProtocolConfigInfo struct {
	Proto string            `json:"proto"`
	Desc  string            `json:"desc"`
	As    string            `json:"as"`
	Type  uint8             `json:"type"` // 1 其它类型 ; 2 工控类型; 3 物联网类型
	Ports map[uint32]uint32 `json:"ports"`
}

type EdtData struct {
	P    string // Proto
	S    string // Sip
	D    string // Dip
	Desc string // Desc
}

type ProtocolField struct {
	N  string // Name
	SN string // ShowName
	Sz string // Size
	Ps string // Pos
	Sh string // Show
	V  string // Value
}

type ProtocolData struct {
	N  string          // Name
	SN string          // ShowName
	Sz string          // Size
	Ps string          // Pos
	F  []ProtocolField // Fields
	FL int             // FieldsLen
}

type PacketResult struct {
	PI EdtData        // PacketInfo
	P  []ProtocolData // ProtocolInfo
	PL int            // ProtocolLen
	S  bool           // 是否保存
}

// ProducerData 生产的数据结构
type ProducerData struct {
	DataByte  []byte // 二进制数据块
	LineNo    string // 线路号
	TaskID    string // 任务ID
	Direction uint8  // 0,其他，1 客户端向服务端 2 服务端向客户端
	IsAlert   bool   // 是否是攻击
	SId       int    // 事件id
	ClassType string // 事件类型
	EventMSG  string // 事件描述
}

// ConsumerData 消费的数据
type ConsumerData struct {
	NegTimestamp    int64          `gorm:"column:neg_timestamp;type:Int64" json:"neg_timestamp"`     // 插入时间时间戳负值 -id
	SessionID       string         `gorm:"column:session_id" json:"session_id"`                      // 会话ID
	TaskID          string         `gorm:"column:task_id" json:"task_id"`                            // 任务ID
	LineNo          string         `gorm:"column:line_no" json:"line_no,omitempty"`                  // 线路号
	EventID         string         `gorm:"column:event_id" json:"event_id"`                          // 事件ID
	VictimID        string         `gorm:"column:victim_id" json:"victim_id"`                        // 被攻击事件ID
	DataByte        []byte         `gorm:"column:pkt;type:text" json:"pkt"`                          // 二进制数据块
	CreateTime      time.Time      `gorm:"column:create_time;type:DateTime64(9)" json:"create_time"` // 插入时间
	Direction       uint8          `gorm:"column:direction" json:"direction"`                        // 0,其他，1 客户端向服务端 2 服务端向客户端
	SrcMac          string         `gorm:"column:src_mac" json:"src_mac"`                            // MAC 地址
	SrcIP           string         `gorm:"column:src" json:"src"`                                    // 源 IP
	SrcPort         uint16         `gorm:"column:sport" json:"sport"`                                // 源端口
	DstMac          string         `gorm:"column:dst_mac" json:"dst_mac"`                            // 目的 MAC 地址
	DstIP           string         `gorm:"column:dst" json:"dst"`                                    // 目的 IP
	DstPort         uint16         `gorm:"column:dport" json:"dport"`                                // 目的端口
	Protocol        string         `gorm:"column:protocol" json:"protocol"`                          // 协议
	ProtocolType    uint8          `gorm:"column:protocol_type" json:"protocol_type"`                // 协议类型（其他1，2：ics，3：iot，默认0）
	TransportLayer  string         `gorm:"column:transport_layer" json:"transport_layer"`            // 传输层协议
	EThType         string         `gorm:"column:eth_type" json:"eth_type"`                          // 以太网类型
	IPVersion       string         `gorm:"column:ip_version" json:"ip_version"`                      // IP 版本
	Action          string         `gorm:"column:action" json:"action"`                              // 行为
	SID             int            `gorm:"column:sid" json:"sid"`                                    // 攻击事件规则ID
	EventType       string         `gorm:"column:event_type" json:"event_type"`                      // 入侵检测类型
	EventDesc       string         `gorm:"column:event_desc" json:"event_desc"`                      // 入侵检测描述
	IsAttack        bool           `gorm:"column:is_attack" json:"is_attack"`                        // 是否是攻击
	ErrType         uint8          `gorm:"column:err_type" json:"err_type"`                          // 异常规约类型,0：正常，1 数据包格式错误 2、数据包的实际长度与协议头中声明的长度不一致 3、"未知功能码",未知命令，4."状态异常"、
	IsKey           bool           `gorm:"column:is_key" json:"is_key"`                              // 是否关键操作
	IsVul           bool           `gorm:"column:is_vul" json:"is_vul"`                              // 是否是漏洞利用
	EventLevel      uint8          `gorm:"column:event_level" json:"event_level"`                    // 事件等级
	Vul             string         `gorm:"column:vul" json:"vul"`                                    // 漏洞
	SrcCountry      string         `gorm:"column:src_country" json:"src_country"`                    // 源地址国家
	DstCountry      string         `gorm:"column:dst_country" json:"dst_country"`                    // 目的地址国家
	SrcProvince     string         `gorm:"column:src_province" json:"src_province"`                  // 源地址省份
	DstProvince     string         `gorm:"column:dst_province" json:"dst_province"`                  // 目的地址省份
	SrcCity         string         `gorm:"column:src_city" json:"src_city"`                          // 源地址城市
	DstCity         string         `gorm:"column:dst_city" json:"dst_city"`                          // 目的地址城市
	LatitudeSrc     float32        `gorm:"column:latitude_src" json:"latitude_src"`                  // 源经度
	LongitudeSrc    float32        `gorm:"column:longitude_src" json:"longitude_src"`                // 纬度
	LatitudeDst     float32        `gorm:"column:latitude_dst" json:"latitude_dst"`                  // 目的经度
	LongitudeDst    float32        `gorm:"column:longitude_dst" json:"longitude_dst"`                // 目的纬度
	Vendor          string         `gorm:"column:vendor" json:"vendor"`                              // 设备厂商
	DeviceType      string         `gorm:"column:device_type" json:"device_type"`                    // 设备类型
	Model           string         `gorm:"column:model" json:"model"`                                // 设备型号
	MetaRaw         string         `gorm:"column:meta" json:"-"`                                     // 原始元数据
	ActionClassCode int32          `gorm:"-" json:"action_class_code"`                               // 关键操作分类
	Meta            []ProtocolData `gorm:"-" json:"meta"`                                            // 解析元数据
}

func (*ConsumerData) TableName() string {
	return "meta_data"
}

func (data *ConsumerData) BeforeCreate(tx *gorm.DB) (err error) {

	metaBytes, err := json.Marshal(data.Meta)
	if err != nil {
		return err
	}

	defer func() {
		metaBytes = nil
	}()

	tx.Statement.SetColumn("meta", string(metaBytes))
	return nil
}

func (data *ConsumerData) AfterFind(tx *gorm.DB) (err error) {
	var meta []ProtocolData
	if err = json.Unmarshal([]byte(data.MetaRaw), &meta); err != nil {
		return err
	}
	data.Meta = meta
	return nil
}

// DistTuple 目的地址元组（传输层）
func (data *ConsumerData) DistTuple() string {
	return data.DstIP + "-" + strconv.Itoa(int(data.DstPort)) + "-" + data.SrcIP + "-" + strconv.Itoa(int(data.SrcPort)) + "-" + data.TransportLayer
}

// DistAppTuple 目的地址元组（应用层）
func (data *ConsumerData) DistAppTuple() string {
	return data.DstIP + "-" + strconv.Itoa(int(data.DstPort)) + "-" + data.SrcIP + "-" + strconv.Itoa(int(data.SrcPort)) + "-" + data.TransportLayer
}

// SrcTuple 源地址元组（传输层）
func (data *ConsumerData) SrcTuple() string {
	return data.SrcIP + "-" + strconv.Itoa(int(data.SrcPort)) + "-" + data.DstIP + "-" + strconv.Itoa(int(data.DstPort)) + "-" + data.TransportLayer
}

// SrcAppTuple 源地址元组（应用层）
func (data *ConsumerData) SrcAppTuple() string {
	return data.SrcIP + "-" + strconv.Itoa(int(data.SrcPort)) + "-" + data.DstIP + "-" + strconv.Itoa(int(data.DstPort)) + "-" + data.Protocol
}

func (data *ConsumerData) ETH(fields []ProtocolField) {
	for _, field := range fields {
		switch field.N {
		case "eth.type":
			data.EThType = field.V
		case "eth.src":
			data.SrcMac = field.V
		case "eth.dst":
			data.DstMac = field.V
		}
	}
}

func (data *ConsumerData) IP(fields []ProtocolField) {
	for _, field := range fields {
		switch field.N {
		case "ip.src":
			data.SrcIP = field.V
		case "ip.dst":
			data.DstIP = field.V
		case "ip.version":
			data.IPVersion = field.V
		}
	}
}

func (data *ConsumerData) TCP(fields []ProtocolField) {
	for _, field := range fields {
		switch field.N {
		case "tcp.srcport":
			data.SrcPort = utils.StrChangeUnit16(&field.V)
		case "tcp.dstport":
			data.DstPort = utils.StrChangeUnit16(&field.V)
		}
	}
}

func (data *ConsumerData) UDP(fields []ProtocolField) {
	for _, field := range fields {
		switch field.N {
		case "udp.srcport":
			data.SrcPort = utils.StrChangeUnit16(&field.V)
		case "udp.dstport":
			data.DstPort = utils.StrChangeUnit16(&field.V)
		}
	}
}

func (data *ConsumerData) GeoIP(geoIp *utils.GeoIP, protocolMap map[string]*ProtocolConfigInfo) {
	// if value, ok := ProtocolMap[data.Protocol]; ok {
	// 	data.Protocol = value
	// }

	// for _, suffix := range []string{".pcap", ".pncap", ".pnc", ".cap", ".erf", ".snoop", ".dmp"} {
	// 	if strings.HasSuffix(data.LineNo, suffix) {
	// 		data.LineNo = strings.TrimSuffix(data.LineNo, suffix)
	// 		break
	// 	}
	// }

	if value, ok := protocolMap[data.Protocol]; ok {
		data.ProtocolType = value.Type
		if data.Direction == 0 {
			if value.Type == 1 || value.Type == 2 {
				if _, exists := value.Ports[uint32(data.SrcPort)]; exists {
					// key 存在于 myMap 中，可以访问其对应的 value
					data.Direction = 2
				} else if _, exists := value.Ports[uint32(data.DstPort)]; exists {
					// key 不存在于 myMap 中
					data.Direction = 1
				}
			}
		}
	}

	srcLocation, err := geoIp.GetLocation(data.SrcIP)
	if err == nil {
		data.SrcCity = srcLocation.City
		data.SrcProvince = srcLocation.Province
		data.SrcCountry = srcLocation.Country
		data.LongitudeSrc = srcLocation.Longitude
		data.LatitudeSrc = srcLocation.Latitude
	}

	dstLocation, err := geoIp.GetLocation(data.DstIP)
	if err == nil {
		data.DstCity = dstLocation.City
		data.DstProvince = dstLocation.Province
		data.DstCountry = dstLocation.Country
		data.LongitudeDst = dstLocation.Longitude
		data.LatitudeDst = dstLocation.Latitude
	}

	ch, err := utils.LineNoConvert(data.LineNo)
	if err == nil {
		data.LineNo = ch
	}
}
