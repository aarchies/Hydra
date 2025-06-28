package session

import (
	"dissect/internal/model"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"
)

type Session struct {
	Id        string                `gorm:"column:id;primaryKey" json:"id"`       // 会话id
	List      []*model.ConsumerData `gorm:"-" json:"list"`                        // 会话包列表
	Interval  time.Duration         `gorm:"-" json:"interval"`                    // 会话间隔
	fd        *os.File              `gorm:"-"`                                    // 文件句柄
	w         *pcapgo.Writer        `gorm:"-"`                                    // pcap句柄
	key       string                `gorm:"-"`                                    // 会话key
	tuple     string                `gorm:"-"`                                    // 会话元组
	renewalCh chan struct{}         `gorm:"-"`                                    // 续租通道
	Path      string                `gorm:"column:path" json:"path"`              // 包路径
	Src       string                `gorm:"column:src" json:"src"`                // 源IP
	SrcPort   uint16                `gorm:"column:src_port" json:"src_port"`      // 源端口
	Dst       string                `gorm:"column:dst" json:"dst"`                // 目的IP
	DstPort   uint16                `gorm:"column:dst_port" json:"dst_port"`      // 目的端口
	Protocol  string                `gorm:"column:protocol" json:"protocol"`      // 协议
	Start     time.Time             `gorm:"column:create_time" json:"start_time"` // 开始时间
	End       time.Time             `gorm:"column:end_time" json:"end_time"`      // 结束时间
}

func (*Session) TableName() string {
	return "session"
}

type Config struct {
	Switch              string                                  `json:"switch,omitempty"`                 // 推送过滤开关(0-关,1-开)
	VulnerabilityMap    map[string]*Vulnerability               `json:"vulnerability_map,omitempty"`      // 漏洞规则
	FilterIp            map[string]uint8                        `json:"filter_ip,omitempty"`              // 处理后的过滤规则, 端口为空或0的
	FilterIpAndPort     map[string]uint8                        `json:"filter_ip_and_port,omitempty"`     // 处理后的过滤规则, 有ip有端口的
	DataPushConfig      *DataPushConfig                         `json:"data_push_config,omitempty"`       // 聚合告警信息推送配置
	ReportMetaConfigMap map[string]map[string]*ReportMetaConfig `json:"report_meta_config_map,omitempty"` // 上报元数据配置
}

// ReportMetaConfig 上报元数据配置
type ReportMetaConfig struct {
	ID           int64     `gorm:"primaryKey" json:"id"`                      // ID
	Protocol     string    `gorm:"column:protocol" json:"protocol"`           // 协议
	ProtocolCode string    `gorm:"column:protocol_code" json:"protocol_code"` // 协议代码
	Tlv          string    `gorm:"column:tlv" json:"tlv"`                     // TLV值
	Filed        string    `gorm:"column:filed" json:"filed"`                 // filed
	FiledZh      string    `gorm:"column:filed_zh" json:"filed_zh"`           // filed 中文
	FiledType    string    `gorm:"column:filed_type" json:"filed_type"`       // filed types
	SearchKey    string    `gorm:"column:search_key" json:"search_key"`       // 命中关键字
	CreateTime   time.Time `gorm:"not null" json:"create_time"`               // 创建时间
	UpdateTime   time.Time `gorm:"not null" json:"update_time"`               // 更新时间

}

func (*ReportMetaConfig) TableName() string {
	return "report_meta_config"
}

// SwitchConfig 推送开关配置
type SwitchConfig struct {
	Id     uint64 `gorm:"column:id;primaryKey;autoIncrement" json:"id"` // 规则编号
	Param  string `gorm:"column:param" json:"param"`                    // 参数名
	Value1 string `gorm:"column:value1" json:"value1"`                  // IP
	Value2 string `gorm:"column:value2" json:"value2"`                  // 端口
	Value3 string `gorm:"column:value3" json:"value3"`                  // 设备码
	Value4 string `gorm:"column:value4" json:"value4"`                  // 推送开关
}

func (*SwitchConfig) TableName() string {
	return "config"
}

// Vulnerability 漏洞库
type Vulnerability struct {
	//ID        int    `gorm:"primaryKey" json:"id"`             // 主键ID
	CveCode  string `gorm:"not null" json:"cve_code"`         // 漏洞编号
	CveName  string `gorm:"not null" json:"cve_name"`         // 漏洞名称
	Detail   string `gorm:"type:text;not null" json:"detail"` // 漏洞详情
	Solution string `gorm:"not null" json:"solution"`         // 修复方案
	//Influence string `gorm:"not null" json:"influence"`        // 受影响软件情况
	Url string `gorm:"not null" json:"url"` // 漏洞链接
	//IsSystem  int    `gorm:"not null;size:1" json:"-"`         //是否是系统内置：1是；2否
}

func (*Vulnerability) TableName() string {
	return "vulnerability"
}

// DataPushConfig 数据推送配置
type DataPushConfig struct {
	ID       int    `gorm:"column:id;primaryKey" json:"id"`    // ID
	Name     string `gorm:"column:name" json:"name"`           // 名称
	URL      string `gorm:"column:url" json:"url"`             // URL
	DataType string `gorm:"column:data_type" json:"data_type"` // 数据类型
	//Params       string     `gorm:"column:params" json:"params"`                   // 参数
	//DataFormat   string     `gorm:"column:data_format" json:"data_format"`         // 数据格式(json或xml,现在仅有json)
	Header       string     `gorm:"column:header" json:"header"`                   // 请求头
	Topic        string     `gorm:"column:topic" json:"topic"`                     // topic
	Status       int        `gorm:"column:status" json:"status"`                   // 是否启用(1-启用,0-不启用)
	IsDeleted    int        `gorm:"column:is_deleted;default:0" json:"is_deleted"` //删除标志(1-删除)
	CreateTime   time.Time  `gorm:"not null" json:"create_time"`                   // 创建时间
	UpdateTime   time.Time  `gorm:"not null" json:"update_time"`                   // 更新时间
	SendLastTime *time.Time `gorm:"type:datetime" json:"send_last_time"`           // SendLastTime 表示资源项的最后发送时间
}

func (*DataPushConfig) TableName() string {
	return "data_push_config"
}

// DataPushStatistics 数据推送统计
type DataPushStatistics struct {
	ID       *int      `gorm:"primaryKey" json:"id"`                                  // ID 表示日志项的唯一标识符。
	SendTime time.Time `json:"send_time,omitempty" gorm:"type:datetime;comment:发送时间"` // SendTime 表示日志项的发送时间。
	Success  uint      `json:"success,omitempty"`                                     // Success 表示日志项的成功状态。
	Fail     uint      `json:"fail,omitempty"`                                        // Fail 表示日志项的失败状态。
	DataType string    `json:"data_type,omitempty"`                                   // DataType 表示日志项的数据类型。
}

func (*DataPushStatistics) TableName() string {
	return "data_push_statistics"
}

// Response 推送后形成收到的响应
type Response struct {
	Code int         `json:"code"`
	Data interface{} `json:"data"`
	Msg  string      `json:"msg"`
}
