package model

import "time"

type AssetType uint8

const (
	Other AssetType = iota + 1 //其它类型
	OT                         //工控类型
	IoT                        //物联网类型
)

// BuiltInAsset 内置资产库
type BuiltInAsset struct {
	ID              string    `gorm:"type:UUID;default:generateUUIDv4()" json:"id"` // 主键ID
	IP              string    `gorm:"not null" json:"ip"`                           // IP 地址
	OpenPort        uint16    `gorm:"not null" json:"open_port"`                    // 开放端口
	Protocol        string    `gorm:"not null" json:"protocol"`                     // 使用协议
	Service         string    `gorm:"not null" json:"service"`                      // 使用协议
	Type            int       `gorm:"not null" json:"type"`                         // 资产类型
	Vendor          string    `json:"vendor,omitempty"`                             // 设备厂商
	DeviceType      string    `json:"device_type,omitempty"`                        // 设备类型
	Model           string    `gorm:"not null" json:"model"`                        // 设备型号
	CPUModel        string    `json:"cpu_model,omitempty"`                          // CPU 型号
	FirmwareVersion string    `json:"firmware_version,omitempty"`                   // 固件版本
	Information     string    `gorm:"type:text" json:"information,omitempty"`       // 资产信息
	Operator        string    `json:"operator,omitempty"`                           // 运营商
	Company         string    `json:"company,omitempty"`                            // 企业
	CveIds          string    `json:"cve_ids,omitempty"`                            // CVE_IDS
	Longitude       float32   `json:"longitude,omitempty"`                          // 经度
	Latitude        float32   `json:"latitude,omitempty"`                           // 纬度
	Country         string    `json:"country,omitempty"`                            // 国家
	Province        string    `json:"province,omitempty"`                           // 省份
	City            string    `json:"city,omitempty"`                               // 城市
	IsSrc           bool      `gorm:"not null" json:"is_src"`                       // 是否单项识别
	IsSystem        int       `gorm:"not null;size:1" json:"is_system"`             //是否是系统内置：1是；2否
	CreateTime      time.Time `gorm:"" json:"-"`                                    // 创建时间
}

func (*BuiltInAsset) TableName() string {
	return "builtin_asset"
}

// AssetInsight 资产分析库
type AssetInsight struct {
	ID              string    `gorm:"primaryKey" json:"id"`                   // 资产编号
	IP              string    `gorm:"not null" json:"ip"`                     // IP 地址
	OpenPort        uint16    `gorm:"not null" json:"open_port"`              // 开放端口
	Protocol        string    `gorm:"not null" json:"protocol"`               // 使用协议
	Type            AssetType `gorm:"not null" json:"type"`                   // 资产类型（1、其他，2：ics，3：iot）
	Vendor          string    `json:"vendor,omitempty"`                       // 设备厂商
	DeviceType      string    `json:"device_type,omitempty"`                  // 设备类型
	Model           string    `json:"model,omitempty"`                        // 设备型号
	CPUModel        string    `json:"cpu_model,omitempty"`                    // CPU 型号
	CPUType         string    `json:"cpu_type,omitempty"`                     // CPU 类型
	FirmwareVersion string    `json:"firmware_version,omitempty"`             // 固件版本
	IsOnline        bool      `gorm:"not null" json:"is_online"`              // 是否在在线资产中
	Information     string    `gorm:"type:text" json:"information,omitempty"` // 资产信息
	Operator        string    `json:"operator,omitempty"`                     // 运营商
	Longitude       float32   `json:"longitude,omitempty"`                    // 经度
	Latitude        float32   `json:"latitude,omitempty"`                     // 纬度
	Country         string    `json:"country,omitempty"`                      // 国家
	Province        string    `json:"province,omitempty"`                     // 省份
	City            string    `json:"city,omitempty"`                         // 城市
	IsSrc           bool      `gorm:"not null" json:"is_src"`                 // 是否单项识别
	IsBuiltin       bool      `gorm:"not null" json:"is_builtin"`             // 是否是内置资产匹配
	CreateTime      time.Time `gorm:"not null" json:"create_time"`            // 创建时间
	UpdateTime      time.Time `gorm:"not null" json:"update_time"`            // 更新时间
	AttackedCount   int       `gorm:"not null" json:"attacked_count"`         // 被攻击次数
	Direction       bool      `gorm:"column:direction" json:"direction"`      // 方向 true-双向 false-单向
	DataByte        string    `gorm:"column:pkt;type:text" json:"pkt"`        // 二进制数据块
}

func (*AssetInsight) TableName() string {
	return "asset_insight"
}
