package config

type FingerPrintAsset struct {
	ID                       int64  `gorm:"primaryKey" json:"id"`             // 指纹库编号
	DeviceName               string `gorm:"not null" json:"device_name"`      // 资产名称
	Vendor                   string `gorm:"not null" json:"vendor"`           // 厂商
	Type                     int    `gorm:"not null;size:1" json:"type"`      // 资产类别
	DeviceType               string `gorm:"not null" json:"device_type"`      // 资产类型
	Desc                     string `json:"desc,omitempty"`                   // 描述
	Protocol                 string `gorm:"not null" json:"protocol"`         // 协议
	Ports                    string `gorm:"not null" json:"ports"`            // 端口
	DeviceModel              string `json:"device_model"`                     // 设备型号
	DeviceModelIsAscii       bool   `json:"device_model_is_ascii"`            // 设备型号是否ascii
	DeviceModelRegexRule     string `json:"device_model_regex_rule"`          // 设备型号正则规则
	CpuType                  string `json:"cpu_type"`                         // cpu类型
	CpuTypeIsAscii           bool   `json:"cpu_type_is_ascii"`                // cpu类型是否ascii
	CpuTypeRegexRule         string `json:"cpu_type_regex_rule"`              // cpu类型正则规则
	CpuModel                 string `json:"cpu_model"`                        // cpu模型
	CpuModelIsAscii          bool   `json:"cpu_model_is_ascii"`               // cpu模型是否ascii
	CpuModelRegexRule        string `json:"cpu_model_regex_rule"`             // cpu模型正则规则
	FirmwareVersion          string `json:"firmware_version"`                 // 固件版本
	FirmwareVersionIsAscii   bool   `json:"firmware_version_is_ascii"`        // 固件版本是否ascii
	FirmwareVersionRegexRule string `json:"firmware_version_regex_rule"`      // 固件版本正则规则
	IsSystem                 int    `gorm:"not null;size:1" json:"is_system"` //是否是系统内置：1是；2否
}

func (*FingerPrintAsset) TableName() string {
	return "asset_protocol_finger"
}

func (f *FingerPrintAsset) HandleRules(rules map[string]Rule) map[string]Rule {
	if f.DeviceModel != "" {
		rules[f.DeviceModel] = Rule{
			Name:      "device_model",
			Vendor:    f.Vendor,
			IsAscii:   f.DeviceModelIsAscii,
			RegexRule: f.DeviceModelRegexRule,
		}
	}
	if f.CpuType != "" {
		rules[f.CpuType] = Rule{
			Name:      "cpu_type",
			Vendor:    f.Vendor,
			IsAscii:   f.CpuTypeIsAscii,
			RegexRule: f.CpuTypeRegexRule,
		}
	}
	if f.CpuModel != "" {
		rules[f.CpuModel] = Rule{
			Name:      "cpu_model",
			Vendor:    f.Vendor,
			IsAscii:   f.CpuModelIsAscii,
			RegexRule: f.CpuModelRegexRule,
		}
	}
	if f.FirmwareVersion != "" {
		rules[f.FirmwareVersion] = Rule{
			Name:      "firmware_version",
			Vendor:    f.Vendor,
			IsAscii:   f.FirmwareVersionIsAscii,
			RegexRule: f.FirmwareVersionRegexRule,
		}
	}
	return rules
}

type AssetProtocolFinger struct {
	DeviceName string `json:"device_name"`    // 资产名称
	Type       int    `json:"type"`           // 资产类别
	DeviceType string `json:"device_type"`    // 资产类型
	Desc       string `json:"desc,omitempty"` // 描述
	Protocol   string `json:"protocol"`       // 协议
	Port       string `json:"port"`           // 端口
	Rules      map[string]Rule
}

type Rule struct {
	Name      string `json:"name"`       // 显示名称
	Vendor    string `json:"vendor"`     // 厂商
	IsAscii   bool   `json:"is_ascii"`   // 是否是ascii编码
	RegexRule string `json:"regex_rule"` // 正则规则
}
