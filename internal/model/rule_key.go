package model

// KeyActionRule 关键操作规则库
type KeyActionRule struct {
	ID             int64  `gorm:"primaryKey" json:"id"`                // 资产编号
	ProtocolName   string `gorm:"not null" json:"protocol_name"`       // 协议名称
	FunctionCode   string `gorm:"not null" json:"function_code"`       // 功能码
	ExtractionRule string `gorm:"not null" json:"extraction_rule"`     // 提取规则
	Desc           string `json:"desc,omitempty"`                      // 描述
	Status         bool   `gorm:"not null" json:"status"`              // 是否启用
	IsSystem       int    `gorm:"not null;size:1" json:"is_system"`    //是否是系统内置：1是；2否
	ClassCode      int32  `gorm:"column:class_code" json:"class_code"` //关键操作分类
	ClassName      string `gorm:"column:class_name" json:"class_name"` //关键操作分类名称
}

func (*KeyActionRule) TableName() string {
	return "key_action_rule"
}

type FilterRule struct {
	IP   string `json:"ip" gorm:"column:ip;primaryKey"`
	Port uint16 `json:"port" gorm:"primaryKey;comment:端口;default:0"`
}

func (*FilterRule) TableName() string {
	return "filter_rule"
}
