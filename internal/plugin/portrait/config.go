package portrait

import (
	"encoding/json"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type config struct {
	Dictionary map[string]dictionary
}

type dictionary struct {
	FuncCode struct {
		Read  []string
		Write []string
	}
	Fields []string
	Enable bool
}

// 资产链路
type AssetLink struct {
	ID         string    `gorm:"type:UUID;default:generateUUIDv4()" json:"id"`             // 主键ID
	AssetId    string    `gorm:"column:asset_id;type:Varchar(255)" json:"asset_id"`        // 资产ID
	Localtion  string    `gorm:"column:localtion;type:Varchar(255)" json:"localtion"`      // 位置
	Links      string    `gorm:"column:links;type:Varchar(255)" json:"links"`              // 链路
	IPS        string    `gorm:"column:ips;type:Varchar(255)" json:"ips"`                  // IP地址
	Detail     string    `gorm:"column:detail;type:Varchar(255)" json:"detail"`            // 详情
	CreateTime time.Time `gorm:"column:create_time;type:DateTime64(9)" json:"create_time"` // 插入时间
}

func (m *AssetLink) TableName() string {
	return "link_asset"
}

// 资产画像
type AssetPortrait struct {
	ID         string            `gorm:"type:UUID;default:generateUUIDv4()" json:"id"` // 主键ID
	AssetID    string            `gorm:"column:asset_id" json:"asset_id"`              // 资产ID
	VulnIds    []int64           `gorm:"-" json:"vuln_ids"`                            // 漏洞ID
	Protocol   string            `gorm:"column:protocol" json:"protocol"`              // 协议
	UserName   string            `gorm:"column:username" json:"username"`              // 账号
	Passwd     string            `gorm:"column:passwd" json:"passwd"`                  // 密码
	Fields     map[string]string `gorm:"-" json:"fields"`                              // 字段
	FieldsStr  string            `gorm:"column:fields" json:"-"`                       // json string
	Script     []Script          `gorm:"-" json:"script_path"`                         // 脚本
	ScriptStr  string            `gorm:"column:script" json:"-"`                       // json string
	CreateTime time.Time         `gorm:"column:create_time" json:"create_time"`
}

type Script struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

func (*AssetPortrait) TableName() string {
	return "portrait_asset"
}

func (data *AssetPortrait) BeforeCreate(tx *gorm.DB) (err error) {
	data.CreateTime = time.Now()

	if len(data.Script) > 0 {
		bytes, err := json.Marshal(data.Script)
		if err != nil {
			logrus.Errorf("json marshal error: %v", err)
		}
		tx.Statement.SetColumn("script", string(bytes))
	}

	if len(data.Fields) > 0 {
		fieldBytes, err := json.Marshal(data.Fields)
		if err != nil {
			logrus.Errorf("json marshal error: %v", err)
		}
		tx.Statement.SetColumn("fields", string(fieldBytes))
	}

	if len(data.VulnIds) > 0 {
		vulnIdsBytes, err := json.Marshal(data.VulnIds)
		if err != nil {
			logrus.Errorf("json marshal error: %v", err)
		}
		tx.Statement.SetColumn("vuln_ids", string(vulnIdsBytes))
	}

	return nil
}

func (data *AssetPortrait) UnMarshalScript() {
	if err := json.Unmarshal([]byte(data.ScriptStr), &data.Script); err != nil {
		logrus.Errorf("json unmarshal error: %v", err)
	}
}

func (data *AssetPortrait) UnMarshalFields() {
	if err := json.Unmarshal([]byte(data.FieldsStr), &data.Fields); err != nil {
		logrus.Errorf("json unmarshal error: %v", err)
	}
}

type AssetPointInfo struct {
	Id         string    `gorm:"type:UUID;default:generateUUIDv4()" json:"id"` // 主键ID
	AssetID    string    `gorm:"column:asset_id" json:"asset_id"`              // 资产ID
	Lable      string    `gorm:"column:lable" json:"lable"`                    // 字段
	Value      string    `gorm:"column:value" json:"value"`                    // 值
	CreateTime time.Time `gorm:"column:create_time" json:"create_time"`
}

func (*AssetPointInfo) TableName() string {
	return "portrait_point"
}
