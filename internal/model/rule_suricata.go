package model

import "time"

// SuricataRule 入侵检测规则库
type SuricataRule struct {
	ID               int       `gorm:"primaryKey" json:"id"`                    // 规则编号
	RName            string    `gorm:"not null" json:"r_name"`                  // 规则名称
	RContent         string    `gorm:"type:text;not null" json:"r_content"`     // 规则内容
	Proto            string    `gorm:"not null" json:"proto"`                   // 协议
	SIp              string    `gorm:"not null" json:"s_ip"`                    // 源IP
	SPort            string    `gorm:"not null" json:"s_port"`                  // 源端口
	Direction        string    `gorm:"not null" json:"direction"`               // 方向
	DIp              string    `gorm:"not null" json:"d_ip"`                    // 目的IP
	DPort            string    `gorm:"not null" json:"d_port"`                  // 目的端口
	EventType        string    `gorm:"not null" json:"event_type"`              // 事件类型
	Level            uint8     `gorm:"not null" json:"level"`                   // 等级
	CorrVuln         string    `gorm:"not null" json:"corr_vuln"`               // 关联漏洞
	IsEnabled        bool      `gorm:"not null;size:1" json:"is_enabled"`       // 是否启用：1是；2否
	OriginalRule     string    `gorm:"type:text;not null" json:"original_rule"` // 原始规则
	RuleType         bool      `gorm:"not null" json:"rule_type"`               // 规则类型 true 代表漏洞，false 代表其他
	CreateTime       time.Time `gorm:"not null" json:"-"`                       // 创建时间
	CreateTimeFormat string    `gorm:"-" json:"create_time"`                    // 创建时间
	IsSystem         int       `gorm:"not null;size:1" json:"is_system"`        // 是否是系统内置：1是；2否
	IsAttack         bool      `gorm:"not null" json:"is_attack"`               // 目标IP是否为受害IP，true:是，false:否
	KillChain        string    `gorm:"not null" json:"kill_chain"`              // 杀伤链
	AttackTactic     string    `gorm:"not null" json:"attack_tactic"`           // ATTACK策略标签
	AttackTechnique  string    `gorm:"not null" json:"attack_technique"`        // ATTACK技术标签
	Confidence       int       `gorm:"not null" json:"confidence"`              // 置信度
	ThreatDetail     string    `gorm:"type:text;not null" json:"threat_detail"` // 威胁详情
}

func (*SuricataRule) TableName() string {
	return "suricata_rule"
}
