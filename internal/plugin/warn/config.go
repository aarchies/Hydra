package warn

import (
	"time"

	"github.com/google/uuid"
)

// 自定义类型
//type StrArray []string

// 实现 driver.Valuer 接口，用于插入数据库时的自定义处理  clickhouse 不支持
// func (a StrArray) Value() (driver.Value, error) {
// 	var strArray string
// 	for i, v := range a {
// 		if i > 0 {
// 			strArray += ","
// 		}
// 		strArray += fmt.Sprintf("'%s'", strings.ReplaceAll(v, "'", "''"))
// 	}
// 	return fmt.Sprintf("[%s]", strArray), nil
// }

type (
	Record struct {
		EventId      string
		Ip           string
		Protocol     string
		EventType    string
		ConnectCount int
		IsKey        bool
		IsAttack     bool
		Country      string
		Province     string
		City         string
		StartTime    time.Time
		EndTime      time.Time
		IsErr        bool
		CIP          string
		Level        uint8
		DeviceType   string
		Model        string
		Vendor       string
		Latitude     float32
		Longitude    float32
		Action       string
		ErrType      uint8
	}

	// AlertEvent 告警事件表-攻击维度
	AlertEvent struct {
		ID             uuid.UUID `gorm:"column:id;primaryKey" json:"id"`                             // ID
		Src            []string  `gorm:"type:Array(String)" json:"src"`                              // 源地址
		Protocol       []string  `gorm:"type:Array(String)" json:"protocol"`                         // 协议
		EventType      []string  `gorm:"type:Array(String)" json:"event_type"`                       // 恶意行为类型
		ErrType        []string  `gorm:"type:Array(String)" json:"err_type"`                         // 异常规约类型
		Action         []string  `gorm:"type:Array(String)" json:"action"`                           // 关键操作
		ConnectCount   int       `gorm:"type:Int32" json:"connect_count"`                            // 通信次数
		KeyCount       int       `gorm:"type:Int32" json:"key_count"`                                // 关键操作次数
		AttackCount    int       `gorm:"type:Int32" json:"attack_count"`                             // 攻击次数
		SrcCountry     string    `gorm:"type:String" json:"src_country,omitempty"`                   // 源地址国家
		SrcProvince    string    `gorm:"type:String" json:"src_province,omitempty"`                  // 源地址省份
		SrcCity        string    `gorm:"type:String" json:"src_city,omitempty"`                      // 源地址城市
		SrcLocation    []float32 `gorm:"type:Tuple(Float32, Float32)" json:"src_location,omitempty"` // 源经纬度
		StartTime      time.Time `gorm:"type:DateTime" json:"start_time"`                            // 开始时间
		EndTime        time.Time `gorm:"type:DateTime" json:"end_time"`                              // 结束时间
		ErrCount       int       `gorm:"type:UInt32" json:"err_count"`                               // 异常规约数
		ConnectIpCount int       `gorm:"type:Int32" json:"connect_ip_count"`                         // 通信IP数
		Level          uint8     `gorm:"column:level" json:"level"`                                  // 级别 1-低危 2-中危 3-高危
		Sign           int8      `gorm:"column:sign" json:"sign"`                                    // 标志字段，1 表示插入或更新的数据，-1 表示要删除的数据。
		CreateTime     time.Time `gorm:"column:create_time" json:"create_time"`                      // 创建时间
		ConnectIp      []string  `gorm:"-" json:"connect_ip"`                                        // 通信I
		Version        uint8     `gorm:"-" json:"version"`                                           // 更新版本
	}

	// AlertVictim 告警事件表-被攻击维度
	AlertVictim struct {
		ID             uuid.UUID `gorm:"column:id;primaryKey" json:"id"`                             // ID
		Dst            string    `gorm:"type:String" json:"dst"`                                     // 目的地址
		Protocol       []string  `gorm:"type:Array(String)" json:"protocol"`                         // 协议
		EventType      []string  `gorm:"type:Array(String)" json:"event_type"`                       // 恶意行为类型
		ErrType        []string  `gorm:"type:Array(String)" json:"err_type"`                         // 异常规约类型
		Action         []string  `gorm:"type:Array(String)" json:"action"`                           // 关键操作
		ConnectCount   int       `gorm:"type:Int32" json:"connect_count"`                            // 通信次数
		KeyCount       int       `gorm:"type:Int32" json:"key_count"`                                // 关键操作次数
		AttackCount    int       `gorm:"type:Int32" json:"attack_count"`                             // 攻击次数
		DstCountry     string    `gorm:"type:String" json:"dst_country,omitempty"`                   // 目的地址国家
		DstProvince    string    `gorm:"type:String" json:"dst_province,omitempty"`                  // 目的地址省份
		DstCity        string    `gorm:"type:String" json:"dst_city,omitempty"`                      // 目的地址城市
		DstLocation    []float32 `gorm:"type:Tuple(Float32, Float32)" json:"dst_location,omitempty"` // 目的经纬度
		StartTime      time.Time `gorm:"type:DateTime" json:"start_time"`                            // 开始时间
		EndTime        time.Time `gorm:"type:DateTime" json:"end_time"`                              // 结束时间
		Vendor         string    `gorm:"column:vendor" json:"vendor,omitempty"`                      // 设备厂商
		DeviceType     string    `gorm:"column:device_type" json:"device_type,omitempty"`            // 设备类型
		Model          string    `gorm:"column:model" json:"model,omitempty"`                        // 设备型号
		ErrCount       uint      `gorm:"type:UInt32" json:"err_count"`                               // 异常规约数
		Level          uint8     `gorm:"column:level" json:"level"`                                  // 级别 1-低危 2-中危 3-高危
		ConnectIpCount int       `gorm:"type:Int32" json:"connect_ip_count"`                         // 通信IP数
		Sign           int8      `gorm:"column:sign" json:"sign"`                                    // 标志字段，1 表示插入或更新的数据，-1 表示要删除的数据。
		CreateTime     time.Time `gorm:"column:create_time" json:"create_time"`                      // 创建时间
		ConnectIp      []string  `gorm:"-" json:"connect_ip"`                                        // 通信I
		Version        uint8     `gorm:"-" json:"version"`                                           // 更新版本
	}
)

func (*AlertEvent) TableName() string {
	return "alert_event"
}

func (*AlertVictim) TableName() string {
	return "alert_victim"
}
