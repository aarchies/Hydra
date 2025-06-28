package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	DB struct {
		Mysql struct {
			Hosts       []string `yaml:"hosts"`
			Port        int      `yaml:"port"`
			UserName    string   `yaml:"username"`
			PassWord    string   `yaml:"password"`
			DataBase    string   `yaml:"dataBase"`
			MaxIdleConn int      `yaml:"max-idle-conn"` // 空闲中的最大连接数
			MaxOpenConn int      `yaml:"max-open-conn"` // 打开到数据库的最大连接数
			Config      string   `yaml:"config"`        // 高级配置
			LogMode     string   `yaml:"log-mode"`      // 是否开启Gorm全局日志
		} `yaml:"mysql"`
		Clickhouse struct {
			Hosts       []string `yaml:"hosts"`
			UserName    string   `yaml:"username"`
			PassWord    string   `yaml:"password"`
			DataBase    string   `yaml:"dataBase"`
			MaxIdleConn int      `yaml:"max-idle-conn"` // 空闲中的最大连接数
			MaxOpenConn int      `yaml:"max-open-conn"` // 打开到数据库的最大连接数
			IsDebug     bool     `yaml:"is_debug"`
		} `yaml:"clickhouse"`
	} `yaml:"db"`
	System struct {
		Path            string `yaml:"path"`              // root path
		LocationFile    string `yaml:"location_file"`     // 地理位置文件
		ProtocolMapFile string `yaml:"protocol_file"`     // 协议文件
		PortraitMapFile string `yaml:"portrait_map_file"` // 画像文件
		ProtocolKeyFile string `yaml:"protocol_key_file"` // 协议关键操作文件
		AreaFilename    string `yaml:"area_file"`         // 地区文件
		LogLevel        string `yaml:"log_level"`         // 日志级别
	} `yaml:"system"`
	Session struct {
		RootPath string `yaml:"root_path"`
		PcapPath string `yaml:"pcap_path"`
		Expired  int    `yaml:"expired"`
		Push     struct {
			IP               string `yaml:"ip"`
			LineInfo         string `yaml:"line_info"`
			SensorIp         string `yaml:"sensor_ip"`
			VendorId         string `yaml:"vendor_id"`
			LRAggregateValue string `yaml:"LR_aggregate_value"`
			ConnTimeout      string `yaml:"conn_timeout"`
			AggregateModel   string `yaml:"aggregate_model"`
		} `yaml:"push"`
	} `yaml:"session"`
}

var configPath = "./config.yaml"

func MustLoad() Config {
	var config Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Init MestLoad Config Error: %s\n", err.Error())
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("Analyze MestLoad Config Error: %s\n", err.Error())
	}
	return config
}
