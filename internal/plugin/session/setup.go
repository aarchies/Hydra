package session

import (
	"dissect/internal"
	"dissect/internal/core"
	"dissect/internal/model"
	"dissect/internal/plugin"
	"dissect/pkg"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func init() {
	core.RegisterPlugin("session", func(c *core.Controller) plugin.Handler {

		conf := InitConfig(c.ServiceContext())
		if conf.DataPushConfig != nil {
			brokerServer := strings.Split(conf.DataPushConfig.URL, ",")
			kafkaProducer = pkg.InitKafkaProducer(brokerServer, conf.DataPushConfig.Topic, true)
		}

		return NewHandler(c.Context(), c.ServiceContext(), conf)
	})
}

func InitConfig(svc *internal.ServiceContext) *Config {
	conf := &Config{}
	wg := &sync.WaitGroup{}
	wg.Add(5)

	go loadFilterRule(svc, conf, wg)
	go loadSwitchSetting(svc, conf, wg)
	go loadlVulnerability(svc, conf, wg)
	go settingDataPushConfig(svc, conf, wg)
	go settingReportMetaConfig(svc, conf, wg)

	wg.Wait()
	return conf
}

// 过滤规则
func loadFilterRule(svc *internal.ServiceContext, conf *Config, wg *sync.WaitGroup) {
	defer wg.Done()
	var rules []*model.FilterRule
	filterIp := make(map[string]uint8)
	filterIpAndPort := make(map[string]uint8)
	err := svc.DB.Select("ip", "port").Find(&rules).Error
	if err != nil {
		logrus.Errorln("init push filterRule error:", err)
	}
	for _, rule := range rules {
		if rule.Port == 0 && rule.IP != "" {
			filterIp[rule.IP] = 0
		} else if rule.Port != 0 && rule.IP != "" {
			filterIpAndPort[fmt.Sprintf("%s:%d", rule.IP, rule.Port)] = 0
		}
	}
	conf.FilterIp = filterIp
	conf.FilterIpAndPort = filterIpAndPort
	logrus.Debugln("load push filterRule is completed")
}

// 开关配置
func loadSwitchSetting(svc *internal.ServiceContext, conf *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	if err := svc.DB.Model(&SwitchConfig{}).Select("value1").Where("param = ?", "data_push_switch").First(&conf.Switch).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			conf.Switch = "1"
			if err = svc.DB.Model(&SwitchConfig{}).Create(&SwitchConfig{
				Param:  "data_push_switch",
				Value1: "1",
			}).Error; err != nil {
				logrus.Errorln("create push switch setting error", err)
			}
		} else {
			logrus.Errorln("select push switch setting error", err)
		}
	}
	logrus.Debugln("load push switch setting is completed ", conf.Switch)
}

// 漏洞库
func loadlVulnerability(svc *internal.ServiceContext, conf *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	var vul []Vulnerability
	if err := svc.DB.Model(&Vulnerability{}).Select("CveCode", "CveName", "Url", "Detail", "Solution").Scan(&vul).Error; err != nil {
		logrus.Errorln("load Vulnerability lib error", err)
	}
	if len(vul) == 0 {
		logrus.Errorln("the vulnerability lib has no data!")
	}

	vulMap := make(map[string]*Vulnerability, len(vul))
	for idx := range vul {
		vulnerability := vul[idx]
		vulMap[vulnerability.CveCode] = &vulnerability
	}
	conf.VulnerabilityMap = vulMap
	logrus.Debugln("load vulnerability lib setting is completed, count:", len(vul))
}

// 聚合告警推送配置
func settingDataPushConfig(svc *internal.ServiceContext, conf *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	if err := svc.DB.Model(&DataPushConfig{}).Where("data_type = ? and status = ?", "聚合告警日志", "1").Where("is_deleted=0").First(&conf.DataPushConfig).Error; err != nil {
		logrus.Errorln("load session dataPush config error", err)
		return
	}

	logrus.Debugln("load session dataPush config is completed")
}

// 元数据上报配置
func settingReportMetaConfig(svc *internal.ServiceContext, conf *Config, wg *sync.WaitGroup) {
	defer wg.Done()

	metaConfigMap := make(map[string]map[string]*ReportMetaConfig)
	var reportMetaConfigs []ReportMetaConfig

	if err := svc.DB.Model(ReportMetaConfig{}).
		Where("search_key is not null and search_key != ''").
		Where("filed is not null and filed != ''").
		Find(&reportMetaConfigs).Error; err != nil {
		logrus.Errorln("load ReportMetaConfig error", err)
		return
	}

	for _, item := range reportMetaConfigs {
		m, ok := metaConfigMap[item.Protocol]
		if !ok {
			m = make(map[string]*ReportMetaConfig)
		}
		m[item.SearchKey] = &item
		metaConfigMap[item.Protocol] = m
	}

	conf.ReportMetaConfigMap = metaConfigMap
}
