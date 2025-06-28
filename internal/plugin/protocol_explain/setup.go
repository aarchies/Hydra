package protocol_explain

import (
	"dissect/internal"
	"dissect/internal/core"
	"dissect/internal/model"
	"dissect/internal/plugin"
	"encoding/json"
	"os"
	"path"

	"github.com/sirupsen/logrus"
)

// Explain 协议解释器
type Handler struct {
	svc *internal.ServiceContext
}

var (
	keyRuleMap     = make(map[string]map[string]map[string]*model.KeyActionRule) // 协议key规则
	protocolKeyMap = make(map[string]map[string]string)                          // 协议key
)

func init() {
	core.RegisterPlugin("explain", func(c *core.Controller) plugin.Handler {
		h := &Handler{
			svc: c.ServiceContext(),
		}
		c.OnStartup(func() error {
			loadLib(h.svc)
			return nil
		})

		return h
	})
}

func loadLib(svc *internal.ServiceContext) {
	var keyRules []*model.KeyActionRule
	if err := svc.DB.Model(&model.KeyActionRule{}).Find(&keyRules).Error; err != nil {
		logrus.Fatalln("init key action rule error!", err)
	}

	for _, i := range keyRules {
		if keyRuleMap[i.ProtocolName] == nil {
			keyRuleMap[i.ProtocolName] = make(map[string]map[string]*model.KeyActionRule)
		}
		if keyRuleMap[i.ProtocolName][i.ExtractionRule] == nil {
			keyRuleMap[i.ProtocolName][i.ExtractionRule] = make(map[string]*model.KeyActionRule)
		}
		keyRuleMap[i.ProtocolName][i.ExtractionRule][i.FunctionCode] = i
	}
	logrus.Debugf("init protocol rule count:%d\n", len(keyRules))

	file, err := os.Open(path.Join(svc.Config.System.Path, svc.Config.System.ProtocolKeyFile))
	if err != nil {
		logrus.Fatalln("Error opening JSON file:", err)
	}
	defer file.Close()

	if err := json.NewDecoder(file).Decode(&protocolKeyMap); err != nil {
		logrus.Fatalln("ProtocolKeyMap Error decoding JSON:", err)
	}

	logrus.Debugf("init protocol key rule count:%d\n", len(protocolKeyMap))
}

func (h *Handler) Handle(result *model.ConsumerData) {
	matchKeyName(result)
	matchKey(result)
	result.GeoIP(h.svc.Cache.GeoIP, h.svc.Cache.ProtocolMap) // geoip
}

func matchKeyName(data *model.ConsumerData) {
	for i := 0; i < len(data.Meta); i++ {
		for j := 0; j < len(data.Meta[i].F); j++ {
			if value, ok := protocolKeyMap[data.Meta[i].F[j].N]; ok {
				data.Meta[i].F[j].SN = value["zn"]
			}
		}
	}
}

// ProcessMatchKey 关键操作匹配逻辑 去关键操作规则库拿规则、循环ProtocolField 匹配规则库，是，则改action，是否关键操作
func matchKey(data *model.ConsumerData) {
	if _, ok := keyRuleMap[data.Protocol]; ok {
		for i := 0; i < len(data.Meta); i++ {
			for j := 0; j < len(data.Meta[i].F); j++ {
				if _, ok = keyRuleMap[data.Protocol][data.Meta[i].F[j].N]; ok {
					if action, ok := keyRuleMap[data.Protocol][data.Meta[i].F[j].N][data.Meta[i].F[j].V]; ok {
						data.IsKey = true
						data.Action = action.Desc
					}
				}
			}
		}
	}
}
