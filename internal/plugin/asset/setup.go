package asset

import (
	"dissect/internal"
	"dissect/internal/core"
	"dissect/internal/plugin"
	"dissect/internal/plugin/asset/config"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

func init() {
	core.RegisterPlugin("asset", func(c *core.Controller) plugin.Handler {
		return NewHandler(c.Context(), loadLib(c.ServiceContext()))
	})
}

func loadLib(svc *internal.ServiceContext) *internal.ServiceContext {
	var wg sync.WaitGroup
	wg.Add(3)

	// 指纹资产库
	go func() {
		defer wg.Done()
		fingers := make([]config.FingerPrintAsset, 0)
		if err := svc.DB.Model(&config.FingerPrintAsset{}).Find(&fingers).Error; err != nil {
			logrus.Fatalln("search fingerPrintAsset fail", err)
		}

		var num int
		cacheUpdates := make(map[string]config.AssetProtocolFinger)
		for _, i := range fingers {
			for _, port := range strings.Split(i.Ports, ";") {
				num++
				key := i.Protocol + "_" + port + "_fingerPrintAsset"
				assetProtocolFinger, exist := svc.Cache.Local.Get(key)
				if !exist {
					svc.Cache.Local.Set(key, config.AssetProtocolFinger{
						DeviceName: i.DeviceName,
						Type:       i.Type,
						DeviceType: i.DeviceType,
						Desc:       i.Desc,
						Protocol:   i.Protocol,
						Port:       port,
						Rules:      i.HandleRules(make(map[string]config.Rule)),
					}, 0)
				} else {
					entity, _ := assetProtocolFinger.(config.AssetProtocolFinger)
					entity.Rules = i.HandleRules(entity.Rules)
					cacheUpdates[key] = entity
				}
			}
		}

		for key, entity := range cacheUpdates {
			svc.Cache.Local.Set(key, entity, 0)
		}
		logrus.Debugln("fingerPrintAsset load is completed! count:", num)
	}()

	// 资产分析库
	go func() {
		defer wg.Done()
		// assetInsights := make([]model.AssetInsight, 0)
		// if err := svc.DB.Model(&model.AssetInsight{}).Find(&assetInsights).Error; err != nil {
		// 	logrus.Fatalln("search assetInsight fail", err)
		// }
		// for _, asset := range assetInsights {
		// 	svc.Cache.Local.Set(fmt.Sprintf("%s_%d_assetInsight", asset.IP, asset.OpenPort), asset, 0)
		// }
		// logrus.Debugln("assetInsight load is completed! count:", len(assetInsights))
	}()

	// 内置资产库
	go func() {
		defer wg.Done()
		// builtIns := make([]model.BuiltInAsset, 0)
		// if err := svc.ClickHouseDB.Model(&model.BuiltInAsset{}).Find(&builtIns).Error; err != nil {
		// 	logrus.Fatalln("search builtin asset fail", err)
		// }
		// for _, asset := range builtIns {
		// 	svc.Cache.Local.Set(fmt.Sprintf("%s_%d_builtInAsset", asset.IP, asset.OpenPort), asset, 0)
		// }
		// logrus.Debugln("builtInAsset load is completed! count:", len(builtIns))
	}()

	wg.Wait()
	return svc
}
