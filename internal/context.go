package internal

import (
	"dissect/config"
	"dissect/internal/model"
	"dissect/pkg"
	"encoding/json"
	"os"
	"path"

	"dissect/pkg/cache"
	"dissect/pkg/clickhouse"
	"dissect/pkg/database/mysql"
	"dissect/utils"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/songzhibin97/gkit/cache/local_cache"
	"gorm.io/gorm"
)

type (
	Cache struct {
		Local           local_cache.Cache                    // 本地缓存
		SuricataRuleMap map[int]*model.SuricataRule          // 入侵检测缓存
		ProtocolMap     map[string]*model.ProtocolConfigInfo // 协议信息映射
		GeoIP           *utils.GeoIP                         // geoip库
	}
	ServiceContext struct {
		Config       config.Config // global config
		Cache        *Cache        // localcache
		DB           *gorm.DB      // tidb
		ClickHouseDB *gorm.DB      // clickhouse
	}
)

func NewServiceContext(c config.Config) *ServiceContext {

	pkg.LogMode(c.System.LogLevel, false)

	db := mysql.NewOption(c.DB.Mysql.Hosts, c.DB.Mysql.Port, c.DB.Mysql.UserName, c.DB.Mysql.PassWord, c.DB.Mysql.DataBase).
		WithLogMode(c.DB.Mysql.LogMode).
		WithMaxIdleConn(c.DB.Mysql.MaxIdleConn).
		WithMaxOpenConn(c.DB.Mysql.MaxOpenConn).
		WithConfig(c.DB.Mysql.Config).
		Connect()

	ck := clickhouse.NewOption(c.DB.Clickhouse.Hosts, c.DB.Clickhouse.UserName, c.DB.Clickhouse.PassWord, c.DB.Clickhouse.DataBase).
		WithIsDebug(c.DB.Clickhouse.IsDebug).
		Connect()

	return &ServiceContext{
		Config:       c,
		Cache:        initCache(db, c),
		DB:           db,
		ClickHouseDB: ck.DB(),
	}
}

func initCache(db *gorm.DB, config config.Config) *Cache {

	c := &Cache{
		Local:           cache.NewCache(0),
		SuricataRuleMap: make(map[int]*model.SuricataRule),
		ProtocolMap:     make(map[string]*model.ProtocolConfigInfo),
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		var suricataRules []*model.SuricataRule
		if err := db.Model(&model.SuricataRule{}).Find(&suricataRules).Error; err != nil {
			logrus.Fatalln("error init suricata rules!", err)
		}
		for _, i := range suricataRules {
			c.SuricataRuleMap[i.ID] = i
		}
		logrus.Debugf("init suricata rules counts %d \n", len(suricataRules))
	}()

	go func() {
		defer wg.Done()
		file, err := os.Open(path.Join(config.System.Path, config.System.ProtocolMapFile))
		if err != nil {
			logrus.Fatalln("Error opening JSON file:", err)
		}
		defer file.Close()

		if err := json.NewDecoder(file).Decode(&c.ProtocolMap); err != nil {
			logrus.Fatalln("ProtocolKeyMap Error decoding JSON:", err)
		}

		logrus.Debugf("init protocol key counts %d \n", len(c.ProtocolMap))
	}()

	go func() {
		defer wg.Done()
		LocationDb, err := utils.NewGeoIP(path.Join(config.System.Path, config.System.LocationFile))
		if err != nil {
			logrus.Fatalln("locationDb error %w", err)
		}

		file, err := os.Open(path.Join(config.System.Path, config.System.AreaFilename))
		if err != nil {
			logrus.Fatalln("Error opening JSON file:", err)
		}
		defer file.Close()

		if err := json.NewDecoder(file).Decode(&LocationDb.AreaMap); err != nil {
			logrus.Fatalln("ProtocolKeyMap Error decoding JSON:", err)
		}
		c.GeoIP = LocationDb
		logrus.Debugf("init area group counts %d \n", len(c.GeoIP.AreaMap))
	}()

	wg.Wait()
	return c
}
