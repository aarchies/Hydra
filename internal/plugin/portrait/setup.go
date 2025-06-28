package portrait

import (
	"dissect/internal/core"
	"dissect/internal/plugin"
	"encoding/json"
	"os"
	"path"

	"github.com/sirupsen/logrus"
)

func init() {
	core.RegisterPlugin("portrait", func(c *core.Controller) plugin.Handler {
		svc := c.ServiceContext()
		conf := &config{}
		file, err := os.Open(path.Join(svc.Config.System.Path, svc.Config.System.PortraitMapFile))
		if err != nil {
			logrus.Fatalln("Error opening JSON file:", err)
		}
		defer file.Close()

		if err := json.NewDecoder(file).Decode(&conf.Dictionary); err != nil {
			logrus.Fatalln("PortraitMapFile Error decoding JSON:", err)
		}

		logrus.Debugf("init portrait key counts %d \n", len(conf.Dictionary))

		return NewHandler(c.Context(), svc, conf)
	})
}
