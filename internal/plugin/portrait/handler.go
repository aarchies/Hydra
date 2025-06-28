package portrait

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
	"time"

	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	relolvers       = map[string]func(meta []model.ProtocolData) map[string]string{}
	point_relolvers = map[string]func(meta []model.ProtocolData) map[string]string{}
)

type Handler struct {
	svc    *internal.ServiceContext
	ctx    context.Context
	config *config
}

func NewHandler(ctx context.Context, svc *internal.ServiceContext, conf *config) *Handler {
	relolver(conf)
	return &Handler{svc, ctx, conf}
}

// Handle implements plugin.Handler.
func (h *Handler) Handle(result *model.ConsumerData) {

	if cachedInsight, exist := h.svc.Cache.Local.Get(fmt.Sprintf("%s_%d", result.DstIP, result.DstPort) + "_assetInsight"); exist {

		// 源IP+PORT -> 目的IP+PORT
		if result.SrcIP != "" && result.SrcPort != 0 && result.LongitudeSrc != 0 && result.LatitudeSrc != 0 && result.SrcCity != "" && result.SrcCountry != "" && result.SrcProvince != "" {

			model := cachedInsight.(model.AssetInsight)
			h.links(result, model)
			h.keyAction(result, model)
			h.point(result, model)

		}
	}
}

// 资产链路
func (h *Handler) links(data *model.ConsumerData, model model.AssetInsight) {
	entity := AssetLink{
		AssetId:    model.ID,
		Localtion:  fmt.Sprintf("%f,%f->%f,%f", data.LongitudeSrc, data.LatitudeSrc, model.Longitude, model.Latitude),
		IPS:        fmt.Sprintf("%s:%d -> %s:%d", data.SrcIP, data.SrcPort, data.DstIP, data.DstPort),
		Links:      fmt.Sprintf("%s %s %s -> %s %s %s", data.SrcCountry, data.SrcProvince, data.SrcCity, model.Country, model.Province, model.City),
		CreateTime: time.Now(),
	}

	jsonData, err := json.Marshal(data.Meta)
	if err != nil {
		logrus.Errorln("asset-> link json marshal failed: ", err)
	}
	entity.Detail = string(jsonData)

	if err := h.svc.ClickHouseDB.Model(&AssetLink{}).Create(&entity).Error; err != nil {
		logrus.Errorln("asset-> link db store failed: ", err)
	}
}

// 关键动作
func (h *Handler) keyAction(data *model.ConsumerData, model model.AssetInsight) {
	resolverFunc, exists := relolvers[data.Protocol]
	if !exists {
		return
	}

	portrait := AssetPortrait{
		AssetID:  model.ID,
		Protocol: data.Protocol,
		Script:   []Script{},
		Fields:   make(map[string]string),
	}

	for k, v := range resolverFunc(data.Meta) {
		if strings.Contains(k, "username") {
			portrait.UserName = v
		} else if strings.Contains(k, "passwd") {
			portrait.Passwd = v
		} else {
			portrait.Fields[k] = v
		}
	}

	portrait.VulnIds = h.vnln(model)

	if len(portrait.Fields) > 0 {
		jsonData, err := json.Marshal(portrait.Fields)
		if err != nil {
			logrus.Errorln("asset-> portrait json marshal failed: ", err)
		}

		if err := h.svc.ClickHouseDB.Model(AssetPortrait{}).Where(AssetPortrait{FieldsStr: string(jsonData)}).FirstOrCreate(&portrait).Error; err != nil {
			logrus.Errorf("portrait data %v", err)
		}
	}
}

// plc点位值
func (h *Handler) point(data *model.ConsumerData, model model.AssetInsight) {
	resolverFunc, exists := point_relolvers[data.Protocol]
	if !exists {
		return
	}

	list := []AssetPointInfo{}

	for k, v := range resolverFunc(data.Meta) {
		list = append(list, AssetPointInfo{
			AssetID: model.ID,
			Lable:   k,
			Value:   v,
		})
	}

	if len(list) > 0 {
		if err := h.svc.ClickHouseDB.CreateInBatches(&list, len(list)).Error; err != nil {
			logrus.Errorf("portrait point data %v", err)
		}
	}
}

// 获取漏洞ID
func (h *Handler) vnln(models model.AssetInsight) []int64 {

	var vulnIds []int64
	query := h.svc.DB.Model(&model.Vulnerability{}).Select("id")

	if models.Vendor != "" {
		query.Where("vendor = ?", models.Vendor)
	}

	if models.DeviceType != "" {
		query.Where("type = ?", models.DeviceType)
	}

	if models.Model != "" {
		query.Where("num = ?", models.Model)
	}

	if models.CPUType != "" {
		query.Where("cpu_type = ?", models.CPUType)
	}

	if models.FirmwareVersion != "" {
		query.Where("firmware_version = ?", models.FirmwareVersion)
	}

	if err := query.Find(&vulnIds).Error; err != nil {
		logrus.Errorf("portrait vulnIds data %v", err)
	}

	return vulnIds
}

func relolver(config *config) {

	for protocol, item := range config.Dictionary {

		if !item.Enable {
			continue
		}

		relolvers[protocol] = func(meta []model.ProtocolData) map[string]string {
			result := map[string]string{}
			for i := range meta {
				for _, v := range meta[i].F {
					if slices.Contains(item.Fields, v.N) {
						result[v.N] = v.V
					}
				}
			}
			return result
		}

		point_relolvers[protocol] = func(meta []model.ProtocolData) map[string]string {
			result := map[string]string{}
			for i := range meta {
				for _, v := range meta[i].F {
					if slices.Contains(item.FuncCode.Read, v.N) || slices.Contains(item.FuncCode.Write, v.N) {
						result[v.N] = v.V
					}
				}
			}
			return result
		}
	}
}
