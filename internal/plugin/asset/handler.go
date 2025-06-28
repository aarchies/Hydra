package asset

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
	"dissect/internal/plugin/asset/config"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"reflect"
	"time"

	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

type Handler struct {
	svc *internal.ServiceContext
	ctx context.Context
}

var (
	uniqueSaveAssetInsight sync.Map
	directionMap           sync.Map
	batchRecords           []model.AssetInsight
	pool                   = sync.Pool{
		New: func() interface{} {
			return new(model.AssetInsight)
		},
	}
)

func NewHandler(ctx context.Context, svc *internal.ServiceContext) *Handler {

	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				batchSave(svc)
			}
		}
	}()

	return &Handler{svc, ctx}
}

func (h *Handler) Handle(data *model.ConsumerData) {

	sKey := fmt.Sprintf("%s_%d", data.SrcIP, data.SrcPort)
	dKey := fmt.Sprintf("%s_%d", data.DstIP, data.DstPort)

	directionMap.Store(sKey, dKey)

	wg := sync.WaitGroup{}
	wg.Add(10)
	go h.assetInsightSrc(data, sKey, dKey, &wg)
	go h.assetInsightDst(data, dKey, sKey, &wg)
	go h.enipProtocolHandle(data, sKey, &wg)
	go h.cipProtocolHandle(data, sKey, &wg)
	go h.modbusProtocolHandle(data, sKey, &wg)
	go h.s7commProtocolHandle(data, sKey, &wg)
	go h.tcpProtocolHandle(data, sKey, &wg)
	go h.assetProtocolFinger(data, sKey, &wg)
	go h.builtInAssetSrc(data, sKey, &wg)
	go h.builtInAssetDst(data, dKey, &wg)
	wg.Wait()

}

// 资产分析src
func (h *Handler) assetInsightSrc(data *model.ConsumerData, srcKey, dstKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		// 获取或创建 AssetInsight 对象
		assetInsight := pool.Get().(*model.AssetInsight)
		defer pool.Put(assetInsight)
		// 判断源IP+PORT是否在资产分析缓存中，如果在，补充data数据
		if cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight"); exist {
			*assetInsight = cachedInsight.(model.AssetInsight)
			data.Vendor = assetInsight.Vendor
			data.DeviceType = assetInsight.DeviceType
			data.Model = assetInsight.Model
			// 判断单双向识别
			if srcKey == getDirectionMap(dstKey) && !assetInsight.Direction {
				assetInsight.Direction = true
			}
			// 如果与资产分析缓存中的数据不一致，加入到保存队列
			if !h.compareWithOldAssetInsight(*assetInsight) {
				h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
				setUniqueSaveAssetInsight(srcKey, *assetInsight)
			}
		}
	}
}

// 资产分析dst
func (h *Handler) assetInsightDst(data *model.ConsumerData, srcKey, dstKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		// 获取或创建 AssetInsight 对象
		assetInsight := pool.Get().(*model.AssetInsight)
		defer pool.Put(assetInsight)
		// 判断目的IP+PORT是否在资产分析缓存中，如果在，补充data数据
		if cachedInsight, exist := h.svc.Cache.Local.Get(dstKey + "_assetInsight"); exist {
			*assetInsight = cachedInsight.(model.AssetInsight)
			data.Vendor = assetInsight.Vendor
			data.DeviceType = assetInsight.DeviceType
			data.Model = assetInsight.Model
			// 判断单双向识别
			if dstKey == getDirectionMap(srcKey) && !assetInsight.Direction {
				assetInsight.Direction = true
			}
			// 判断目的IP是否被攻击，如果被攻击表示为true，攻击数量自增1
			if data.IsAttack {
				assetInsight.AttackedCount++
				assetInsight.UpdateTime = time.Now()
			}
			// 如果与资产分析缓存中的数据不一致，加入到保存队列
			if !h.compareWithOldAssetInsight(*assetInsight) {
				h.svc.Cache.Local.Set(dstKey+"_assetInsight", *assetInsight, 0)
				setUniqueSaveAssetInsight(dstKey, *assetInsight)
			}
		}
	}
}

// 内置资产Src
func (h *Handler) builtInAssetSrc(data *model.ConsumerData, key string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		_, exist := h.svc.Cache.Local.Get(key + "_assetInsight")
		if !exist {
			// 内置资产
			builtInAssetCache, exist := h.svc.Cache.Local.Get(key + "_builtInAsset")
			if exist {
				builtInAsset, _ := builtInAssetCache.(model.BuiltInAsset)
				// 补充data数据
				data.Vendor = builtInAsset.Vendor
				data.DeviceType = builtInAsset.DeviceType
				data.Model = builtInAsset.Model
				// 获取或创建 model.AssetInsight 对象
				assetInsight := pool.Get().(*model.AssetInsight)
				defer pool.Put(assetInsight)
				*assetInsight = model.AssetInsight{
					ID:              key,
					IP:              builtInAsset.IP,
					OpenPort:        builtInAsset.OpenPort,
					Protocol:        data.Protocol,
					Type:            model.AssetType(builtInAsset.Type),
					Vendor:          builtInAsset.Vendor,
					DeviceType:      builtInAsset.DeviceType,
					Model:           builtInAsset.Model,
					CPUModel:        builtInAsset.CPUModel,
					FirmwareVersion: builtInAsset.FirmwareVersion,
					IsOnline:        true,
					Information:     builtInAsset.Information,
					Operator:        builtInAsset.Operator,
					Longitude:       data.LongitudeSrc,
					Latitude:        data.LatitudeSrc,
					Country:         data.SrcCountry,
					Province:        data.SrcProvince,
					City:            data.SrcCity,
					IsBuiltin:       true,
					CreateTime:      time.Now(),
					UpdateTime:      time.Now(),
					AttackedCount:   0,
					Direction:       false,
				}
				// 如果与资产分析缓存中的数据不一致，加入到保存队列
				if !h.compareWithOldAssetInsight(*assetInsight) {
					h.svc.Cache.Local.Set(key+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(key, *assetInsight)
				}
			}
		}
	}
}

// 内置资产Dst
func (h *Handler) builtInAssetDst(data *model.ConsumerData, key string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		assertInCache, exist := h.svc.Cache.Local.Get(key + "_assetInsight")
		if !exist {
			// 内置资产
			builtInAssetCache, exist := h.svc.Cache.Local.Get(key + "_builtInAsset")
			if exist {
				builtInAsset, _ := builtInAssetCache.(model.BuiltInAsset)
				// 补充data数据
				data.Vendor = builtInAsset.Vendor
				data.DeviceType = builtInAsset.DeviceType
				data.Model = builtInAsset.Model
				// 获取或创建 model.AssetInsight 对象
				assetInsight := pool.Get().(*model.AssetInsight)
				defer pool.Put(assetInsight)
				*assetInsight = model.AssetInsight{
					ID:              key,
					IP:              builtInAsset.IP,
					OpenPort:        builtInAsset.OpenPort,
					Protocol:        data.Protocol,
					Type:            model.AssetType(builtInAsset.Type),
					Vendor:          builtInAsset.Vendor,
					DeviceType:      builtInAsset.DeviceType,
					Model:           builtInAsset.Model,
					CPUModel:        builtInAsset.CPUModel,
					FirmwareVersion: builtInAsset.FirmwareVersion,
					IsOnline:        true,
					Information:     builtInAsset.Information,
					Operator:        builtInAsset.Operator,
					Longitude:       data.LongitudeDst,
					Latitude:        data.LatitudeDst,
					Country:         data.DstCountry,
					Province:        data.DstProvince,
					City:            data.DstCity,
					IsBuiltin:       true,
					CreateTime:      time.Now(),
					UpdateTime:      time.Now(),
					AttackedCount:   0,
					Direction:       false,
				}
				// 如果与资产分析缓存中的数据不一致，加入到保存队列
				if !h.compareWithOldAssetInsight(*assetInsight) {
					h.svc.Cache.Local.Set(key+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(key, *assetInsight)
				}
			}
		} else {
			data.Vendor = assertInCache.(model.AssetInsight).Vendor
			data.DeviceType = assertInCache.(model.AssetInsight).DeviceType
			data.Model = assertInCache.(model.AssetInsight).Model
		}
	}
}

// 资产指纹识别
func (h *Handler) assetProtocolFinger(data *model.ConsumerData, srcKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		if len(data.Meta) == 0 {
			return
		}

		assetProtocolFinger, exist := h.svc.Cache.Local.Get(fmt.Sprintf("%s_%d_fingerPrintAsset", data.Protocol, data.SrcPort))
		if exist {
			assetProtocolFinger, _ := assetProtocolFinger.(config.AssetProtocolFinger)
			assetInsight := pool.Get().(*model.AssetInsight)
			defer pool.Put(assetInsight)

			cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight")
			if !exist {
				*assetInsight = model.AssetInsight{
					ID:            srcKey,
					IP:            data.SrcIP,
					OpenPort:      data.SrcPort,
					Protocol:      data.Protocol,
					Type:          model.AssetType(assetProtocolFinger.Type),
					DeviceType:    assetProtocolFinger.DeviceType,
					IsOnline:      true,
					Information:   handleInformation(data.Meta),
					Longitude:     data.LongitudeSrc,
					Latitude:      data.LatitudeSrc,
					Country:       data.SrcCountry,
					Province:      data.SrcProvince,
					City:          data.SrcCity,
					IsBuiltin:     false,
					CreateTime:    time.Now(),
					UpdateTime:    time.Now(),
					AttackedCount: 0,
					Direction:     false,
					DataByte:      base64.StdEncoding.EncodeToString(data.DataByte),
				}
				if len(data.Meta) > 0 {
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if rule, exists := assetProtocolFinger.Rules[data.Meta[len(data.Meta)-1].F[i].N]; exists {
							assetInsight.Vendor = rule.Vendor
							value := data.Meta[len(data.Meta)-1].F[i].V
							if value != "" {
								if rule.Name == "device_model" {
									assetInsight.Model = value
									continue
								} else if rule.Name == "cpu_model" {
									assetInsight.CPUModel = value
									assetInsight.Model = value
									continue
								} else if rule.Name == "cpu_type" {
									assetInsight.CPUType = value
									continue
								} else if rule.Name == "firmware_version" {
									assetInsight.FirmwareVersion = value
									continue
								}
							}
						}
					}
					// 特殊处理欧姆龙相关数据
					if data.Protocol == "OMRON" {
						if strings.Contains(assetInsight.CPUModel, "_") {
							assetInsight.Model = strings.Split(assetInsight.CPUModel, "_")[0]
						} else if strings.Contains(assetInsight.CPUModel, "-") {
							assetInsight.Model = strings.Split(assetInsight.CPUModel, "-")[0]
						}
					}
					if assetInsight.Model != "" || assetInsight.CPUModel != "" || assetInsight.CPUType != "" {
						data.Vendor = assetInsight.Vendor
						data.DeviceType = assetInsight.DeviceType
						data.Model = assetInsight.Model
						h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
						setUniqueSaveAssetInsight(srcKey, *assetInsight)
					}
				}
			} else {
				*assetInsight, _ = cachedInsight.(model.AssetInsight)
				if assetInsight.IsBuiltin && len(data.Meta) > 0 {
					saveFlag := false
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if rule, exists := assetProtocolFinger.Rules[data.Meta[len(data.Meta)-1].F[i].N]; exists {
							if assetInsight.Vendor == "" {
								assetInsight.Vendor = rule.Vendor
							}
							value := data.Meta[len(data.Meta)-1].F[i].V
							if value != "" {
								if rule.Name == "device_model" {
									assetInsight.Model = value
									continue
								} else if rule.Name == "cpu_model" {
									assetInsight.CPUModel = value
									assetInsight.Model = value
									saveFlag = true
									continue
								} else if rule.Name == "cpu_type" {
									assetInsight.CPUType = value
									continue
								} else if rule.Name == "firmware_version" {
									assetInsight.FirmwareVersion = value
									continue
								}
							}
						}
					}
					if saveFlag {
						if data.Protocol == "OMRON" {
							if strings.Contains(assetInsight.CPUModel, "_") {
								assetInsight.Model = strings.Split(assetInsight.CPUModel, "_")[0]
							} else if strings.Contains(assetInsight.CPUModel, "-") {
								assetInsight.Model = strings.Split(assetInsight.CPUModel, "-")[0]
							}
						}
						if !h.compareWithOldAssetInsight(*assetInsight) {
							data.Vendor = assetInsight.Vendor
							data.DeviceType = assetInsight.DeviceType
							data.Model = assetInsight.Model
							assetInsight.Protocol = data.Protocol
							assetInsight.IsBuiltin = false
							assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
							assetInsight.UpdateTime = time.Now()
							h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
							setUniqueSaveAssetInsight(srcKey, *assetInsight)
						}
					}
				}
			}
		}
	}
}

// CIP协议解析
func (h *Handler) cipProtocolHandle(data *model.ConsumerData, srcKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		if data.Protocol != "CIP" || len(data.Meta) == 0 {
			return
		}
		assetInsight := pool.Get().(*model.AssetInsight)
		defer pool.Put(assetInsight)
		cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight")
		if !exist {
			// 识别CIP协议设备
			*assetInsight = model.AssetInsight{
				ID:            srcKey,
				IP:            data.SrcIP,
				OpenPort:      data.SrcPort,
				Protocol:      data.Protocol,
				Type:          model.AssetType(2),
				DeviceType:    "PLC",
				IsOnline:      true,
				Information:   handleInformation(data.Meta),
				Longitude:     data.LongitudeSrc,
				Latitude:      data.LatitudeSrc,
				Country:       data.SrcCountry,
				Province:      data.SrcProvince,
				City:          data.SrcCity,
				IsBuiltin:     false,
				CreateTime:    time.Now(),
				UpdateTime:    time.Now(),
				AttackedCount: 0,
				Direction:     false,
				DataByte:      base64.StdEncoding.EncodeToString(data.DataByte),
			}
			for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
				if data.Meta[len(data.Meta)-1].F[i].N == "cip.id.vendor_id" {
					vendor := strings.ReplaceAll(data.Meta[len(data.Meta)-1].F[i].Sh, "Vendor ID: ", "")
					assetInsight.Vendor = strings.Split(vendor, " ")[0]
				} else if data.Meta[len(data.Meta)-1].F[i].N == "cip.id.product_name" {
					assetInsight.Model = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, "/")[0]
					assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
				} else if data.Meta[len(data.Meta)-1].F[i].N == "cip.id.major_rev" {
					//cip.id.major_rev和cip.id.minor_rev，如16.4
					assetInsight.FirmwareVersion = data.Meta[len(data.Meta)-1].F[i].V + "." + data.Meta[len(data.Meta)-1].F[i+1].V
				}
			}
			if assetInsight.Model != "" || assetInsight.CPUModel != "" || assetInsight.CPUType != "" {
				data.Vendor = assetInsight.Vendor
				data.DeviceType = assetInsight.DeviceType
				data.Model = assetInsight.Model
				h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
				setUniqueSaveAssetInsight(srcKey, *assetInsight)
			}
		} else {
			*assetInsight, _ = cachedInsight.(model.AssetInsight)
			if assetInsight.IsBuiltin && len(data.Meta) > 0 {
				for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
					if data.Meta[len(data.Meta)-1].F[i].N == "cip.id.vendor_id" {
						vendor := strings.ReplaceAll(data.Meta[len(data.Meta)-1].F[i].Sh, "Vendor ID: ", "")
						assetInsight.Vendor = strings.Split(vendor, " ")[0]
					} else if data.Meta[len(data.Meta)-1].F[i].N == "cip.id.product_name" {
						assetInsight.Model = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, "/")[0]
						assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
					} else if data.Meta[len(data.Meta)-1].F[i].N == "cip.id.major_rev" {
						//cip.id.major_rev和cip.id.minor_rev，如16.4
						assetInsight.FirmwareVersion = data.Meta[len(data.Meta)-1].F[i].V + "." + data.Meta[len(data.Meta)-1].F[i+1].V
					}
				}
				if !h.compareWithOldAssetInsight(*assetInsight) {
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					assetInsight.Protocol = data.Protocol
					assetInsight.IsBuiltin = false
					assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
					assetInsight.UpdateTime = time.Now()
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		}
	}
}

// ENIP协议解析
func (h *Handler) enipProtocolHandle(data *model.ConsumerData, srcKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		if data.Protocol != "ENIP" || len(data.Meta) == 0 {
			return
		}
		assetInsight := pool.Get().(*model.AssetInsight)
		defer pool.Put(assetInsight)
		cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight")
		if !exist {
			// 识别ENIP协议设备
			*assetInsight = model.AssetInsight{
				ID:            srcKey,
				IP:            data.SrcIP,
				OpenPort:      data.SrcPort,
				Protocol:      data.Protocol,
				Type:          model.AssetType(2),
				DeviceType:    "PLC",
				IsOnline:      true,
				Information:   handleInformation(data.Meta),
				Longitude:     data.LongitudeSrc,
				Latitude:      data.LatitudeSrc,
				Country:       data.SrcCountry,
				Province:      data.SrcProvince,
				City:          data.SrcCity,
				IsBuiltin:     false,
				CreateTime:    time.Now(),
				UpdateTime:    time.Now(),
				AttackedCount: 0,
				Direction:     false,
				DataByte:      base64.StdEncoding.EncodeToString(data.DataByte),
			}
			if len(data.Meta) > 0 {
				for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
					if data.Meta[len(data.Meta)-1].F[i].N == "enip.lir.vendor" {
						vendor := strings.ReplaceAll(data.Meta[len(data.Meta)-1].F[i].Sh, "Vendor ID: ", "")
						index := strings.Index(vendor, " (")
						if index != -1 {
							vendor = vendor[:index]
						}
						assetInsight.Vendor = vendor
					} else if data.Meta[len(data.Meta)-1].F[i].N == "enip.lir.name" {
						if strings.Contains(data.Meta[len(data.Meta)-1].F[i].V, "/") {
							assetInsight.Model = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, "/")[0]
						} else {
							assetInsight.Model = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, " ")[0]
						}
						assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
					} else if data.Meta[len(data.Meta)-1].F[i].N == "enip.lir.revision" {
						assetInsight.FirmwareVersion = strings.ReplaceAll(data.Meta[len(data.Meta)-1].F[i].Sh, "Revision: ", "")
					}
				}
				if assetInsight.Model != "" || assetInsight.CPUModel != "" || assetInsight.CPUType != "" {
					// 补充data数据
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		} else {
			*assetInsight, _ = cachedInsight.(model.AssetInsight)
			if assetInsight.IsBuiltin && len(data.Meta) > 0 {
				for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
					if data.Meta[len(data.Meta)-1].F[i].N == "enip.lir.vendor" {
						vendor := strings.ReplaceAll(data.Meta[len(data.Meta)-1].F[i].Sh, "Vendor ID: ", "")
						assetInsight.Vendor = strings.Split(vendor, " ")[0]
					} else if data.Meta[len(data.Meta)-1].F[i].N == "enip.lir.name" {
						if strings.Contains(data.Meta[len(data.Meta)-1].F[i].V, "/") {
							assetInsight.Model = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, "/")[0]
						} else {
							assetInsight.Model = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, " ")[0]
						}
						assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
					} else if data.Meta[len(data.Meta)-1].F[i].N == "enip.lir.revision" {
						assetInsight.FirmwareVersion = strings.ReplaceAll(data.Meta[len(data.Meta)-1].F[i].Sh, "Revision: ", "")
					}
				}
				if !h.compareWithOldAssetInsight(*assetInsight) {
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					assetInsight.Protocol = data.Protocol
					assetInsight.IsBuiltin = false
					assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
					assetInsight.UpdateTime = time.Now()
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		}
	}
}

// MODBUS协议解析
func (h *Handler) modbusProtocolHandle(data *model.ConsumerData, srcKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		if data.Protocol != "Modbus/TCP" || len(data.Meta) == 0 {
			return
		}

		assetInsight := pool.Get().(*model.AssetInsight)
		defer pool.Put(assetInsight)
		cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight")
		if !exist {
			// 识别MODBUS协议设备
			*assetInsight = model.AssetInsight{
				ID:            srcKey,
				IP:            data.SrcIP,
				OpenPort:      data.SrcPort,
				Protocol:      data.Protocol,
				Type:          model.AssetType(2),
				DeviceType:    "PLC",
				IsOnline:      true,
				Information:   handleInformation(data.Meta),
				Longitude:     data.LongitudeSrc,
				Latitude:      data.LatitudeSrc,
				Country:       data.SrcCountry,
				Province:      data.SrcProvince,
				City:          data.SrcCity,
				IsBuiltin:     false,
				CreateTime:    time.Now(),
				UpdateTime:    time.Now(),
				AttackedCount: 0,
				Direction:     false,
				DataByte:      base64.StdEncoding.EncodeToString(data.DataByte),
			}
			if len(data.Meta) > 0 && len(data.Meta[len(data.Meta)-1].F) > 0 {
				if data.Meta[len(data.Meta)-1].F[0].N == "modbus.func_code" && data.Meta[len(data.Meta)-1].F[0].V == "43" {
					num := 1
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if num == 1 && data.Meta[len(data.Meta)-1].F[i].N == "modbus.object_str_value" {
							num++
							// 第一次出现，赋值给 assetInsight.Vendor
							assetInsight.Vendor = data.Meta[len(data.Meta)-1].F[i].V
							if strings.HasPrefix(assetInsight.Vendor, "Schneider") {
								assetInsight.Vendor = "Schneider"
							} else if strings.HasPrefix(assetInsight.Model, "ABB") {
								assetInsight.Vendor = "ABB"
							}
						} else if num == 2 && data.Meta[len(data.Meta)-1].F[i].N == "modbus.object_str_value" {
							num++
							// 第二次出现，赋值给 assetInsight.CPUModel
							assetInsight.Model = data.Meta[len(data.Meta)-1].F[i].V
							assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
							if strings.HasPrefix(assetInsight.CPUModel, "HMI") {
								assetInsight.DeviceType = "HMI"
							}
						} else if num == 3 && data.Meta[len(data.Meta)-1].F[i].N == "modbus.object_str_value" {
							// 第三次出现，赋值给 assetInsight.FirmwareVersion
							assetInsight.FirmwareVersion = data.Meta[len(data.Meta)-1].F[i].V
						}
					}
				} else if data.Meta[len(data.Meta)-1].F[0].N == "modbus.func_code" && data.Meta[len(data.Meta)-1].F[0].V == "90" {
					assetInsight.Vendor = "Schneider"
				}
				if assetInsight.Vendor != "" || assetInsight.Model != "" || assetInsight.CPUModel != "" || assetInsight.CPUType != "" {
					// 补充data数据
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		} else {
			*assetInsight, _ = cachedInsight.(model.AssetInsight)
			if assetInsight.IsBuiltin && len(data.Meta) > 0 && len(data.Meta[len(data.Meta)-1].F) > 0 {
				if data.Meta[len(data.Meta)-1].F[0].N == "modbus.func_code" && data.Meta[len(data.Meta)-1].F[0].V == "43" {
					num := 1
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if num == 1 && data.Meta[len(data.Meta)-1].F[i].N == "modbus.object_str_value" {
							num++
							// 第一次出现，赋值给 assetInsight.Vendor
							assetInsight.Vendor = data.Meta[len(data.Meta)-1].F[i].V
							if strings.HasPrefix(assetInsight.Vendor, "Schneider") {
								assetInsight.Vendor = "Schneider"
							} else if strings.HasPrefix(assetInsight.Model, "ABB") {
								assetInsight.Vendor = "ABB"
							}
						} else if num == 2 && data.Meta[len(data.Meta)-1].F[i].N == "modbus.object_str_value" {
							num++
							// 第二次出现，赋值给 assetInsight.CPUModel
							assetInsight.Model = data.Meta[len(data.Meta)-1].F[i].V
							assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
							if strings.HasPrefix(assetInsight.CPUModel, "HMI") {
								assetInsight.DeviceType = "HMI"
							}
						} else if num == 3 && data.Meta[len(data.Meta)-1].F[i].N == "modbus.object_str_value" {
							// 第三次出现，赋值给 assetInsight.FirmwareVersion
							assetInsight.FirmwareVersion = data.Meta[len(data.Meta)-1].F[i].V
						}
					}
				} else if data.Meta[len(data.Meta)-1].F[0].N == "modbus.func_code" && data.Meta[len(data.Meta)-1].F[0].V == "90" {
					assetInsight.Vendor = "Schneider"
				}
				if !h.compareWithOldAssetInsight(*assetInsight) {
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					assetInsight.Protocol = data.Protocol
					assetInsight.IsBuiltin = false
					assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
					assetInsight.UpdateTime = time.Now()
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		}
	}
}

// S7COMM协议解析
func (h *Handler) s7commProtocolHandle(data *model.ConsumerData, srcKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		if (data.Protocol != "S7COMM" && data.Protocol != "S7COMM-PLUS") || data.SrcPort != 102 || len(data.Meta) == 0 {
			return
		}
		// 获取或创建 model.AssetInsight 对象
		assetInsight := pool.Get().(*model.AssetInsight)
		defer pool.Put(assetInsight)
		cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight")
		if !exist {
			// 识别西门子设备
			*assetInsight = model.AssetInsight{
				ID:            srcKey,
				IP:            data.SrcIP,
				OpenPort:      data.SrcPort,
				Protocol:      data.Protocol,
				Type:          model.AssetType(2),
				Vendor:        "Siemens",
				DeviceType:    "PLC",
				IsOnline:      true,
				Information:   handleInformation(data.Meta),
				Longitude:     data.LongitudeSrc,
				Latitude:      data.LatitudeSrc,
				Country:       data.SrcCountry,
				Province:      data.SrcProvince,
				City:          data.SrcCity,
				IsBuiltin:     false,
				CreateTime:    time.Now(),
				UpdateTime:    time.Now(),
				AttackedCount: 0,
				Direction:     false,
				DataByte:      base64.StdEncoding.EncodeToString(data.DataByte),
			}
			if len(data.Meta) > 0 {
				if data.Protocol == "S7COMM" {
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if assetInsight.CPUModel == "" {
							if data.Meta[len(data.Meta)-1].F[i].N == "s7comm.szl.xy11.0001.anz" {
								assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
								switch assetInsight.CPUModel[5:6] {
								case "2":
									if assetInsight.CPUModel[9:10] == "1" {
										assetInsight.Model = "S7-1200"
									} else {
										assetInsight.Model = "S7-200"
									}
								case "3":
									assetInsight.Model = "S7-300"
								case "4":
									assetInsight.Model = "S7-400"
								case "5":
									assetInsight.Model = "S7-1500"
								case "1":
									assetInsight.Model = "S7-1500"
								default:
									if strings.Contains(assetInsight.CPUModel, "1500") {
										assetInsight.Model = "S7-1500"
									}
								}
							}
						}
						if assetInsight.FirmwareVersion == "" {
							if data.Meta[len(data.Meta)-1].F[i].N == "s7comm.szl.xy11.0001.ausbg" {
								assetInsight.FirmwareVersion = data.Meta[len(data.Meta)-1].F[i].V
							}
						}
					}
				} else if data.Protocol == "S7COMM-PLUS" {
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if assetInsight.CPUModel == "" {
							if data.Meta[len(data.Meta)-1].F[i].N == "s7comm-plus.value.wstring" {
								if strings.Contains(data.Meta[len(data.Meta)-1].F[i].V, ";") {
									assetInsight.CPUModel = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, ";")[1]
									assetInsight.FirmwareVersion = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, ";")[2]
									switch assetInsight.CPUModel[5:6] {
									case "2":
										if assetInsight.CPUModel[9:10] == "1" {
											assetInsight.Model = "S7-1200"
										} else {
											assetInsight.Model = "S7-200"
										}
									case "3":
										assetInsight.Model = "S7-300"
									case "4":
										assetInsight.Model = "S7-400"
									case "5":
										assetInsight.Model = "S7-1500"
									case "1":
										assetInsight.Model = "S7-1500"
									default:
										if strings.Contains(assetInsight.CPUModel, "1500") {
											assetInsight.Model = "S7-1500"
										} else {
											assetInsight.Model = ""
										}
									}
								}
							}
						}
					}
				}
				if assetInsight.Model != "" || assetInsight.CPUModel != "" || assetInsight.CPUType != "" {
					// 补充data数据
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		} else {
			*assetInsight, _ = cachedInsight.(model.AssetInsight)
			if assetInsight.IsBuiltin && len(data.Meta) > 0 {
				if data.Protocol == "S7COMM" {
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if assetInsight.CPUModel == "" {
							if data.Meta[len(data.Meta)-1].F[i].N == "s7comm.szl.xy11.0001.anz" {
								assetInsight.CPUModel = data.Meta[len(data.Meta)-1].F[i].V
								switch assetInsight.CPUModel[5:6] {
								case "2":
									if assetInsight.CPUModel[9:10] == "1" {
										assetInsight.Model = "S7-1200"
									} else {
										assetInsight.Model = "S7-200"
									}
								case "3":
									assetInsight.Model = "S7-300"
								case "4":
									assetInsight.Model = "S7-400"
								case "5":
									assetInsight.Model = "S7-1500"
								case "1":
									assetInsight.Model = "S7-1500"
								default:
									if strings.Contains(assetInsight.CPUModel, "1500") {
										assetInsight.Model = "S7-1500"
									} else {
										assetInsight.Model = ""
									}
								}
							}
						}
						if assetInsight.FirmwareVersion == "" {
							if data.Meta[len(data.Meta)-1].F[i].N == "s7comm.szl.xy11.0001.ausbg" {
								assetInsight.FirmwareVersion = data.Meta[len(data.Meta)-1].F[i].V
							}
						}
					}
				} else if data.Protocol == "S7COMM-PLUS" {
					for i := 0; i < len(data.Meta[len(data.Meta)-1].F); i++ {
						if assetInsight.CPUModel == "" {
							if data.Meta[len(data.Meta)-1].F[i].N == "s7comm-plus.value.wstring" {
								if strings.Contains(data.Meta[len(data.Meta)-1].F[i].V, ";") {
									assetInsight.CPUModel = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, ";")[1]
									assetInsight.FirmwareVersion = strings.Split(data.Meta[len(data.Meta)-1].F[i].V, ";")[2]
									switch assetInsight.CPUModel[5:6] {
									case "2":
										if assetInsight.CPUModel[9:10] == "1" {
											assetInsight.Model = "S7-1200"
										} else {
											assetInsight.Model = "S7-200"
										}
									case "3":
										assetInsight.Model = "S7-300"
									case "4":
										assetInsight.Model = "S7-400"
									case "5":
										assetInsight.Model = "S7-1500"
									case "1":
										assetInsight.Model = "S7-1500"
									default:
										if strings.Contains(assetInsight.CPUModel, "1500") {
											assetInsight.Model = "S7-1500"
										} else {
											assetInsight.Model = ""
										}
									}
								}
							}
						}
					}
				}
				if !h.compareWithOldAssetInsight(*assetInsight) {
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					assetInsight.Protocol = data.Protocol
					assetInsight.IsBuiltin = false
					assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
					assetInsight.UpdateTime = time.Now()
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		}
	}
}

// TCP协议解析
func (h *Handler) tcpProtocolHandle(data *model.ConsumerData, srcKey string, wg *sync.WaitGroup) {
	defer wg.Done()

	select {
	case <-h.ctx.Done():
		return
	default:
		if data.Protocol != "TCP" || len(data.Meta) == 0 {
			return
		}
		// 处理模拟数据
		if len(data.DataByte) >= 61 && string(data.DataByte[56:61]) == "06GEN" {
			h.handleTcpTest(data, srcKey)
			return
		}
		// 获取或创建 model.AssetInsight 对象
		assetInsight := pool.Get().(*model.AssetInsight)
		defer pool.Put(assetInsight)
		cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight")
		if !exist {
			// 识别研华设备
			if data.SrcPort == 5058 || data.SrcPort == 5048 {
				// 获取设备类型标识
				if len(data.DataByte) > 78 {
					subArr := data.DataByte[76:78]
					hexString := hex.EncodeToString(subArr)
					if DeviceModelMap[hexString] != "" {
						data.Vendor = "研华科技"
						data.DeviceType = "PLC"
						data.Model = DeviceModelMap[hexString]
						*assetInsight = model.AssetInsight{
							ID:            srcKey,
							IP:            data.SrcIP,
							OpenPort:      data.SrcPort,
							Protocol:      data.Protocol,
							Type:          model.AssetType(2),
							Vendor:        "研华科技",
							DeviceType:    "PLC",
							Model:         DeviceModelMap[hexString],
							CPUModel:      DeviceModelMap[hexString],
							IsOnline:      true,
							Longitude:     data.LongitudeSrc,
							Latitude:      data.LatitudeSrc,
							Country:       data.SrcCountry,
							Province:      data.SrcProvince,
							City:          data.SrcCity,
							IsBuiltin:     false,
							CreateTime:    time.Now(),
							UpdateTime:    time.Now(),
							AttackedCount: 0,
							Direction:     false,
							DataByte:      base64.StdEncoding.EncodeToString(data.DataByte),
						}
						data.Vendor = assetInsight.Vendor
						data.DeviceType = assetInsight.DeviceType
						data.Model = assetInsight.Model
						h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
						setUniqueSaveAssetInsight(srcKey, *assetInsight)
					}
				}
			} else if data.SrcPort == 1962 {
				// 识别菲尼克斯设备
				// 获取设备类型标识
				if len(data.DataByte) > 204 {
					if strings.HasPrefix(string(data.DataByte[84:100]), "ILC") {
						data.Vendor = "Phoenix"
						data.DeviceType = "PLC"
						m := string(data.DataByte[84:100])
						cpuModel := string(data.DataByte[204 : len(data.DataByte)-1])
						firmwareVersion := string(data.DataByte[110:124])
						data.Model = strings.ReplaceAll(m, "\u0000", "")
						*assetInsight = model.AssetInsight{
							ID:              srcKey,
							IP:              data.SrcIP,
							OpenPort:        data.SrcPort,
							Protocol:        data.Protocol,
							Type:            model.AssetType(2),
							Vendor:          "Phoenix",
							DeviceType:      "PLC",
							Model:           strings.ReplaceAll(m, "\u0000", ""),
							CPUModel:        strings.ReplaceAll(cpuModel, "\u0000", ""),
							FirmwareVersion: strings.ReplaceAll(firmwareVersion, "\u0000", ""),
							IsOnline:        true,
							Longitude:       data.LongitudeSrc,
							Latitude:        data.LatitudeSrc,
							Country:         data.SrcCountry,
							Province:        data.SrcProvince,
							City:            data.SrcCity,
							CreateTime:      time.Now(),
							UpdateTime:      time.Now(),
							AttackedCount:   0,
							Direction:       false,
							DataByte:        base64.StdEncoding.EncodeToString(data.DataByte),
						}
						data.Vendor = assetInsight.Vendor
						data.DeviceType = assetInsight.DeviceType
						data.Model = assetInsight.Model
						h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
						setUniqueSaveAssetInsight(srcKey, *assetInsight)
					}
				}
			}
		} else {
			*assetInsight, _ = cachedInsight.(model.AssetInsight)
			if assetInsight.IsBuiltin {
				// 识别研华设备
				if data.SrcPort == 5058 || data.SrcPort == 5048 {
					// 获取设备类型标识
					if len(data.DataByte) > 78 {
						subArr := data.DataByte[76:78]
						hexString := hex.EncodeToString(subArr)
						if DeviceModelMap[hexString] != "" {
							assetInsight.Vendor = "研华科技"
							assetInsight.DeviceType = "PLC"
							assetInsight.Model = DeviceModelMap[hexString]
							assetInsight.CPUModel = DeviceModelMap[hexString]
							assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
						}
					}
				} else if data.SrcPort == 1962 {
					// 识别菲尼克斯设备
					// 获取设备类型标识
					if len(data.DataByte) > 204 {
						if strings.HasPrefix(string(data.DataByte[84:100]), "ILC") {
							model := string(data.DataByte[84:100])
							cpuModel := string(data.DataByte[204 : len(data.DataByte)-1])
							firmwareVersion := string(data.DataByte[110:124])
							assetInsight.Vendor = "Phoenix"
							assetInsight.DeviceType = "PLC"
							assetInsight.Model = strings.ReplaceAll(model, "\u0000", "")
							assetInsight.CPUModel = strings.ReplaceAll(cpuModel, "\u0000", "")
							assetInsight.FirmwareVersion = strings.ReplaceAll(firmwareVersion, "\u0000", "")
							assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
						}
					}
				}
				if !h.compareWithOldAssetInsight(*assetInsight) {
					data.Vendor = assetInsight.Vendor
					data.DeviceType = assetInsight.DeviceType
					data.Model = assetInsight.Model
					assetInsight.Protocol = data.Protocol
					assetInsight.IsBuiltin = false
					assetInsight.UpdateTime = time.Now()
					h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
					setUniqueSaveAssetInsight(srcKey, *assetInsight)
				}
			}
		}
	}
}

func (h *Handler) handleTcpTest(data *model.ConsumerData, srcKey string) {
	payload := string(data.DataByte[54:])
	split := strings.Split(payload, ";")
	assetType, _ := strconv.Atoi(split[1][1:])

	// 获取或创建 model.AssetInsight 对象
	assetInsight := pool.Get().(*model.AssetInsight)
	defer pool.Put(assetInsight)
	cachedInsight, exist := h.svc.Cache.Local.Get(srcKey + "_assetInsight")
	if !exist {
		*assetInsight = model.AssetInsight{
			ID:              srcKey,
			IP:              data.SrcIP,
			OpenPort:        data.SrcPort,
			Protocol:        data.Protocol,
			Type:            model.AssetType(assetType),
			Vendor:          split[3],
			DeviceType:      split[2],
			Model:           split[4],
			CPUModel:        split[5],
			FirmwareVersion: split[6],
			IsOnline:        true,
			Longitude:       data.LongitudeSrc,
			Latitude:        data.LatitudeSrc,
			Country:         data.SrcCountry,
			Province:        data.SrcProvince,
			City:            data.SrcCity,
			IsBuiltin:       false,
			CreateTime:      time.Now(),
			UpdateTime:      time.Now(),
			AttackedCount:   0,
			Direction:       false,
			DataByte:        base64.StdEncoding.EncodeToString(data.DataByte),
		}
		data.Vendor = assetInsight.Vendor
		data.DeviceType = assetInsight.DeviceType
		data.Model = assetInsight.Model
		h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
		setUniqueSaveAssetInsight(srcKey, *assetInsight)
	} else {
		*assetInsight, _ = cachedInsight.(model.AssetInsight)
		if assetInsight.IsBuiltin {
			assetInsight.Vendor = split[3]
			assetInsight.DeviceType = split[2]
			assetInsight.Model = split[4]
			assetInsight.CPUModel = split[5]
			assetInsight.FirmwareVersion = split[6]
			assetInsight.DataByte = base64.StdEncoding.EncodeToString(data.DataByte)
			if !h.compareWithOldAssetInsight(*assetInsight) {
				data.Vendor = assetInsight.Vendor
				data.DeviceType = assetInsight.DeviceType
				data.Model = assetInsight.Model
				assetInsight.Protocol = data.Protocol
				assetInsight.IsBuiltin = false
				assetInsight.UpdateTime = time.Now()
				h.svc.Cache.Local.Set(srcKey+"_assetInsight", *assetInsight, 0)
				setUniqueSaveAssetInsight(srcKey, *assetInsight)
			}
		}
	}
}

func (h *Handler) compareWithOldAssetInsight(assetInsight model.AssetInsight) bool {

	assetInsightOld, exist := h.svc.Cache.Local.Get(fmt.Sprintf("%s_%d_assetInsight", assetInsight.IP, assetInsight.OpenPort))
	if exist {
		assetInsightOld, _ := assetInsightOld.(model.AssetInsight)
		if reflect.DeepEqual(assetInsight, assetInsightOld) {
			return true
		}
	}
	return false
}

func batchSave(svc *internal.ServiceContext) {
	uniqueSaveAssetInsight.Range(func(key, value interface{}) bool {
		v, ok := value.(model.AssetInsight)
		if ok {
			batchRecords = append(batchRecords, v)
			return true
		}
		return false
	})

	if len(batchRecords) > 0 {
		if err := svc.DB.Save(&batchRecords).Error; err != nil {
			logrus.Errorln("批量保存资产分析数据失败：", err)
		}

		batchRecords = nil
		uniqueSaveAssetInsight = sync.Map{}
	}
}

func setUniqueSaveAssetInsight(key string, value model.AssetInsight) {
	if VendorMap[value.Vendor] != "" {
		value.Vendor = VendorMap[value.Vendor]
	}
	if typeMap[value.DeviceType] != "" {
		value.DeviceType = typeMap[value.DeviceType]
	}
	uniqueSaveAssetInsight.Store(key, value)
}

func getDirectionMap(key string) string {
	value, ok := directionMap.Load(key)
	if ok {
		return value.(string)
	}
	return ""
}

func handleInformation(meta []model.ProtocolData) string {
	jsonData, err := json.Marshal(meta)
	if err != nil {
		fmt.Println("Error marshaling to JSON:", err)
		return ""
	}
	return string(jsonData)
}
