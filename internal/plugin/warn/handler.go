package warn

import (
	"context"
	"fmt"
	"sync"

	"dissect/internal"
	"dissect/internal/model"
	"dissect/pkg/cache"
	"strconv"
	"strings"
	"time"

	"github.com/duke-git/lancet/v2/slice"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/songzhibin97/gkit/cache/local_cache"
)

type Handler struct {
	cache    local_cache.Cache
	wg       sync.WaitGroup
	svc      *internal.ServiceContext
	ctx      context.Context
	attackCh chan *Record // 攻击维度消费通道
	victimCh chan *Record // 被攻击维度消费通道
}

func NewHandler(ctx context.Context, svc *internal.ServiceContext) *Handler {
	h := &Handler{
		ctx:      ctx,
		cache:    cache.NewCache(0),
		wg:       sync.WaitGroup{},
		svc:      svc,
		attackCh: make(chan *Record),
		victimCh: make(chan *Record),
	}

	go func() {
		for result := range h.attackCh {
			select {
			case <-ctx.Done():
				return
			default:
				h.aggregationEventFun(result)
			}
		}
	}()

	go func() {
		for result := range h.victimCh {
			select {
			case <-ctx.Done():
				return
			default:
				h.aggregationVictimFun(result)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.saveData()
			}
		}
	}()

	return h
}

// Handle implements plugin.Handler.
func (h *Handler) Handle(result *model.ConsumerData) {

	if result.SrcIP == "" || result.DstIP == "" || (!result.IsKey && !result.IsAttack && result.ErrType == 0) || (result.ProtocolType != 2 && result.ProtocolType != 3) {
		return
	}

	if rule, ok := h.svc.Cache.SuricataRuleMap[result.SID]; ok {
		result.EventType = rule.EventType
		result.EventLevel = rule.Level
		result.Vul = rule.CorrVuln
		if rule.CorrVuln != "" {
			result.IsVul = true
		}
	}

	year, month, day := result.CreateTime.Date()
	timeKey := fmt.Sprintf("%d%d%d%d", year, month, day, result.CreateTime.Hour())
	h.wg.Add(2)

	go func() {
		defer h.wg.Done()
		for {
			select {
			case <-h.ctx.Done():
				return
			default:
				h.attackFunction(result, timeKey)
				return
			}
		}
	}()
	go func() {
		defer h.wg.Done()
		for {
			select {
			case <-h.ctx.Done():
				return
			default:
				h.victimFunction(result, timeKey)
				return
			}
		}
	}()
	h.wg.Wait()
}

// 攻击维度 client <-> service || client -> service
func (h *Handler) attackFunction(data *model.ConsumerData, timeKey string) {
	// 1: client -> service
	if data.Direction == 1 || data.Direction == 0 {
		var _uuid string
		srcArr := strings.Split(data.SrcIP, ".")
		srcIpSubnet := fmt.Sprintf("%s.%s.%s.0", srcArr[0], srcArr[1], srcArr[2]) //192.168.124.0/24
		if eventId, ok := h.cache.Get(fmt.Sprintf("%s-%s", timeKey, srcIpSubnet)); ok {
			_uuid = eventId.(string)
		} else {
			_uuid = uuid.New().String()
			h.cache.SetDefault(fmt.Sprintf("%s-%s", timeKey, srcIpSubnet), _uuid)
		}
		data.EventID = _uuid
		h.attackCh <- convertData(data, _uuid, data.DstIP, data.DstCountry, data.DstProvince, data.DstCity, data.SrcIP, data.LatitudeDst, data.LongitudeDst)

		key := fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.SrcIP, data.SrcPort, data.DstIP, data.DstPort, 2)
		item, ok := h.cache.Get(key)
		if ok {
			consumerData := item.(*model.ConsumerData)
			consumerData.EventID = _uuid
			h.attackCh <- convertData(consumerData, _uuid, consumerData.DstIP, consumerData.DstCountry, consumerData.DstProvince, consumerData.DstCity, consumerData.SrcIP, consumerData.LatitudeDst, consumerData.LongitudeDst)
			h.cache.Delete(key)
		} else {
			h.cache.SetDefault(fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.SrcIP, data.SrcPort, data.DstIP, data.DstPort, 1), data)
		}
		// 2: service -> client
	} else if data.Direction == 2 {
		key := fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.DstIP, data.DstPort, data.SrcIP, data.SrcPort, 1)
		item, ok := h.cache.Get(key)
		if ok {
			consumerData := item.(*model.ConsumerData)
			data.EventID = consumerData.EventID
			h.cache.Delete(key)
			h.attackCh <- convertData(data, data.EventID, data.DstIP, data.DstCountry, data.DstProvince, data.DstCity, data.SrcIP, data.LatitudeDst, data.LongitudeDst)
		} else {
			h.cache.SetDefault(fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.DstIP, data.DstPort, data.SrcIP, data.SrcPort, 2), data)
		}
	}
}

// 被攻击维度 client -> service and service -> client || service -> client
func (h *Handler) victimFunction(data *model.ConsumerData, timeKey string) {
	if data.Direction == 1 || data.Direction == 0 {
		key := fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.SrcIP, data.SrcPort, data.DstIP, data.DstPort, 2)
		item, ok := h.cache.Get(key)
		if ok && item != nil {
			consumerData := item.(*model.ConsumerData)
			_uuid := consumerData.VictimID
			data.VictimID = _uuid
			h.victimCh <- convertData(data, _uuid, data.SrcIP, data.SrcCountry, data.SrcProvince, data.SrcCity, data.DstIP, data.LatitudeSrc, data.LongitudeSrc)
			h.cache.Delete(key)
		} else {
			h.cache.SetDefault(fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.SrcIP, data.SrcPort, data.DstIP, data.DstPort, 1), data)
		}
	} else if data.Direction == 2 {
		var _uuid string
		if victimId, ok := h.cache.Get(fmt.Sprintf("%s-%s", timeKey, data.SrcIP)); ok {
			_uuid = victimId.(string)
		} else {
			_uuid = uuid.New().String()
			h.cache.SetDefault(fmt.Sprintf("%s-%s", timeKey, data.SrcIP), _uuid)
		}
		data.VictimID = _uuid
		h.victimCh <- convertData(data, _uuid, data.DstIP, data.DstCountry, data.DstProvince, data.DstCity, data.SrcIP, data.LatitudeDst, data.LongitudeDst)

		key := fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.DstIP, data.DstPort, data.SrcIP, data.SrcPort, 1)
		item, ok := h.cache.Get(key)
		if ok {
			consumerData := item.(*model.ConsumerData)
			consumerData.VictimID = _uuid
			h.victimCh <- convertData(consumerData, _uuid, consumerData.DstIP, consumerData.DstCountry, consumerData.DstProvince, consumerData.DstCity, consumerData.SrcIP, consumerData.LatitudeDst, consumerData.LongitudeDst)
			h.cache.Delete(key)
		} else {
			h.cache.SetDefault(fmt.Sprintf("%s-%s-%d-%s-%d-%d", timeKey, data.DstIP, data.DstPort, data.SrcIP, data.SrcPort, 2), data)
		}
	}
}

func (h *Handler) aggregationEventFun(record *Record) {
	var event AlertEvent
	eventInCache, expire, ok := h.cache.GetWithExpire(record.EventId)
	var residue time.Duration
	if ok {
		event = eventInCache.(AlertEvent)
		residue = expire.Sub(time.Now())
	} else {
		if record.Ip == "" {
			return
		}
		event.SrcLocation = []float32{0, 0}
	}
	event.ID = uuid.MustParse(record.EventId)
	if !record.StartTime.IsZero() {
		if event.StartTime.IsZero() || event.StartTime.After(record.StartTime) {
			event.StartTime = record.StartTime
		}
	}
	if !record.EndTime.IsZero() {
		if event.EndTime.IsZero() || event.EndTime.Before(record.EndTime) {
			event.EndTime = record.EndTime
		}
	}
	if record.Ip != "" && !slice.Contain(event.Src, record.Ip) {
		event.Src = append(event.Src, record.Ip)
	}
	if record.Protocol != "" && !slice.Contain(event.Protocol, record.Protocol) {
		event.Protocol = append(event.Protocol, record.Protocol)
	}
	if record.EventType != "" && !slice.Contain(event.EventType, record.EventType) {
		event.EventType = append(event.EventType, record.EventType)
	}
	if record.Country != "" {
		event.SrcCountry = record.Country
	}
	if record.Province != "" {
		event.SrcProvince = record.Province
	}
	if record.City != "" {
		event.SrcCity = record.City
	}
	if record.IsAttack {
		event.AttackCount++
	}
	if record.IsKey {
		event.KeyCount++
		if record.Action != "" && !slice.Contain(event.Action, record.Action) {
			event.Action = append(event.Action, record.Action)
		}
	}
	if record.IsErr {
		event.ErrCount++
		formatInt := strconv.FormatInt(int64(record.ErrType), 10)
		if record.ErrType != 0 && !slice.Contain(event.ErrType, formatInt) {
			event.ErrType = append(event.ErrType, formatInt)
		}
	}
	if record.Level != 0 && record.Level > event.Level {
		event.Level = record.Level
	}
	if record.CIP != "" && !slice.Contain(event.ConnectIp, record.CIP) {
		event.ConnectIp = append(event.ConnectIp, record.CIP)
		event.ConnectIpCount = len(event.ConnectIp)
	}
	if record.ConnectCount != 0 {
		event.ConnectCount++
	}
	if record.Latitude != 0 {
		event.SrcLocation[0] = record.Latitude
	}
	if record.Longitude != 0 {
		event.SrcLocation[1] = record.Longitude
	}
	event.Version++
	if residue != 0 {
		h.cache.Set(record.EventId, event, residue)
	} else {
		h.cache.SetDefault(record.EventId, event)
	}
}

func (h *Handler) aggregationVictimFun(record *Record) {
	var victim AlertVictim
	eventInCache, expire, ok := h.cache.GetWithExpire(record.EventId)
	var residue time.Duration
	if ok {
		victim = eventInCache.(AlertVictim)
		residue = expire.Sub(time.Now())
	} else {
		if record.Ip == "" {
			return
		}
		victim.DstLocation = []float32{0, 0}
	}
	victim.ID = uuid.MustParse(record.EventId)
	if !record.StartTime.IsZero() {
		if victim.StartTime.IsZero() || victim.StartTime.After(record.StartTime) {
			victim.StartTime = record.StartTime
		}
	}
	if !record.EndTime.IsZero() {
		if victim.EndTime.IsZero() || victim.EndTime.Before(record.EndTime) {
			victim.EndTime = record.EndTime
		}
	}
	if record.Ip != "" {
		victim.Dst = record.Ip
	}
	if record.Protocol != "" && !slice.Contain(victim.Protocol, record.Protocol) {
		victim.Protocol = append(victim.Protocol, record.Protocol)
	}
	if record.EventType != "" && !slice.Contain(victim.EventType, record.EventType) {
		victim.EventType = append(victim.EventType, record.EventType)
	}
	if record.Country != "" {
		victim.DstCountry = record.Country
	}
	if record.Province != "" {
		victim.DstProvince = record.Province
	}
	if record.City != "" {
		victim.DstCity = record.City
	}
	if record.IsAttack {
		victim.AttackCount++
	}
	if record.IsKey {
		victim.KeyCount++
		if record.Action != "" && !slice.Contain(victim.Action, record.Action) {
			victim.Action = append(victim.Action, record.Action)
		}
	}
	if record.IsErr {
		victim.ErrCount++
		formatInt := strconv.FormatInt(int64(record.ErrType), 10)
		if record.ErrType != 0 && !slice.Contain(victim.ErrType, formatInt) {
			victim.ErrType = append(victim.ErrType, formatInt)
		}
	}
	if record.Level != 0 && record.Level > victim.Level {
		victim.Level = record.Level
	}
	if record.CIP != "" && !slice.Contain(victim.ConnectIp, record.CIP) {
		victim.ConnectIp = append(victim.ConnectIp, record.CIP)
		victim.ConnectIpCount = len(victim.ConnectIp)
	}
	if record.Model != "" {
		victim.Model = record.Model
	}
	if record.DeviceType != "" {
		victim.DeviceType = record.DeviceType
	}
	if record.Vendor != "" {
		victim.Vendor = record.Vendor
	}
	if record.ConnectCount != 0 {
		victim.ConnectCount++
	}
	if record.Latitude != 0 {
		victim.DstLocation[0] = record.Latitude
	}
	if record.Longitude != 0 {
		victim.DstLocation[1] = record.Longitude
	}
	victim.Version++
	if residue != 0 {
		h.cache.Set(record.EventId, victim, residue)
	} else {
		h.cache.SetDefault(record.EventId, victim)
	}
}

func (h *Handler) saveData() {

	var eventList []AlertEvent
	for _, item := range h.cache.Iterator() {
		event, ok := item.Val.(AlertEvent)
		if !ok {
			continue
		}
		if ct, ok := h.cache.Get(event.ID.String() + "SAVED_CACHE"); ok {
			oldCreateTime := ct.([]interface{})[0].(time.Time)
			oldVersion := ct.([]interface{})[1].(uint8)
			if event.Version == oldVersion {
				continue
			}

			eventList = append(eventList, AlertEvent{
				ID:          event.ID,
				StartTime:   time.Now(),
				EndTime:     time.Now(),
				SrcLocation: []float32{0, 0},
				Sign:        -1,
				CreateTime:  oldCreateTime,
			})
		}
		event.Sign = 1
		event.CreateTime = time.Now()
		eventList = append(eventList, event)
	}

	if len(eventList) > 0 {
		if err := h.svc.ClickHouseDB.CreateInBatches(eventList, len(eventList)).Error; err == nil {
			for _, item := range eventList {
				h.cache.SetDefault(item.ID.String()+"SAVED_CACHE", []interface{}{item.CreateTime, item.Version})
			}
			eventList = nil
		} else {
			logrus.Errorln("save AlertEvent data error!", err)
		}
	}

	var victimList []AlertVictim
	for _, item := range h.cache.Iterator() {
		victim, ok := item.Val.(AlertVictim)
		if !ok {
			continue
		}
		if ct, ok := h.cache.Get(victim.ID.String() + "SAVED_CACHE"); ok {
			oldCreateTime := ct.([]interface{})[0].(time.Time)
			oldVersion := ct.([]interface{})[1].(uint8)
			if victim.Version == oldVersion {
				continue
			}
			victimList = append(victimList, AlertVictim{
				ID:          victim.ID,
				StartTime:   time.Now(),
				EndTime:     time.Now(),
				DstLocation: []float32{0, 0},
				Sign:        -1,
				CreateTime:  oldCreateTime,
			})
		}
		victim.Sign = 1
		victim.CreateTime = time.Now()
		victimList = append(victimList, victim)
	}

	if len(victimList) > 0 {
		if err := h.svc.ClickHouseDB.CreateInBatches(victimList, len(victimList)).Error; err == nil {
			for _, item := range victimList {
				h.cache.SetDefault(item.ID.String()+"SAVED_CACHE", []interface{}{item.CreateTime, item.Version})
			}
			victimList = nil
		} else {
			logrus.Errorln("save AlertVictim data error!", err)
		}
	}
}

func convertData(data *model.ConsumerData, _uuid string, ip string, country string, province string, city string, cip string, latitude float32, longitude float32) *Record {
	return &Record{
		EventId:      _uuid,
		Ip:           ip,
		Protocol:     data.Protocol,
		EventType:    data.EventType,
		ConnectCount: 1,
		IsKey:        data.IsKey,
		IsAttack:     data.IsAttack,
		Country:      country,
		Province:     province,
		City:         city,
		StartTime:    data.CreateTime,
		EndTime:      data.CreateTime,
		IsErr:        data.ErrType != 0,
		CIP:          cip,
		Level:        data.EventLevel,
		DeviceType:   data.DeviceType,
		Model:        data.Model,
		Vendor:       data.Vendor,
		Latitude:     latitude,
		Longitude:    longitude,
		Action:       data.Action,
		ErrType:      data.ErrType,
	}
}
