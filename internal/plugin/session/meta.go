package session

import (
	"dissect/internal/model"
	meta "dissect/internal/plugin/session/pb/meta"
	metaprotocol "dissect/internal/plugin/session/pb/meta/protocol"
	"errors"
	"log"
	"reflect"
	"strconv"
	"strings"

	"github.com/duke-git/lancet/v2/convertor"
	"github.com/duke-git/lancet/v2/slice"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

var (
	Container  map[string]reflect.Type = make(map[string]reflect.Type)
	ThreatType map[string]*uint32      = make(map[string]*uint32)
)

func init() {
	Container["BACnet-APDU"] = reflect.TypeOf(metaprotocol.BacNetInfo{})
	Container["DNP 3.0"] = reflect.TypeOf(metaprotocol.DNP3Info{})
	Container["ENIP"] = reflect.TypeOf(metaprotocol.EnipInfo{})
	Container["CIP"] = reflect.TypeOf(metaprotocol.EtherNetIpInfo{})
	Container["ICS"] = reflect.TypeOf(metaprotocol.ICSInfo{})
	Container["IEC 60870-5-104"] = reflect.TypeOf(metaprotocol.Iec104Info{})
	Container["MMS"] = reflect.TypeOf(metaprotocol.Iec61850MmsInfo{})
	Container["Modbus/TCP"] = reflect.TypeOf(metaprotocol.ModbusInfo{})
	Container["OMRON"] = reflect.TypeOf(metaprotocol.OmronFinsInfo{})
	Container["OpcUa"] = reflect.TypeOf(metaprotocol.OpcUaInfo{})
	Container["Profinet"] = reflect.TypeOf(metaprotocol.ProFiNetInfo{})
	Container["S7COMM"] = reflect.TypeOf(metaprotocol.S7CommInfo{})
	Container["H1"] = reflect.TypeOf(metaprotocol.Sinech1Info{})

	ThreatType["上位机漏洞利用"] = proto.Uint32(0x040001)
	ThreatType["工业交换机漏洞利用"] = proto.Uint32(0x040002)
	ThreatType["PLC 漏洞利用"] = proto.Uint32(0x040003)
	ThreatType["SCADA 漏洞利用"] = proto.Uint32(0x040004)
	ThreatType["DCS 漏洞利用"] = proto.Uint32(0x040005)
	ThreatType["HMI 漏洞利用"] = proto.Uint32(0x040006)
	ThreatType["楼宇自动化漏洞利用"] = proto.Uint32(0x040007)
	ThreatType["操作指令伪造"] = proto.Uint32(0x040008)
	ThreatType["物联网设备攻击"] = proto.Uint32(0x040009)
	ThreatType["实时操作系统攻击"] = proto.Uint32(0x040010)
	ThreatType["实时数据库攻击"] = proto.Uint32(0x04000A)
	ThreatType["信息泄露"] = proto.Uint32(0x02000D)
	ThreatType["数据伪造"] = proto.Uint32(0x04000B)
	ThreatType["拒绝服务"] = proto.Uint32(0x02002E)
	ThreatType["远程代码执行利用"] = proto.Uint32(0x020020)
	ThreatType["信息侦察"] = proto.Uint32(0x020001)
	ThreatType["缓冲区溢出利用"] = proto.Uint32(0x02002A)
}

func fillMetaData(data *model.ConsumerData, conf *Config) *meta.MetaInfo {

	var protocolInfo meta.ProtocolInfo
	metaConfig, ok := conf.ReportMetaConfigMap[data.Protocol]
	if !ok {
		return nil
	}

	targetType, exists := Container[data.Protocol]
	if !exists {
		logrus.Errorln("无法找到协议的类型映射:", data.Protocol)
		return nil
	}

	var protocolCode uint32
	var metaDataFNs []*model.ProtocolField
	ptr := reflect.New(targetType).Elem()

	for i := range data.Meta {
		for j := range data.Meta[i].F {
			fData := data.Meta[i].F[j]
			metaDataFNs = append(metaDataFNs, &fData)
			config := metaConfig[fData.N]
			if config == nil {
				continue
			}

			pUint, err := strconv.ParseUint(config.ProtocolCode, 0, 64)
			if err != nil {
				logrus.Errorln("无法解析协议码：", config.ProtocolCode, err)
				continue
			}

			protocolCode = uint32(pUint)
			setObjFiled(&ptr, config.Filed, config.FiledType, fData.V)
		}
	}

	specialFieldExtract(data, &ptr, metaDataFNs)
	message := ptr.Addr().Interface()
	msg, ok := message.(proto.Message)
	if !ok {
		logrus.Errorln("Value is not a proto.Message")
		return nil
	}

	anyMessage, err := anypb.New(msg)
	if err != nil {
		logrus.Errorln("Error marshaling to anypb.Any:", err)
		return nil
	}

	if protocolCode != 0 {
		protocolInfo.Type = convertor.ToPointer(protocolCode)
		protocolInfo.ProtocolMeta = anyMessage
		return &meta.MetaInfo{
			ProtocolInfo: []*meta.ProtocolInfo{&protocolInfo},
		}
	}
	return nil
}

func specialFieldExtract(data *model.ConsumerData, ptr *reflect.Value, metaDataFNs []*model.ProtocolField) {
	if data.Protocol == "Modbus/TCP" {
		setObjFiled(ptr, "ProtoID", "string", "0")
		objectStrValues := slice.Filter(metaDataFNs, func(index int, item *model.ProtocolField) bool {
			return item.N == "modbus.object_str_value"
		})
		if len(objectStrValues) >= 3 {
			setObjFiled(ptr, "SoftwareVersion", "string", objectStrValues[2].V)
		}
		if len(objectStrValues) >= 2 {
			setObjFiled(ptr, "Product", "string", objectStrValues[1].V)
		}
		if len(objectStrValues) >= 1 {
			setObjFiled(ptr, "Vendor", "string", objectStrValues[0].V)
		}

		registerCountFN := slice.Filter(metaDataFNs, func(index int, item *model.ProtocolField) bool {
			return item.N == "modbus.word_cnt" || item.N == "modbus.bit_cnt"
		})
		if len(registerCountFN) > 0 {
			setObjFiled(ptr, "RegisterCount", "uint32", registerCountFN[0].V)
		}
	} else if data.Protocol == "S7COMM" {
		for i := range metaDataFNs {
			if metaDataFNs[i].N == "s7comm.szl.xy11.0001.anz" && (i-1 > 0) && metaDataFNs[i-1].N == "s7comm.szl.xy11.0001.index" {
				indexValue := metaDataFNs[i-1].V
				parseInt, err := strconv.ParseInt(indexValue, 0, 64)
				if err == nil {
					if parseInt == 6 {
						setObjFiled(ptr, "HardwareVersion", "string", metaDataFNs[i].V)
					} else if parseInt == 7 {
						setObjFiled(ptr, "FirmwareVersion", "string", metaDataFNs[i].V)
					} else if parseInt == 129 {
						setObjFiled(ptr, "FirmwareExtend", "string", metaDataFNs[i].V)
					}
				} else {
					log.Println("s7comm.szl.xy11.0001.anz indexValue 转换失败：", indexValue, err)
				}
			}
		}
	}
}

func setObjFiled(ptr *reflect.Value, filedName string, filedType string, v string) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("setObjFiled error recover， 字段：", filedName, "，类型：", filedType, "，值：", v, r)
		}
	}()

	filed := ptr.FieldByName(filedName)
	if filed.IsValid() && filed.CanSet() {
		if err := strToFieldType(filedType, v, &filed); err != nil {
			logrus.Errorln("无法设置字段：", filedName, "，类型：", filedType, "，值：", v, "，错误：", err)
		}
	}
}

func strToFieldType(fieldType string, value string, field *reflect.Value) error {
	switch fieldType {
	case "int64":
		convertValue, err := convertor.ToInt(value)
		if err == nil {
			field.Set(reflect.ValueOf(&convertValue))
		} else {
			return errors.New("meta类型【int64】转换失败")
		}
	case "float32":
		convertValue, err := convertor.ToFloat(value)
		if err == nil {
			convertValue2 := float32(convertValue)
			field.Set(reflect.ValueOf(&convertValue2))
		} else {
			return errors.New("meta类型【float32】转换失败")
		}
	case "uint32":
		convertValue, err := convertor.ToInt(value)
		if err == nil {
			convertValue2 := uint32(convertValue)
			field.Set(reflect.ValueOf(&convertValue2))
		} else {
			return errors.New("meta类型【uint32】转换失败")
		}
	case "string":
		clone := convertor.DeepClone(value)
		field.Set(reflect.ValueOf(&clone))
	case "bool":
		if strings.HasPrefix(value, "0x") {
			pint, err := strconv.ParseInt(value, 0, 64)
			if err == nil {
				if pint != 0 {
					field.Set(reflect.ValueOf(true))
				}
			}
		} else {
			convertValue, err := convertor.ToBool(value)
			if err == nil {
				field.Set(reflect.ValueOf(&convertValue))
			} else {
				return errors.New("meta类型【bool】转换失败")
			}
		}
	default:
		return errors.New("meta类型没有找到对应类型")
	}
	return nil
}
