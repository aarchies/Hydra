package resolver

/*
#cgo pkg-config: glib-2.0
#cgo windows CFLAGS: -I../../../include
#cgo windows LDFLAGS: -L../../../include/lib/win -ltshark -lm
#cgo unix CFLAGS: -I/usr/local/include/
#cgo unix LDFLAGS: -L/usr/local/lib -ltshark -lm
#include <tshark.h>
*/
import "C"
import (
	"dissect/internal/model"
	"dissect/internal/model/pb"
	"dissect/utils"
	"strings"
	"time"
	"unsafe"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	C.process_main_init()
}

func Execute(buffer *model.ProducerData) *model.ConsumerData {

	packets := C.dissect_single_packet((*C.uint8_t)(unsafe.Pointer(&buffer.DataByte[0])), C.size_t(len(buffer.DataByte))) // 单线程
	result := ConvertPacket(&packets)
	C.free_packet_result(&packets) // 释放内存

	return ConvertResult(result, buffer)
}

func ExecuteProto(buffer *pb.ProducerData) *pb.ConsumerData {

	packets := C.dissect_single_packet((*C.uint8_t)(unsafe.Pointer(&buffer.DataByte[0])), C.size_t(len(buffer.DataByte))) // 单线程
	result := ConvertProtoPacket(&packets)
	C.free_packet_result(&packets) // 释放内存

	return ConvertProtoResult(result, buffer)
}

func ConvertProtoPacket(packets *C.packet_result) *pb.PacketResult {
	result := &pb.PacketResult{
		Pi: &pb.EdtData{
			P:    C.GoString(&packets.packet_info.proto[0]),
			S:    C.GoString(&packets.packet_info.sip[0]),
			D:    C.GoString(&packets.packet_info.dip[0]),
			Desc: C.GoString(&packets.packet_info.desc[0]),
		},
		P: make([]*pb.ProtocolData, int(packets.protocol_info.len)),
		S: strings.HasPrefix(C.GoString(&packets.packet_info.proto[0]), "0x") && C.GoString(&packets.packet_info.proto[0]) == "",
	}

	for i := 0; i < int(packets.protocol_info.len); i++ {
		cProtocolData := (*C.protocol_data)(unsafe.Pointer(uintptr(unsafe.Pointer(packets.protocol_info.data)) + uintptr(i)*unsafe.Sizeof(C.protocol_data{})))
		result.P[i] = &pb.ProtocolData{
			N:  C.GoString(cProtocolData.name),
			Sn: C.GoString(cProtocolData.showname),
			Sz: C.GoString(cProtocolData.size),
			Ps: C.GoString(cProtocolData.pos),
			F:  make([]*pb.ProtocolField, int(cProtocolData.fields.len)),
		}

		for j := 0; j < int(cProtocolData.fields.len); j++ {
			cField := (*C.protocol_field)(unsafe.Pointer(uintptr(unsafe.Pointer(cProtocolData.fields.data)) + uintptr(j)*unsafe.Sizeof(C.protocol_field{})))
			result.P[i].F[j] = &pb.ProtocolField{
				N:  C.GoString(cField.name),
				Sn: C.GoString(cField.showname),
				Sz: C.GoString(cField.size),
				Ps: C.GoString(cField.pos),
				Sh: C.GoString(cField.show),
				V:  C.GoString(cField.value),
			}
		}
	}

	return result
}

func ConvertPacket(packets *C.packet_result) *model.PacketResult {
	result := &model.PacketResult{
		PI: model.EdtData{
			P:    C.GoString(&packets.packet_info.proto[0]),
			S:    C.GoString(&packets.packet_info.sip[0]),
			D:    C.GoString(&packets.packet_info.dip[0]),
			Desc: C.GoString(&packets.packet_info.desc[0]),
		},
		P: make([]model.ProtocolData, int(packets.protocol_info.len)),
		S: strings.HasPrefix(C.GoString(&packets.packet_info.proto[0]), "0x") && C.GoString(&packets.packet_info.proto[0]) == "",
	}

	for i := 0; i < int(packets.protocol_info.len); i++ {
		cProtocolData := (*C.protocol_data)(unsafe.Pointer(uintptr(unsafe.Pointer(packets.protocol_info.data)) + uintptr(i)*unsafe.Sizeof(C.protocol_data{})))
		result.P[i] = model.ProtocolData{
			N:  C.GoString(cProtocolData.name),
			SN: C.GoString(cProtocolData.showname),
			Sz: C.GoString(cProtocolData.size),
			Ps: C.GoString(cProtocolData.pos),
			F:  make([]model.ProtocolField, int(cProtocolData.fields.len)),
		}

		for j := 0; j < int(cProtocolData.fields.len); j++ {
			cField := (*C.protocol_field)(unsafe.Pointer(uintptr(unsafe.Pointer(cProtocolData.fields.data)) + uintptr(j)*unsafe.Sizeof(C.protocol_field{})))
			result.P[i].F[j] = model.ProtocolField{
				N:  C.GoString(cField.name),
				SN: C.GoString(cField.showname),
				Sz: C.GoString(cField.size),
				Ps: C.GoString(cField.pos),
				Sh: C.GoString(cField.show),
				V:  C.GoString(cField.value),
			}
		}
	}

	return result
}

func ConvertProtoResult(result *pb.PacketResult, buffer *pb.ProducerData) *pb.ConsumerData {

	data := &pb.ConsumerData{
		DataByte:   buffer.DataByte,
		LineNo:     buffer.LineNo,
		CreateTime: timestamppb.Now(),
		Meta:       make([]*pb.ProtocolData, 0, len(result.P)),
	}

	for _, proto := range result.P {
		switch proto.N {
		case "eth":

			for _, field := range proto.F {
				switch field.N {
				case "eth.type":
					data.EThType = field.V
				case "eth.src":
					data.SrcMac = field.V
				case "eth.dst":
					data.DstMac = field.V
				}
			}

		case "ip":
			for _, field := range proto.F {
				switch field.N {
				case "ip.src":
					data.SrcIP = field.V
				case "ip.dst":
					data.DstIP = field.V
				case "ip.version":
					data.IPVersion = field.V
				}
			}
		case "tcp":
			for _, field := range proto.F {
				switch field.N {
				case "tcp.srcport":
					data.SrcPort = uint32(utils.StrChangeUnit16(&field.V))
				case "tcp.dstport":
					data.DstPort = uint32(utils.StrChangeUnit16(&field.V))
				}
			}
			data.TransportLayer = proto.N
		case "udp":
			for _, field := range proto.F {
				switch field.N {
				case "udp.srcport":
					data.SrcPort = uint32(utils.StrChangeUnit16(&field.V))
				case "udp.dstport":
					data.DstPort = uint32(utils.StrChangeUnit16(&field.V))
				}
			}
			data.TransportLayer = proto.N
		default:
			data.Meta = append(data.Meta, proto) // 如果没有处理，保留此元素
		}
	}

	data.Protocol = result.Pi.P                         // 协议类型
	data.Action = result.Pi.Desc                        // 行为
	data.TaskId = strings.TrimRight(buffer.TaskId, "0") // 任务ID
	data.SId = buffer.SId                               // 事件id
	data.IsAttack = buffer.IsAlert                      // 是否被攻击
	data.Direction = buffer.Direction                   // 0:其他，1:客户端向服务端 2:服务端向客户端
	data.EventType = buffer.ClassType                   // 事件类型
	data.EventDesc = buffer.EventMSG                    // 事件描述
	data.NegTimestamp = -time.Now().UnixNano()          // 时间戳
	result = nil
	buffer = nil

	return data
}

func ConvertResult(result *model.PacketResult, buffer *model.ProducerData) *model.ConsumerData {

	data := &model.ConsumerData{
		DataByte:   buffer.DataByte,
		LineNo:     buffer.LineNo,
		CreateTime: time.Now(),
		Meta:       make([]model.ProtocolData, 0, len(result.P)),
	}

	for _, proto := range result.P {
		switch proto.N {
		case "eth":
			data.ETH(proto.F)
		case "ip":
			data.IP(proto.F)
		case "tcp":
			data.TCP(proto.F)
			data.TransportLayer = proto.N
		case "udp":
			data.UDP(proto.F)
			data.TransportLayer = proto.N
		default:
			data.Meta = append(data.Meta, proto) // 如果没有处理，保留此元素
		}
	}

	data.Protocol = result.PI.P                         // 协议类型
	data.Action = result.PI.Desc                        // 行为
	data.TaskID = strings.TrimRight(buffer.TaskID, "0") // 任务ID
	data.SID = buffer.SId                               // 事件id
	data.IsAttack = buffer.IsAlert                      // 是否被攻击
	data.Direction = buffer.Direction                   // 0:其他，1:客户端向服务端 2:服务端向客户端
	data.EventType = buffer.ClassType                   // 事件类型
	data.EventDesc = buffer.EventMSG                    // 事件描述
	data.NegTimestamp = -time.Now().UnixNano()          // 时间戳
	result = nil
	buffer = nil

	//logrus.Debugln("packet result ->", data)

	return data
}

func Exit() {
	C.process_main_after()
}
