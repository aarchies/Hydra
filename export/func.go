package export

import "C"

import (
	"dissect/internal/core/runtime"
	"dissect/internal/model/pb"
	"encoding/hex"

	"google.golang.org/protobuf/proto"
)

//export Entrance
func Entrance(hex_data string, line_no string, task_id string, direction int, isAlert int, sid int, classType string, eMsg string) {

	binaryData, err := hex.DecodeString(hex_data)
	if err != nil {
		return
	}

	bytes, err := proto.Marshal(&pb.ProducerData{
		DataByte:  binaryData,
		LineNo:    line_no,
		TaskId:    task_id,
		Direction: uint32(direction),
		IsAlert:   isAlert != 0,
		SId:       int64(sid),
		ClassType: classType,
		EventMSG:  eMsg,
	})
	if err != nil {
		return
	}
	runtime.WeightPut(bytes)
}

func EntranceByte(hex_data []byte, line_no string, task_id string, direction int, isAlert int, sid int, classType string, eMsg string) {
	bytes, err := proto.Marshal(&pb.ProducerData{
		DataByte:  append([]byte(nil), hex_data...), // 深拷贝
		LineNo:    line_no,
		TaskId:    task_id,
		Direction: uint32(direction),
		IsAlert:   isAlert != 0,
		SId:       int64(sid),
		ClassType: classType,
		EventMSG:  eMsg,
	})
	if err != nil {
		return
	}
	runtime.WeightPut(bytes)
}
