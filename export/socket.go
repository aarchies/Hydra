package export

import (
	"bufio"
	"bytes"
	"io"
	"net"

	"github.com/sirupsen/logrus"
)

const (
	DATA_LENGTH      = 8   // Data
	TID_LENGTH       = 51  // Tid
	DIRECTION_LENGTH = 1   // Direction
	ALERT_LENGTH     = 1   // IsAlert
	SID_LENGTH       = 4   // Sid
	CLASS_LENGTH     = 4   // ClassType
	MSG_LENGTH       = 128 // EMsg
)

func StartSocketServer() {
	listener, err := net.Listen("tcp", ":50051")
	if err != nil {
		logrus.Fatalf("启动服务器失败: %v", err)
	}
	defer listener.Close()

	logrus.Infof("Server listening at %v", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.Errorf("接受连接失败: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	reader := bufio.NewReader(conn)
	var count = 0

	for {
		data, err := reader.ReadSlice('\x1e')
		if err != nil {
			if err != io.EOF {
				logrus.Errorf("读取数据失败: %v", err)
			}
			break
		}

		data = bytes.TrimRight(data[0:len(data)-1], "\x00")
		count++

		if count > 1 && len(data) > 4 {
			data = data[3:]
		}

		if len(data) == 0 {
			continue
		}

		Entrance(string(data), "1234567890", "1234567890", 1, 0, 10001172, "信息侦察", "Modbus检测")

		logrus.Infof("received count %d msg %d %v", count, len(data), data)
	}
}
