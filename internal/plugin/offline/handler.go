package offline

import (
	"context"
	"dissect/internal"
	"dissect/internal/model"
	"net"
	"net/rpc"
	"os"
	"path"

	"github.com/maxtors/surisoc"
	"github.com/sirupsen/logrus"
)

type Handler struct {
	ctx context.Context
	svc *internal.ServiceContext
}
type PcapHandler struct {
	sock *surisoc.SuricataSocket
}

const SOCKET_PATH_NAME = "/opt/parser"
const OFFLINE_PATH = "/opt/upload_file"
const OFFLINE_SOCKET = "offline.sock"
const OFFLINE_ENGINE_SOCKET = "offline_engine.sock"

func NewHandler(ctx context.Context, svc *internal.ServiceContext) *Handler {
	h := &Handler{
		ctx: ctx,
		svc: svc,
	}
	go h.listener()
	return h
}

func (h *Handler) listener() {

	session, err := surisoc.NewSuricataSocket(path.Join(SOCKET_PATH_NAME, OFFLINE_ENGINE_SOCKET))
	if err != nil {
		logrus.Errorln("CreateSocket error:", err)
		return
	}
	defer session.Close()

	if err = rpc.Register(&PcapHandler{
		sock: session,
	}); err != nil {
		logrus.Errorln("pcapHandler error:", err)
		return
	}

	rpcSocketPath := path.Join(SOCKET_PATH_NAME, OFFLINE_SOCKET)
	os.Remove(rpcSocketPath)

	l, err := net.Listen("unix", rpcSocketPath)
	if err != nil {
		logrus.Errorln("Listen error:", err)
	}

	logrus.Infof("offline engine rpc server listening %s... \n", rpcSocketPath)

	for {
		conn, err := l.Accept()
		if err != nil {
			logrus.Errorln("Accept error:", err)
		}
		go rpc.ServeConn(conn)
	}
}

func (p *PcapHandler) ProcessPcap(filename string, reply *string) error {

	filePath := path.Join(OFFLINE_PATH, filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		*reply = "File does not exist"
		return err
	}

	logrus.Infof("start ProcessPcap: %s", filePath)
	response, err := p.sock.Send("pcap-file", filePath, "/tmp")
	if err != nil {
		logrus.Errorln("Error running version:", err)
		return err
	}
	logrus.Infof("ProcessPcap response: %s", response)

	// Convert the response.Message to a string
	res, err := response.ToString()
	if err != nil {
		logrus.Errorln("Error converting response:", err)
		return err
	}

	*reply = string(res)
	return nil
}

func (h *Handler) Handle(data *model.ConsumerData) {}
