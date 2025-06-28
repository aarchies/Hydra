package rpc

// import (
// 	"context"
// 	"errors"
// 	"flag"
// 	"fmt"
// 	"log"
// 	"net"
// 	"net/rpc"
// 	"os"
// 	"path/filepath"
// 	"dissect/internal/model"
// 	"dissect/internal/shard"
// )

// type Server struct{}

// // GetParserData is an RPC method that processes data
// func (s *Server) GetParserData(data []byte, reply *model.PacketResult) error {
// 	if len(data) == 0 {
// 		return errors.New("data cannot be empty")
// 	}
// 	shard.ParserData(data, reply)
// 	return nil
// }

// func (s *Server) GetParserBytes(data []byte, reply *[]byte) error {
// 	if len(data) == 0 {
// 		return errors.New("data cannot be empty")
// 	}
// 	shard.ParserBytes(data, reply)
// 	return nil
// }

// func ParserServer(ctx context.Context) {
// 	defer func() {
// 		if err := recover(); err != nil {
// 			fmt.Println("Recovered in f", err)
// 		}

// 		log.Println("Received shutdown signal. Shutting down...")
// 	}()

// 	// Create socket directory if it doesn't exist
// 	if err := os.MkdirAll(SOCKET_PATH_NAME, 0777); err != nil {
// 		log.Fatal("Failed to create directory:", err)
// 	}

// 	// Parse command-line arguments
// 	var POption string
// 	flag.StringVar(&POption, "P", "", "socket file name")
// 	flag.Parse()

// 	// Validate command-line arguments
// 	if POption == "" {
// 		log.Fatal("P option cannot be empty. Please specify the socket file name.")
// 	}
// 	if !isChildPathInParentPath(SOCKET_PATH_NAME, POption) {
// 		log.Fatalf("Socket file path '%s' is not under the directory '%s'.", POption, SOCKET_PATH_NAME)
// 	}

// 	// Register RPC service
// 	if err := rpc.Register(new(Server)); err != nil {
// 		log.Fatal("Error registering ItemService:", err)
// 	}

// 	// Remove existing socket file if any
// 	defer RemoveFile(POption)

// 	// Start Unix domain socket listener
// 	listener, err := net.Listen("unix", POption)
// 	if err != nil {
// 		log.Fatal("Listener error:", err)
// 	}
// 	defer listener.Close()

// 	log.Println("Server started on Unix socket", POption)

// 	// Main loop to accept incoming connections
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			log.Println("Stopping server...")
// 			return // Exit the main function to gracefully shut down
// 		default:
// 			conn, err := listener.Accept()
// 			if err != nil {
// 				log.Println("Connection error:", err)
// 				continue
// 			}
// 			go rpc.ServeConn(conn)
// 		}
// 	}
// }

// // isChildPathInParentPath checks if childPath is within parentPath
// func isChildPathInParentPath(parentPath string, childPath string) bool {
// 	if filepath.HasPrefix(childPath, parentPath) {
// 		return true
// 	}
// 	return false
// }

// // RemoveFile removes the specified socket file
// func RemoveFile(socketPath string) {
// 	if err := os.RemoveAll(socketPath); err != nil {
// 		log.Fatal("Failed to remove existing socket file:", err)
// 	}
// }
