package main

import (
	"log"
	"net"
	"net/rpc"
	"os"

	langRpc "github.com/kloudmate/polylang-detector/rpc"
)

// main function to start the RPC server.
func main() {
	// Register the RPC handler
	rpc.Register(new(langRpc.RPCHandler))

	// Listen for incoming connections on a specific port
	addr := os.Getenv("KM_CFG_UPDATER_RPC_ADDR")
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Error starting RPC server: %v", err)
	}
	defer listener.Close()

	log.Printf("RPC server listening on port %s\n", addr)

	// Accept connections and serve them concurrently
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		go rpc.ServeConn(conn)
	}
}
