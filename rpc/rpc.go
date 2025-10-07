package rpc

import (
	"fmt"
	"log"

	"github.com/kloudmate/polylang-detector/detector"
)

type RPCHandler struct{}

// PushDetectionResults receives a batch of ContainerInfo structs from a client.
func (h *RPCHandler) PushDetectionResults(results []detector.ContainerInfo, reply *string) error {
	log.Println("Received a batch of detection results via RPC.", "size", len(results))
	for _, info := range results {
		log.Println("Received result", "namespace", info.Namespace, "kind", info.Kind, "container", info.ContainerName, "language", info.Language)
	}
	*reply = fmt.Sprintf("Successfully processed %d results.", len(results))
	return nil
}
