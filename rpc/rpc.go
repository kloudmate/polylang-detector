package rpc

import (
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/kloudmate/polylang-detector/detector"
)

type RPCHandler struct{}

// PushDetectionResults receives a batch of ContainerInfo structs from a client.
func (h *RPCHandler) PushDetectionResults(results []detector.ContainerInfo, reply *string) error {
	log.Info("Received a batch of detection results via RPC.", "size", len(results))
	for _, info := range results {
		log.Info("Received result", "container", info.ContainerName, "namespace", info.Namespace, "language", info.Language)
	}
	*reply = fmt.Sprintf("Successfully processed %d results.", len(results))
	return nil
}
