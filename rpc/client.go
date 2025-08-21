package rpc

import (
	"context"
	"log"
	"net/rpc"
	"os"
	"time"

	"github.com/kloudmate/polylang-detector/detector"
	"github.com/kloudmate/polylang-detector/workload"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// StartRPCClient is the startup function for the RPC client.
func StartRPCClient(clientset *kubernetes.Clientset, config *rest.Config, ctx context.Context) {

	execDetector := &detector.ExecDetector{
		Clientset: clientset,
		Config:    config,
		Queue:     make(chan detector.ContainerInfo, 100), // Queue with a capacity of 100
		QueueSize: 5,                                      // Batch size
	}

	// Connect to RPC server
	client, err := rpc.Dial("tcp", os.Getenv("KM_CFG_UPDATER_RPC_ADDR"))
	if err != nil {
		if err == rpc.ErrShutdown {
			log.Printf("RPC server is shutdown : Attempting to reconnect")
			execDetector.ConnectWithRetry()
		}
		log.Fatalf("Error connecting to RPC server: %v", err)
	}
	execDetector.RpcClient = client
	defer client.Close()

	go func() {
		var batch []detector.ContainerInfo
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case result := <-execDetector.Queue:
				execDetector.BatchMutex.Lock()
				batch = append(batch, result)
				execDetector.BatchMutex.Unlock()
				if len(batch) >= execDetector.QueueSize {
					execDetector.SendBatch(batch)
					batch = nil
				}
			case <-ctx.Done():
				return
			case <-ticker.C:
				execDetector.BatchMutex.Lock()
				if len(batch) > 0 {
					execDetector.SendBatch(batch)
					batch = nil
				}
				execDetector.BatchMutex.Unlock()
			}
		}
	}()

	// Example usage: Simulate detecting multiple pods
	workload.AnalyzeWorkloads(ctx, execDetector)

	// Keep the client running for a while to allow all batch of deployments to be sent
	time.Sleep(30 * time.Second)
}
