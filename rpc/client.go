package rpc

import (
	"context"
	"sync"
	"time"

	"github.com/kloudmate/polylang-detector/detector"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// SendDataToUpdater is the startup function for the RPC client.
func SendDataToUpdater(pd *detector.PolylangDetector, clientset *kubernetes.Clientset, config *rest.Config, ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	var batch []detector.ContainerInfo
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case result := <-pd.Queue:
			pd.BatchMutex.Lock()
			batch = append(batch, result)
			currentSize := len(batch)
			pd.BatchMutex.Unlock()

			if currentSize >= pd.QueueSize {
				pd.DomainLogger.(interface {
					RPCBatchSending(count int, reason string)
				}).RPCBatchSending(currentSize, "queue_size_threshold_reached")
				pd.SendBatch(batch)
				batch = nil
			} else {
				pd.DomainLogger.(interface {
					RPCBatchQueued(batchSize, queueSize int)
				}).RPCBatchQueued(currentSize, pd.QueueSize)
			}
		case <-ctx.Done():
			// Keep the client running for a while to allow all batch of deployments to be sent
			pd.BatchMutex.Lock()
			if len(batch) > 0 {
				pd.DomainLogger.(interface {
					RPCBatchSending(count int, reason string)
				}).RPCBatchSending(len(batch), "application_shutdown")
				pd.SendBatch(batch)
			}
			pd.BatchMutex.Unlock()
			if pd.RpcClient != nil {
				pd.RpcClient.Close()
			}
			return
		case <-ticker.C:
			pd.BatchMutex.Lock()
			if len(batch) > 0 {
				pd.DomainLogger.(interface {
					RPCBatchSending(count int, reason string)
				}).RPCBatchSending(len(batch), "periodic_flush_interval")
				pd.SendBatch(batch)
				batch = nil
			}
			pd.BatchMutex.Unlock()
		}
	}

}
