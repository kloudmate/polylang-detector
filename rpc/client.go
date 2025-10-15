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

	// Send all cached workloads on startup (after a short delay to allow initial detection)
	time.Sleep(10 * time.Second)
	sendAllCachedWorkloads(pd)

	// Create a ticker to periodically send all cached workloads (every 5 minutes)
	cacheSyncTicker := time.NewTicker(15 * time.Second)
	defer cacheSyncTicker.Stop()

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
		case <-cacheSyncTicker.C:
			// Periodically send all cached workloads to keep config updater in sync
			sendAllCachedWorkloads(pd)
		}
	}

}

// sendAllCachedWorkloads sends all active workloads from cache to the config updater
func sendAllCachedWorkloads(pd *detector.PolylangDetector) {
	allContainers := pd.Cache.GetAllActiveContainers()
	if len(allContainers) == 0 {
		pd.Logger.Sugar().Info("No cached workloads to send")
		return
	}

	pd.Logger.Sugar().Infow("Sending all cached workloads to config updater",
		"count", len(allContainers),
	)

	// Send in batches to avoid overwhelming the RPC server
	batchSize := 10
	for i := 0; i < len(allContainers); i += batchSize {
		end := i + batchSize
		if end > len(allContainers) {
			end = len(allContainers)
		}

		batch := allContainers[i:end]
		pd.DomainLogger.(interface {
			RPCBatchSending(count int, reason string)
		}).RPCBatchSending(len(batch), "cached_workloads_sync")
		pd.SendBatch(batch)
	}

	pd.Logger.Sugar().Info("Completed sending cached workloads")
}
