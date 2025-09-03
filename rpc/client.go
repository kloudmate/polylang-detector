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
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case result := <-pd.Queue:
			pd.BatchMutex.Lock()
			batch = append(batch, result)
			pd.BatchMutex.Unlock()
			if len(batch) >= pd.QueueSize {
				pd.Logger.Sugar().Infof("sending apm data as max queue size reached")
				pd.SendBatch(batch)
				batch = nil
			} else {
				pd.Logger.Sugar().Infof("skipping sending apm data to updater due to less queue size")
			}
		case <-ctx.Done():
			// Keep the client running for a while to allow all batch of deployments to be sent
			pd.Logger.Sugar().Infof("sending all pending data to updater before exiting")
			pd.BatchMutex.Lock()
			pd.SendBatch(batch)
			pd.BatchMutex.Unlock()
			pd.RpcClient.Close()
			return
		case <-ticker.C:
			pd.BatchMutex.Lock()
			if len(batch) > 0 {
				pd.Logger.Sugar().Infof("sending apm data as waiting duration expired")
				pd.SendBatch(batch)
				batch = nil
			} else {
				pd.Logger.Sugar().Infof("no apm data available to send to the updater")
			}
			pd.BatchMutex.Unlock()
		}
	}

}
