package workload

import (
	"context"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// StartWorker contains the ever-running logic of the application.
// It uses a context to know when to shut down.
func StartWorker(ctx context.Context, wg *sync.WaitGroup, clientset *kubernetes.Clientset, config *rest.Config) {
	defer wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	log.Info(nil, "Starting new scan at", time.Now().Format(time.RFC3339))
	AnalyzeWorkloads(ctx, nil)
	log.Infof("Scan complete. Waiting for 1 minute \n")
	// The loop will continue until the context is canceled.
	for {
		select {
		case <-ctx.Done():
			// The context was canceled, time to shut down gracefully.
			log.Info("Worker received shutdown signal. Exiting work loop.")
			// TODO: Perform flushing logs or closing connections.
			return

		case <-ticker.C:
			log.Info(nil, "Starting new scan at", time.Now().Format(time.RFC3339))
			AnalyzeWorkloads(ctx, nil)
			log.Infof("Scan complete. Waiting for 1 minute \n")
		}
	}
}
