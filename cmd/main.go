package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/kloudmate/polylang-detector/detector"
	"github.com/kloudmate/polylang-detector/pkg/logger"
	"github.com/kloudmate/polylang-detector/rpc"
	"github.com/kloudmate/polylang-detector/workload"
)

var (
	version = "0.1.0"
	commit  = "none"
)

func main() {
	// Initialize domain logger
	domainLogger, err := logger.NewProductionLogger()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer domainLogger.Sync()

	domainLogger.ApplicationStarting(version, commit)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup

	k8sClient, k8sConfig, err := workload.GetClientSet()
	if err != nil {
		domainLogger.K8sClientInitFailed(err)
		os.Exit(1)
	}
	domainLogger.K8sClientInitialized("in-cluster")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	langDetector := detector.NewPolylangDetector(k8sConfig, k8sClient, domainLogger)

	// Start RPC connection in background - don't block startup
	go func() {
		if err := langDetector.DialWithRetry(ctx, time.Second*10); err != nil {
			domainLogger.Error("RPC connection permanently failed")
		}
	}()

	// Perform initial scan of existing pods for better accuracy
	go workload.ScanPods(ctx, k8sClient, langDetector)

	go workload.AnalyzeWorkloads(ctx, langDetector, &wg)
	go rpc.SendDataToUpdater(langDetector, k8sClient, k8sConfig, ctx, &wg)

	domainLogger.ApplicationReady()

	sig := <-sigChan
	domainLogger.ApplicationShuttingDown(sig.String())
	cancel()
	wg.Wait()
	domainLogger.ApplicationShutdownComplete()
}
