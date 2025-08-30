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
	"github.com/kloudmate/polylang-detector/rpc"
	"github.com/kloudmate/polylang-detector/workload"
)

var (
	version = "0.1.0"
	commit  = "none"
)

func main() {
	log.Info("kloudmate polylang detector",
		"version", version,
		"commitSHA", commit,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	k8sClient, k8sConfig, err := workload.GetClientSet()
	if err != nil {
		log.Errorf("Failed to create Kubernetes client: %v\n", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	langDetector := detector.NewPolylangDetector(k8sConfig, k8sClient)
	if err = langDetector.DialWithRetry(ctx, time.Second*10); err != nil {
		log.Fatalf("cannot establish connection with the config updater :%v", err)
	}

	go workload.AnalyzeWorkloads(ctx, langDetector, &wg)
	go rpc.SendDataToUpdater(langDetector, k8sClient, k8sConfig, ctx, &wg)

	sig := <-sigChan
	log.Printf("Received signal: %v. Initiating graceful shutdown...\n", sig)
	cancel()
	wg.Wait()
	log.Printf("Graceful shutdown complete. Exiting main.")
}
