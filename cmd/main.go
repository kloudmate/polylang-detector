package main

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/kloudmate/polylang-detector/rpc"
	"github.com/kloudmate/polylang-detector/workload"
)

var (
	version = "0.1.0"
	commit  = "none"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log.Info("kloudmate polylang detector",
		"version", version,
		"commitSHA", commit,
	)
	clientset, config, err := workload.GetClientSet()
	if err != nil {
		log.Errorf("Failed to create Kubernetes client: %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	wg.Add(1)
	// workload.StartWorker(ctx, &wg, clientset, config)
	go rpc.StartRPCClient(clientset, config, ctx)
	// workload.AnalyzeWorkloads(ctx, detector.NewExecDetector(config, clientset))
	sig := <-sigChan
	wg.Done()
	log.Printf("Received signal: %v. Initiating graceful shutdown...", sig)
	ctx.Done()
	cancel()
	log.Info("Polylang Detector shutdown complete.")
}
