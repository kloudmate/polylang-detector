package detector

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kloudmate/polylang-detector/detector/inspectors"
	"github.com/kloudmate/polylang-detector/detector/process"
	runtimedetector "github.com/odigos-io/runtime-detector"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/apimachinery/pkg/types"
)

// EBPFDetector uses the Odigos pattern: watch pods, then inspect with eBPF
type EBPFDetector struct {
	Clientset        *kubernetes.Clientset
	LanguageDetector *inspectors.LanguageDetector
	Cache            *LanguageCache
	Logger           *zap.Logger
	processEvents    chan runtimedetector.ProcessEvent
	runtimeDetector  *runtimedetector.Detector
	processedPods    sync.Map
	queue            chan ContainerInfo
}

// NewEBPFDetector creates a new eBPF-based detector using Odigos pattern
func NewEBPFDetector(clientset *kubernetes.Clientset, cache *LanguageCache, logger *zap.Logger, queue chan ContainerInfo) (*EBPFDetector, error) {
	processEvents := make(chan runtimedetector.ProcessEvent, 1000)

	// Convert zap.Logger to slog.Logger
	slogLogger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create runtime detector - we'll use it to inspect processes
	opts := []runtimedetector.DetectorOption{
		runtimedetector.WithLogger(slogLogger),
	}

	runtimeDetector, err := runtimedetector.NewDetector(processEvents, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create runtime detector: %w", err)
	}

	return &EBPFDetector{
		Clientset:        clientset,
		LanguageDetector: inspectors.NewLanguageDetector(),
		Cache:            cache,
		Logger:           logger,
		processEvents:    processEvents,
		runtimeDetector:  runtimeDetector,
		queue:            queue,
	}, nil
}

// Start begins the Odigos-style detection: watch pods, inspect each one
func (ed *EBPFDetector) Start(ctx context.Context) error {
	ed.Logger.Info("Starting eBPF detector (Odigos pattern)")

	// Start the runtime detector
	go func() {
		if err := ed.runtimeDetector.Run(ctx); err != nil {
			ed.Logger.Error("Runtime detector stopped", zap.Error(err))
		}
	}()

	// Process eBPF events in background
	go ed.consumeProcessEvents(ctx)

	// Main loop: periodically scan all pods
	go ed.scanPodsLoop(ctx)

	return nil
}

// consumeProcessEvents processes events from eBPF (for metrics/logging)
func (ed *EBPFDetector) consumeProcessEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ed.processEvents:
			// We receive all process events here
			// We can use them for real-time detection if needed
			if event.EventType == runtimedetector.ProcessExecEvent && event.ExecDetails != nil {
				ed.Logger.Debug("Process exec detected",
					zap.Int("pid", event.PID),
					zap.String("exe", event.ExecDetails.ExePath),
				)
			}
		}
	}
}

// scanPodsLoop periodically scans all running pods (Odigos pattern)
func (ed *EBPFDetector) scanPodsLoop(ctx context.Context) {
	ed.Logger.Info("Starting pod scanning loop")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial scan
	ed.scanAllRunningPods(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ed.scanAllRunningPods(ctx)
		}
	}
}

// scanAllRunningPods scans all running pods and detects languages
func (ed *EBPFDetector) scanAllRunningPods(ctx context.Context) {
	pods, err := ed.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		ed.Logger.Error("Failed to list pods", zap.Error(err))
		return
	}

	ed.Logger.Info("Scanning pods", zap.Int("count", len(pods.Items)))

	for _, pod := range pods.Items {
		// Skip if already processed
		key := pod.Namespace + "/" + pod.Name
		if _, exists := ed.processedPods.Load(key); exists {
			continue
		}

		// Skip ignored namespaces (should be checked by caller)
		// For now, process all pods

		go ed.detectPodLanguages(ctx, &pod)
	}
}

// detectPodLanguages detects languages for all containers in a pod
func (ed *EBPFDetector) detectPodLanguages(ctx context.Context, pod *corev1.Pod) {
	key := pod.Namespace + "/" + pod.Name

	ed.Logger.Info("Detecting languages for pod",
		zap.String("namespace", pod.Namespace),
		zap.String("pod", pod.Name),
	)

	for _, container := range pod.Spec.Containers {
		// Check cache first
		containerEnvVars := make(map[string]string)
		for _, env := range container.Env {
			if env.Value != "" {
				containerEnvVars[env.Name] = env.Value
			}
		}

		if cachedInfo, found := ed.Cache.Get(container.Image, containerEnvVars); found {
			ed.Logger.Debug("Cache hit",
				zap.String("image", container.Image),
				zap.String("language", cachedInfo.Language),
			)

			// Update pod-specific info and send
			info := *cachedInfo
			info.PodName = pod.Name
			info.Namespace = pod.Namespace
			info.ContainerName = container.Name
			info.DetectedAt = time.Now()

			// Get deployment name
			depName, _ := getPodDeploymentName(ed.Clientset, pod.Namespace, pod.Name)
			info.DeploymentName = depName

			ownerRef := metav1.GetControllerOf(pod)
			if ownerRef != nil {
				info.Kind = ownerRef.Kind
			} else {
				info.Kind = "Pod"
			}

			if _, ok := OtelSupportedLanguages[info.Language]; ok {
				ed.queue <- info
			}
			continue
		}

		// Detect using proc inspection (fallback to traditional method)
		containerInfo := ed.detectContainerLanguage(ctx, pod, &container)
		if containerInfo != nil && containerInfo.Language != "Unknown" {
			ed.Logger.Info("Detected language",
				zap.String("namespace", pod.Namespace),
				zap.String("pod", pod.Name),
				zap.String("container", container.Name),
				zap.String("language", containerInfo.Language),
			)

			// Cache the result
			ed.Cache.Set(container.Image, containerEnvVars, *containerInfo)

			// Send to queue
			if _, ok := OtelSupportedLanguages[containerInfo.Language]; ok {
				ed.queue <- *containerInfo
			}
		}
	}

	// Mark as processed
	ed.processedPods.Store(key, true)
}

// detectContainerLanguage detects language for a specific container in a pod
func (ed *EBPFDetector) detectContainerLanguage(ctx context.Context, pod *corev1.Pod, container *corev1.Container) *ContainerInfo {
	info := &ContainerInfo{
		PodName:       pod.Name,
		Namespace:     pod.Namespace,
		ContainerName: container.Name,
		Image:         container.Image,
		EnvVars:       make(map[string]string),
		DetectedAt:    time.Now(),
	}

	// Extract environment variables
	for _, env := range container.Env {
		if env.Value != "" {
			info.EnvVars[env.Name] = env.Value
		}
	}

	// Get deployment/owner information
	depName, _ := getPodDeploymentName(ed.Clientset, pod.Namespace, pod.Name)
	info.DeploymentName = depName

	ownerRef := metav1.GetControllerOf(pod)
	if ownerRef != nil {
		info.Kind = ownerRef.Kind
	} else {
		info.Kind = "Pod"
	}

	// Find processes belonging to this specific container using Odigos pattern
	// Expected mount root: /kubepods/<pod-uid>/containers/<container-name>/
	pids := findProcessesInContainer(pod.UID, container.Name)

	if len(pids) == 0 {
		ed.Logger.Debug("No processes found for container",
			zap.String("pod", pod.Name),
			zap.String("container", container.Name),
		)
		info.Language = "Unknown"
		info.Confidence = "low"
		return info
	}

	// Detect language from the first process that gives us a result
	for _, pid := range pids {
		procCtx, err := process.GetProcessContext(pid)
		if err != nil {
			continue
		}

		result, err := ed.LanguageDetector.Detect(procCtx)
		if err != nil || result == nil || result.Language == inspectors.LanguageUnknown {
			continue
		}

		// Found a language!
		info.Language = string(result.Language)
		info.Framework = result.Framework
		info.Confidence = result.Confidence
		info.Evidence = []string{fmt.Sprintf("Detected via mount-based process discovery with %s confidence", result.Confidence)}
		return info
	}

	info.Language = "Unknown"
	info.Confidence = "low"
	return info
}

// findProcessesInContainer finds all PIDs for processes in a specific container
// Uses the Odigos pattern: check mount info for pod UID + container name
func findProcessesInContainer(podUID types.UID, containerName string) []int {
	// Expected mount root pattern: /kubepods/<pod-uid>/containers/<container-name>/
	expectedMountRoot := fmt.Sprintf("%s/containers/%s/", podUID, containerName)

	// Get all processes
	allPids, err := process.FindAllProcesses()
	if err != nil {
		return nil
	}

	var matchingPids []int
	procDir := process.GetProcDir()

	for _, pid := range allPids {
		// Check if this process belongs to the container by examining mountinfo
		mountinfoPath := fmt.Sprintf("%s/%d/mountinfo", procDir, pid)
		if isPodContainerProcess(mountinfoPath, expectedMountRoot) {
			matchingPids = append(matchingPids, pid)
		}
	}

	return matchingPids
}

// isPodContainerProcess checks if a process belongs to a specific container
// by examining its mount information (Odigos pattern)
func isPodContainerProcess(mountinfoPath string, expectedMountRoot string) bool {
	file, err := os.Open(mountinfoPath)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Check if any mount point contains the expected mount root
		// This indicates the process is in this container
		if strings.Contains(line, expectedMountRoot) {
			return true
		}
	}

	return false
}
