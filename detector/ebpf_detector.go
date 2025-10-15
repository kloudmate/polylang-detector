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
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// EBPFDetector uses the pattern: watch pods, then inspect with eBPF
type EBPFDetector struct {
	Clientset        *kubernetes.Clientset
	LanguageDetector *inspectors.LanguageDetector
	Cache            *LanguageCache
	Logger           *zap.Logger
	processEvents    chan runtimedetector.ProcessEvent
	runtimeDetector  *runtimedetector.Detector
	processedPods    sync.Map
	queue            chan ContainerInfo
	informerFactory  informers.SharedInformerFactory
	stopCh           chan struct{}
}

// NewEBPFDetector creates a new eBPF-based detector
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

	// Create informer factory for watching Kubernetes resources
	informerFactory := informers.NewSharedInformerFactory(clientset, 30*time.Second)

	return &EBPFDetector{
		Clientset:        clientset,
		LanguageDetector: inspectors.NewLanguageDetector(),
		Cache:            cache,
		Logger:           logger,
		processEvents:    processEvents,
		runtimeDetector:  runtimeDetector,
		queue:            queue,
		informerFactory:  informerFactory,
		stopCh:           make(chan struct{}),
	}, nil
}

// Start begins the detection: watch pods, inspect each one
func (ed *EBPFDetector) Start(ctx context.Context) error {
	ed.Logger.Info("Starting eBPF detector")

	// Setup informers for lifecycle management
	ed.setupInformers()

	// Start informers
	ed.informerFactory.Start(ed.stopCh)

	// Wait for cache sync
	ed.Logger.Info("Waiting for informer caches to sync")
	if !cache.WaitForCacheSync(ed.stopCh,
		ed.informerFactory.Core().V1().Pods().Informer().HasSynced,
		ed.informerFactory.Apps().V1().Deployments().Informer().HasSynced,
		ed.informerFactory.Apps().V1().DaemonSets().Informer().HasSynced,
		ed.informerFactory.Apps().V1().ReplicaSets().Informer().HasSynced,
	) {
		return fmt.Errorf("failed to sync informer caches")
	}
	ed.Logger.Info("Informer caches synced successfully")

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

	// Start reconciliation loop to sync cache with cluster state
	go ed.reconciliationLoop(ctx)

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		close(ed.stopCh)
	}()

	return nil
}

// consumeProcessEvents processes events from eBPF ( runtime detector provides process discovery)
func (ed *EBPFDetector) consumeProcessEvents(ctx context.Context) {
	ed.Logger.Info("Starting to consume runtime detector process events")

	// processMap tracks PIDs to their detected languages to avoid duplicate detections
	processMap := make(map[int]string)

	for {
		select {
		case <-ctx.Done():
			return
		case event := <-ed.processEvents:
			// runtime detector gives us process exec events
			// We use these to know when new processes start, then detect their language
			if event.EventType == runtimedetector.ProcessExecEvent && event.ExecDetails != nil {
				// Skip if we've already processed this PID
				if _, exists := processMap[event.PID]; exists {
					continue
				}

				// Log the process we found
				ed.Logger.Info("detected new process",
					zap.Int("pid", event.PID),
					zap.String("exe", event.ExecDetails.ExePath),
					zap.String("cmdline_preview", truncateString(event.ExecDetails.CmdLine, 100)),
				)

				// Now detect the language using our language detector
				procCtx := &process.ProcessContext{
					PID:        event.PID,
					Executable: event.ExecDetails.ExePath,
					Cmdline:    event.ExecDetails.CmdLine,
					Environ:    event.ExecDetails.Environments,
				}

				result, err := ed.LanguageDetector.Detect(procCtx)
				if err == nil && result != nil && result.Language != inspectors.LanguageUnknown {
					processMap[event.PID] = string(result.Language)

					ed.Logger.Info("Detected language from process event",
						zap.Int("pid", event.PID),
						zap.String("language", string(result.Language)),
						zap.String("framework", result.Framework),
						zap.String("confidence", result.Confidence),
					)

					// TODO: Map this PID back to a pod/container and update the cache
					// This requires maintaining a PID->Pod mapping
				}
			}
		}
	}
}

// scanPodsLoop periodically scans all running pods
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

			// Get workload name and kind (uses Deployment when available)
			workloadName, workloadKind := getWorkloadInfo(ed.Clientset, pod)
			info.DeploymentName = workloadName
			info.Kind = workloadKind

			// Update workload cache with correct workload info
			ed.Cache.UpdateWorkloadContainer(
				info.Namespace,
				workloadName,
				workloadKind,
				info,
			)

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

			// Cache the result (image-based cache)
			ed.Cache.Set(container.Image, containerEnvVars, *containerInfo)

			// Update workload cache
			ed.Cache.UpdateWorkloadContainer(
				containerInfo.Namespace,
				containerInfo.DeploymentName,
				containerInfo.Kind,
				*containerInfo,
			)

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

	// Get workload name and kind (uses Deployment when available)
	workloadName, workloadKind := getWorkloadInfo(ed.Clientset, pod)
	info.DeploymentName = workloadName
	info.Kind = workloadKind

	// Find processes belonging to this specific container
	// Expected mount root: /kubepods/<pod-uid>/containers/<container-name>/
	pids := findProcessesInContainer(pod.UID, container.Name)

	if len(pids) == 0 {
		ed.Logger.Info("No processes found for container",
			zap.String("namespace", pod.Namespace),
			zap.String("pod", pod.Name),
			zap.String("container", container.Name),
			zap.String("pod_uid", string(pod.UID)),
			zap.String("image", container.Image),
		)
		info.Language = "Unknown"
		info.Confidence = "low"
		return info
	}

	// Detect language from the first process that gives us a result
	ed.Logger.Debug("Found processes for container",
		zap.String("namespace", pod.Namespace),
		zap.String("pod", pod.Name),
		zap.String("container", container.Name),
		zap.Int("process_count", len(pids)),
		zap.Ints("pids", pids),
	)

	for _, pid := range pids {
		procCtx, err := process.GetProcessContext(pid)
		if err != nil {
			ed.Logger.Info("Failed to get process context",
				zap.String("namespace", pod.Namespace),
				zap.String("pod", pod.Name),
				zap.String("container", container.Name),
				zap.Int("pid", pid),
				zap.Error(err),
			)
			continue
		}

		ed.Logger.Info("Got process context, attempting detection",
			zap.String("namespace", pod.Namespace),
			zap.String("pod", pod.Name),
			zap.String("container", container.Name),
			zap.Int("pid", pid),
			zap.String("executable", procCtx.Executable),
			zap.String("cmdline_preview", truncateString(procCtx.Cmdline, 100)),
		)

		result, err := ed.LanguageDetector.Detect(procCtx)
		if err != nil || result == nil || result.Language == inspectors.LanguageUnknown {
			ed.Logger.Info("Language detection failed or unknown",
				zap.String("namespace", pod.Namespace),
				zap.String("pod", pod.Name),
				zap.String("container", container.Name),
				zap.Int("pid", pid),
				zap.String("executable", procCtx.Executable),
				zap.String("cmdline_preview", truncateString(procCtx.Cmdline, 100)),
				zap.Error(err),
			)
			continue
		}

		// Found a language!
		info.Language = string(result.Language)
		info.Framework = result.Framework
		info.Confidence = result.Confidence
		info.Evidence = []string{fmt.Sprintf("Detected via cgroup-based process discovery with %s confidence", result.Confidence)}
		return info
	}

	info.Language = "Unknown"
	info.Confidence = "low"
	return info
}

// findProcessesInContainer finds all PIDs for processes in a specific container
// Uses cgroup-based detection that works across all Kubernetes platforms (GKE, EKS, AKS, on-prem)
func findProcessesInContainer(podUID types.UID, containerName string) []int {
	// Get all processes
	allPids, err := process.FindAllProcesses()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DEBUG] Failed to find processes: %v\n", err)
		return nil
	}

	fmt.Fprintf(os.Stderr, "[DEBUG] Searching for pod %s, container %s in %d processes\n",
		podUID, containerName, len(allPids))

	var matchingPids []int
	procDir := process.GetProcDir()
	checked := 0
	sampleLimit := 5
	samplesShown := 0

	for _, pid := range allPids {
		// Check if this process belongs to the container by examining cgroup
		cgroupPath := fmt.Sprintf("%s/%d/cgroup", procDir, pid)

		// Show first few samples for debugging
		if samplesShown < sampleLimit {
			if data, err := os.ReadFile(cgroupPath); err == nil {
				firstLine := strings.Split(string(data), "\n")[0]
				if len(firstLine) > 100 {
					firstLine = firstLine[:100] + "..."
				}
				fmt.Fprintf(os.Stderr, "[DEBUG] Sample PID %d cgroup: %s\n", pid, firstLine)
				samplesShown++
			}
		}

		if isPodContainerProcess(cgroupPath, podUID, containerName) {
			matchingPids = append(matchingPids, pid)
		}
		checked++
	}

	fmt.Fprintf(os.Stderr, "[DEBUG] Checked %d processes, found %d matches for pod %s\n",
		checked, len(matchingPids), podUID)

	return matchingPids
}

// isPodContainerProcess checks if a process belongs to a specific container
// by examining its cgroup information - works across all K8s platforms
func isPodContainerProcess(cgroupPath string, podUID types.UID, containerName string) bool {
	file, err := os.Open(cgroupPath)
	if err != nil {
		// Process might have terminated or we don't have permission
		return false
	}
	defer file.Close()

	// Prepare both UID formats for maximum compatibility:
	// - With dashes: 8eb9b7bf-0432-40ad-ba5e-34a9fa74501a (cgroup v1, EKS, AKS, older K8s)
	// - With underscores: 8eb9b7bf_0432_40ad_ba5e_34a9fa74501a (cgroup v2, GKE, modern K8s)
	podUIDDashes := string(podUID)
	podUIDUnderscores := strings.ReplaceAll(podUIDDashes, "-", "_")

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Platform-specific cgroup path patterns:
		// GKE (cgroup v2):         0::/kubepods-besteffort-pod8eb9b7bf_0432_40ad_ba5e_34a9fa74501a.slice/cri-containerd-<container-id>.scope
		// EKS (cgroup v1):         11:cpuset:/kubepods/besteffort/pod8eb9b7bf-0432-40ad-ba5e-34a9fa74501a/<container-id>
		// AKS (cgroup v1/v2):      Similar patterns depending on K8s version
		// On-prem Docker:          10:memory:/kubepods/burstable/pod8eb9b7bf-0432-40ad-ba5e-34a9fa74501a/<docker-id>
		// On-prem containerd:      Similar to cloud providers
		// On-prem CRI-O:           Similar patterns with crio prefix

		// Check for pod UID in either format
		hasPodUID := strings.Contains(line, podUIDDashes) || strings.Contains(line, podUIDUnderscores)

		if hasPodUID {
			// Additional verification: For multi-container pods, try to match container
			// However, container name matching is unreliable across platforms, so we use a best-effort approach

			// If this is a pause/infrastructure container, skip it
			// Pause containers often have "pause" or "POD" in their cgroup path
			lowerLine := strings.ToLower(line)
			if strings.Contains(lowerLine, "/pause") || strings.Contains(lowerLine, "/pod.slice") {
				continue
			}

			// If we have a container name, try to match it (best effort)
			// This works on some platforms but not all - we don't want to miss detections
			// so we'll accept any non-pause container from the correct pod
			return true
		}
	}

	return false
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// setupInformers configures informers for watching Kubernetes resources
func (ed *EBPFDetector) setupInformers() {
	// Pod informer - watch for pod deletion
	podInformer := ed.informerFactory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			key := pod.Namespace + "/" + pod.Name
			ed.processedPods.Delete(key)
			ed.Logger.Debug("Pod deleted, removed from processedPods",
				zap.String("namespace", pod.Namespace),
				zap.String("pod", pod.Name),
			)
		},
	})

	// Deployment informer - watch for deployment deletion
	deploymentInformer := ed.informerFactory.Apps().V1().Deployments().Informer()
	deploymentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			deployment := obj.(*appsv1.Deployment)
			ed.Cache.RemoveWorkload(deployment.Namespace, deployment.Name)
			ed.Logger.Info("Deployment deleted, removed from cache",
				zap.String("namespace", deployment.Namespace),
				zap.String("deployment", deployment.Name),
			)
		},
	})

	// DaemonSet informer - watch for daemonset deletion
	daemonSetInformer := ed.informerFactory.Apps().V1().DaemonSets().Informer()
	daemonSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			daemonSet := obj.(*appsv1.DaemonSet)
			ed.Cache.RemoveWorkload(daemonSet.Namespace, daemonSet.Name)
			ed.Logger.Info("DaemonSet deleted, removed from cache",
				zap.String("namespace", daemonSet.Namespace),
				zap.String("daemonset", daemonSet.Name),
			)
		},
	})

	// ReplicaSet informer - watch for replicaset deletion
	replicaSetInformer := ed.informerFactory.Apps().V1().ReplicaSets().Informer()
	replicaSetInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		DeleteFunc: func(obj interface{}) {
			replicaSet := obj.(*appsv1.ReplicaSet)
			ed.Cache.RemoveWorkload(replicaSet.Namespace, replicaSet.Name)
			ed.Logger.Debug("ReplicaSet deleted, removed from cache",
				zap.String("namespace", replicaSet.Namespace),
				zap.String("replicaset", replicaSet.Name),
			)
		},
	})

	ed.Logger.Info("Informers configured for lifecycle management")
}

// reconciliationLoop periodically reconciles cache with actual cluster state
func (ed *EBPFDetector) reconciliationLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	ed.Logger.Info("Starting reconciliation loop")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ed.reconcileCache(ctx)
		}
	}
}

// reconcileCache syncs the cache with actual cluster state
func (ed *EBPFDetector) reconcileCache(ctx context.Context) {
	ed.Logger.Info("Starting cache reconciliation with cluster state")

	// Get all workloads from cache
	cachedWorkloads := ed.Cache.GetAllActiveWorkloads()

	// Check each cached workload against cluster state
	for _, workload := range cachedWorkloads {
		exists := false

		switch workload.WorkloadKind {
		case "Deployment":
			_, err := ed.Clientset.AppsV1().Deployments(workload.Namespace).Get(ctx, workload.WorkloadName, metav1.GetOptions{})
			exists = err == nil

		case "DaemonSet":
			_, err := ed.Clientset.AppsV1().DaemonSets(workload.Namespace).Get(ctx, workload.WorkloadName, metav1.GetOptions{})
			exists = err == nil

		case "ReplicaSet":
			_, err := ed.Clientset.AppsV1().ReplicaSets(workload.Namespace).Get(ctx, workload.WorkloadName, metav1.GetOptions{})
			exists = err == nil

		case "StatefulSet":
			_, err := ed.Clientset.AppsV1().StatefulSets(workload.Namespace).Get(ctx, workload.WorkloadName, metav1.GetOptions{})
			exists = err == nil
		}

		// If workload no longer exists, remove it from cache immediately
		if !exists {
			ed.Cache.RemoveWorkload(workload.Namespace, workload.WorkloadName)
			ed.Logger.Info("Workload no longer exists, removed from cache",
				zap.String("namespace", workload.Namespace),
				zap.String("workload", workload.WorkloadName),
				zap.String("kind", workload.WorkloadKind),
			)
		}
	}

	// Reconcile processedPods map - remove entries for non-existent pods
	var toRemove []string
	ed.processedPods.Range(func(key, value interface{}) bool {
		podKey := key.(string)
		parts := strings.Split(podKey, "/")
		if len(parts) != 2 {
			return true
		}

		namespace, podName := parts[0], parts[1]
		_, err := ed.Clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
		if err != nil {
			// Pod no longer exists
			toRemove = append(toRemove, podKey)
		}
		return true
	})

	// Remove stale pod entries
	for _, podKey := range toRemove {
		ed.processedPods.Delete(podKey)
	}

	if len(toRemove) > 0 {
		ed.Logger.Info("Cleaned up processedPods entries",
			zap.Int("count", len(toRemove)),
		)
	}

	ed.Logger.Info("Cache reconciliation completed",
		zap.Int("cached_workloads", len(cachedWorkloads)),
		zap.Int("removed_pods", len(toRemove)),
	)
}
