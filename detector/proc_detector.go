package detector

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/log"
	"github.com/kloudmate/polylang-detector/detector/inspectors"
	"github.com/kloudmate/polylang-detector/detector/process"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ProcBasedDetector uses /proc filesystem for language detection (DaemonSet mode)
type ProcBasedDetector struct {
	Clientset        *kubernetes.Clientset
	LanguageDetector *inspectors.LanguageDetector
	Cache            *LanguageCache
}

// NewProcBasedDetector creates a new /proc-based language detector
func NewProcBasedDetector(clientset *kubernetes.Clientset, cache *LanguageCache) *ProcBasedDetector {
	// Set proc dir to /host/proc if running in DaemonSet with hostPID
	if _, err := os.Stat("/host/proc"); err == nil {
		process.SetProcDir("/host/proc")
		log.Info("Using /host/proc for process inspection (DaemonSet mode)")
	} else {
		log.Info("Using /proc for process inspection")
	}

	return &ProcBasedDetector{
		Clientset:        clientset,
		LanguageDetector: inspectors.NewLanguageDetector(),
		Cache:            cache,
	}
}

// DetectLanguageForPod detects languages for all containers in a pod using /proc inspection
func (pd *ProcBasedDetector) DetectLanguageForPod(ctx context.Context, namespace, podName string) ([]ContainerInfo, error) {
	pod, err := pd.Clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	if pod.Status.Phase != corev1.PodRunning {
		return nil, fmt.Errorf("pod is not running: %s", pod.Status.Phase)
	}

	var results []ContainerInfo

	// Get pod's owner information
	ownerRef := metav1.GetControllerOf(pod)
	var ownerKind string
	if ownerRef == nil {
		ownerKind = "Pod"
	} else {
		ownerKind = ownerRef.Kind
	}

	// For each container in the pod
	for _, container := range pod.Spec.Containers {
		// Check cache first
		containerEnvVars := make(map[string]string)
		for _, env := range container.Env {
			if env.Value != "" {
				containerEnvVars[env.Name] = env.Value
			}
		}

		if cachedInfo, found := pd.Cache.Get(container.Image, containerEnvVars); found {
			// Update pod-specific information
			cachedInfo.PodName = podName
			cachedInfo.Namespace = namespace
			cachedInfo.ContainerName = container.Name
			cachedInfo.DetectedAt = time.Now()

			// Get deployment name
			depName, _ := getPodDeploymentName(pd.Clientset, namespace, podName)
			cachedInfo.DeploymentName = depName

			results = append(results, *cachedInfo)
			log.Infof("Cache hit for %s: %s", container.Image, cachedInfo.Language)
			continue
		}

		log.Infof("Cache miss for %s, detecting language...", container.Image)

		// Find container processes using /proc
		containerInfo, err := pd.detectContainerLanguage(ctx, pod, container)
		if err != nil {
			log.Errorf("Failed to detect language for container %s/%s/%s: %v", namespace, podName, container.Name, err)
			continue
		}

		// Get deployment name
		depName, _ := getPodDeploymentName(pd.Clientset, namespace, podName)
		containerInfo.DeploymentName = depName
		containerInfo.Kind = ownerKind

		// Store in cache
		pd.Cache.Set(container.Image, containerEnvVars, *containerInfo)
		log.Infof("Cached result for %s: %s", container.Image, containerInfo.Language)

		results = append(results, *containerInfo)
	}

	return results, nil
}

// detectContainerLanguage detects the language of a specific container
func (pd *ProcBasedDetector) detectContainerLanguage(ctx context.Context, pod *corev1.Pod, container corev1.Container) (*ContainerInfo, error) {
	info := &ContainerInfo{
		PodName:       pod.Name,
		Namespace:     pod.Namespace,
		ContainerName: container.Name,
		Image:         container.Image,
		EnvVars:       make(map[string]string),
		DetectedAt:    time.Now(),
	}

	// Extract environment variables from pod spec
	for _, env := range container.Env {
		if env.Value != "" {
			info.EnvVars[env.Name] = env.Value
		}
	}

	// Find container's main process
	// We need to map from pod/container to PID
	// Strategy: Find processes in cgroup matching this container

	// Get container status to find container ID
	var containerID string
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name == container.Name && status.ContainerID != "" {
			// Extract container ID from containerID field
			// Format: docker://abc123... or containerd://abc123...
			parts := strings.Split(status.ContainerID, "://")
			if len(parts) == 2 {
				containerID = parts[1]
				if len(containerID) > 12 {
					containerID = containerID[:12]
				}
				break
			}
		}
	}

	if containerID == "" {
		return nil, fmt.Errorf("container ID not found for %s", container.Name)
	}

	// Get PIDs for this container
	pids, err := process.GetContainerPIDs(containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container PIDs: %w", err)
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("no processes found for container %s", container.Name)
	}

	// Detect language for each process and collect results
	var detections []*inspectors.DetectionResult
	for _, pid := range pids {
		procCtx, err := process.GetProcessContext(pid)
		if err != nil {
			log.Debugf("Failed to get process context for PID %d: %v", pid, err)
			continue
		}

		// Run language detection
		result, err := pd.LanguageDetector.Detect(procCtx)
		if err != nil {
			// Check if it's a conflict error
			if conflictErr, ok := err.(*inspectors.ErrLanguageDetectionConflict); ok {
				log.Warnf("Language detection conflict for PID %d: %v", pid, conflictErr)
				continue
			}
			log.Debugf("Failed to detect language for PID %d: %v", pid, err)
			continue
		}

		if result != nil && result.Language != inspectors.LanguageUnknown {
			detections = append(detections, result)
		}
	}

	// Select the best detection result
	if len(detections) == 0 {
		info.Language = "Unknown"
		info.Confidence = "low"
		return info, nil
	}

	// Use the first high-confidence detection, or the first result if no high-confidence found
	bestResult := detections[0]
	for _, result := range detections {
		if result.Confidence == "high" {
			bestResult = result
			break
		}
	}

	info.Language = string(bestResult.Language)
	info.Framework = bestResult.Framework
	info.Confidence = bestResult.Confidence
	info.Evidence = []string{fmt.Sprintf("Detected via /proc inspection with %s confidence", bestResult.Confidence)}

	return info, nil
}
