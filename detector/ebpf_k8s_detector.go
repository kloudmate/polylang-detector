package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// EbpfK8sDetector provides Kubernetes-aware eBPF language detection
type EbpfK8sDetector struct {
	clientset     *kubernetes.Clientset
	ebpfDetector  *EbpfDetector
	nodeDetection bool // Whether we're running on the same node as pods
}

// ContainerRuntimeInfo contains container runtime information from crictl
type ContainerRuntimeInfo struct {
	ID     string                 `json:"id"`
	PID    int                    `json:"pid"`
	Labels map[string]string      `json:"labels"`
	Info   map[string]interface{} `json:"info"`
}

// NewEbpfK8sDetector creates a new Kubernetes-aware eBPF detector
func NewEbpfK8sDetector(clientset *kubernetes.Clientset) *EbpfK8sDetector {
	return &EbpfK8sDetector{
		clientset:     clientset,
		ebpfDetector:  NewEbpfDetector(),
		nodeDetection: isRunningOnNode(),
	}
}

// DetectLanguageForPod detects programming language for a pod using eBPF
func (ekd *EbpfK8sDetector) DetectLanguageForPod(ctx context.Context, namespace, podName string) ([]ContainerInfo, error) {
	pod, err := ekd.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	var results []ContainerInfo

	// Method 1: If we're running as a DaemonSet with hostPID, use direct process inspection
	if ekd.nodeDetection {
		containerInfos, err := ekd.detectViaNodeAccess(ctx, pod)
		if err == nil && len(containerInfos) > 0 {
			return containerInfos, nil
		}
	}

	// Method 2: Use crictl/docker inspection (works from Deployment without hostPID)
	containerInfos, err := ekd.detectViaCrictl(ctx, pod)
	if err == nil && len(containerInfos) > 0 {
		return containerInfos, nil
	}

	// Method 3: Remote node eBPF inspection via crictl exec (for Deployment mode)
	containerInfos, err = ekd.detectViaRemoteInspection(ctx, pod)
	if err == nil && len(containerInfos) > 0 {
		return containerInfos, nil
	}

	return results, fmt.Errorf("failed to detect language for pod %s/%s", namespace, podName)
}

// detectViaNodeAccess detects language by accessing node's process information
func (ekd *EbpfK8sDetector) detectViaNodeAccess(ctx context.Context, pod *corev1.Pod) ([]ContainerInfo, error) {
	var results []ContainerInfo

	for _, container := range pod.Spec.Containers {
		// Get container ID from pod status
		var containerID string
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == container.Name {
				// Extract container ID (remove prefix like "docker://")
				parts := strings.Split(status.ContainerID, "://")
				if len(parts) == 2 {
					containerID = parts[1]
				}
				break
			}
		}

		if containerID == "" {
			continue
		}

		// Detect language using eBPF detector
		procInfos, err := ekd.ebpfDetector.DetectLanguageForContainer(ctx, containerID)
		if err != nil || len(procInfos) == 0 {
			continue
		}

		// Convert to ContainerInfo
		for _, procInfo := range procInfos {
			if procInfo.Language == "" {
				continue
			}

			depName, _ := getPodDeploymentName(ekd.clientset, pod.Namespace, pod.Name)
			ownerRef := metav1.GetControllerOf(pod)
			kind := "Pod"
			if ownerRef != nil {
				kind = ownerRef.Kind
			}

			info := ContainerInfo{
				PodName:        pod.Name,
				Namespace:      pod.Namespace,
				ContainerName:  container.Name,
				Image:          container.Image,
				Language:       procInfo.Language,
				Framework:      procInfo.Framework,
				Confidence:     procInfo.Confidence,
				DeploymentName: depName,
				Kind:           kind,
				DetectedAt:     time.Now(),
				EnvVars:        make(map[string]string),
			}

			// Extract env vars
			for _, env := range container.Env {
				if env.Value != "" {
					info.EnvVars[env.Name] = env.Value
				}
			}

			results = append(results, info)
		}
	}

	return results, nil
}

// detectViaCrictl detects language using crictl container runtime CLI
func (ekd *EbpfK8sDetector) detectViaCrictl(ctx context.Context, pod *corev1.Pod) ([]ContainerInfo, error) {
	var results []ContainerInfo

	for _, container := range pod.Spec.Containers {
		// Get container ID from pod status
		var containerID string
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == container.Name {
				parts := strings.Split(status.ContainerID, "://")
				if len(parts) == 2 {
					containerID = parts[1]
				}
				break
			}
		}

		if containerID == "" {
			continue
		}

		// Get container PID using crictl
		pid, err := ekd.getContainerPID(containerID)
		if err != nil {
			continue
		}

		// Detect language by PID
		procInfo, err := ekd.ebpfDetector.DetectLanguageByPID(pid)
		if err != nil || procInfo.Language == "" {
			continue
		}

		depName, _ := getPodDeploymentName(ekd.clientset, pod.Namespace, pod.Name)
		ownerRef := metav1.GetControllerOf(pod)
		kind := "Pod"
		if ownerRef != nil {
			kind = ownerRef.Kind
		}

		info := ContainerInfo{
			PodName:        pod.Name,
			Namespace:      pod.Namespace,
			ContainerName:  container.Name,
			Image:          container.Image,
			Language:       procInfo.Language,
			Framework:      procInfo.Framework,
			Confidence:     procInfo.Confidence,
			DeploymentName: depName,
			Kind:           kind,
			DetectedAt:     time.Now(),
			EnvVars:        make(map[string]string),
		}

		for _, env := range container.Env {
			if env.Value != "" {
				info.EnvVars[env.Name] = env.Value
			}
		}

		results = append(results, info)
	}

	return results, nil
}

// getContainerPID gets the PID of a container's main process
func (ekd *EbpfK8sDetector) getContainerPID(containerID string) (int, error) {
	// Try crictl first
	cmd := exec.Command("crictl", "inspect", containerID)
	output, err := cmd.Output()
	if err != nil {
		// Fallback to docker
		cmd = exec.Command("docker", "inspect", containerID)
		output, err = cmd.Output()
		if err != nil {
			return 0, fmt.Errorf("failed to inspect container: %w", err)
		}
	}

	// Parse JSON output
	var inspectData []map[string]interface{}
	if err := json.Unmarshal(output, &inspectData); err != nil {
		return 0, fmt.Errorf("failed to parse inspect output: %w", err)
	}

	if len(inspectData) == 0 {
		return 0, fmt.Errorf("no inspect data for container")
	}

	// Extract PID from different possible locations
	data := inspectData[0]

	// Try crictl format
	if info, ok := data["info"].(map[string]interface{}); ok {
		if pid, ok := info["pid"].(float64); ok {
			return int(pid), nil
		}
	}

	// Try docker format
	if state, ok := data["State"].(map[string]interface{}); ok {
		if pid, ok := state["Pid"].(float64); ok {
			return int(pid), nil
		}
	}

	return 0, fmt.Errorf("could not find PID in inspect output")
}

// detectViaRemoteInspection detects language by reading /proc via crictl exec
// This works from a Deployment without hostPID by using the container runtime
func (ekd *EbpfK8sDetector) detectViaRemoteInspection(ctx context.Context, pod *corev1.Pod) ([]ContainerInfo, error) {
	var results []ContainerInfo

	for _, container := range pod.Spec.Containers {
		// Get container ID from pod status
		var containerID string
		for _, status := range pod.Status.ContainerStatuses {
			if status.Name == container.Name {
				parts := strings.Split(status.ContainerID, "://")
				if len(parts) == 2 {
					containerID = parts[1]
				}
				break
			}
		}

		if containerID == "" {
			continue
		}

		// Use crictl to read process info remotely
		// This reads /proc from the container's namespace
		cmdline, err := ekd.readContainerProcFile(containerID, "1/cmdline")
		if err != nil {
			continue
		}

		exe, err := ekd.readContainerProcFile(containerID, "1/exe")
		if err != nil {
			exe = ""
		}

		// Create minimal process info for detection
		procInfo := &ProcessInfo{
			PID:        1,
			Cmdline:    strings.ReplaceAll(cmdline, "\x00", " "),
			Executable: exe,
		}

		// Detect language
		lang, fw, conf := ekd.ebpfDetector.matchLanguageSignatures(procInfo)
		if lang == "" {
			continue
		}

		depName, _ := getPodDeploymentName(ekd.clientset, pod.Namespace, pod.Name)
		ownerRef := metav1.GetControllerOf(pod)
		kind := "Pod"
		if ownerRef != nil {
			kind = ownerRef.Kind
		}

		info := ContainerInfo{
			PodName:        pod.Name,
			Namespace:      pod.Namespace,
			ContainerName:  container.Name,
			Image:          container.Image,
			Language:       lang,
			Framework:      fw,
			Confidence:     conf,
			DeploymentName: depName,
			Kind:           kind,
			DetectedAt:     time.Now(),
			EnvVars:        make(map[string]string),
		}

		for _, env := range container.Env {
			if env.Value != "" {
				info.EnvVars[env.Name] = env.Value
			}
		}

		results = append(results, info)
	}

	if len(results) > 0 {
		return results, nil
	}

	return nil, fmt.Errorf("no languages detected via remote inspection")
}

// readContainerProcFile reads a file from container's /proc using crictl exec
func (ekd *EbpfK8sDetector) readContainerProcFile(containerID, procPath string) (string, error) {
	// Try crictl exec to read /proc file
	cmd := exec.Command("crictl", "exec", containerID, "cat", fmt.Sprintf("/proc/%s", procPath))
	output, err := cmd.Output()
	if err != nil {
		// Try readlink for exe
		if strings.HasSuffix(procPath, "/exe") {
			cmd = exec.Command("crictl", "exec", containerID, "readlink", fmt.Sprintf("/proc/%s", procPath))
			output, err = cmd.Output()
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	return string(output), nil
}

// isRunningOnNode checks if we're running on a node with access to host PID namespace
func isRunningOnNode() bool {
	// Check if we have access to host processes
	// This would be true if running as a DaemonSet with hostPID: true
	_, err := exec.Command("test", "-d", "/proc/1/root").Output()
	return err == nil
}

// DetectLanguageWithEbpf attempts eBPF detection first, falls back to other methods
func (pd *PolylangDetector) DetectLanguageWithEbpf(namespace, podName string) ([]ContainerInfo, error) {
	// Create eBPF detector
	ebpfDetector := NewEbpfK8sDetector(pd.Clientset)

	// Try eBPF detection
	results, err := ebpfDetector.DetectLanguageForPod(context.TODO(), namespace, podName)
	if err == nil && len(results) > 0 {
		// Cache and enqueue results
		for i := range results {
			info := &results[i]
			pd.Cache.Set(info.Image, info.EnvVars, *info)

			if _, ok := otelSupportedLanguages[info.Language]; ok {
				pd.Queue <- *info
			}
		}
		return results, nil
	}

	// Fallback to existing detection method
	return pd.DetectLanguageWithRuntimeInfo(namespace, podName)
}

