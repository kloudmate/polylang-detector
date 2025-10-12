package detector

import (
	"context"
	"fmt"
	"net/rpc"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// ContainerInfo holds the detected information for a single container.
type ContainerInfo struct {
	PodName         string
	Namespace       string
	ContainerName   string
	Image           string
	Kind            string
	EnvVars         map[string]string
	ProcessCommands []string
	DetectedAt      time.Time
	Language        string
	Framework       string
	Enabled         bool
	Confidence      string
	DeploymentName  string
	Evidence        []string
}

// PolylangDetector contains the Kubernetes client to interact with the cluster.
type PolylangDetector struct {
	Clientset    *kubernetes.Clientset
	Config       *rest.Config
	RpcClient    *rpc.Client
	ServerAddr   string
	Logger       *zap.Logger
	DomainLogger interface {
		LanguageDetectionStarted(namespace, podName, containerName string)
		LanguageDetected(namespace, podName, containerName, image, language, framework, confidence string)
		LanguageDetectionFailed(namespace, podName, containerName string, err error)
		UnsupportedLanguage(language string)
		CacheHit(image, language string)
		CacheMiss(image string)
		CacheStored(image, language string)
		RPCBatchSent(count int, response string)
		RPCBatchFailed(count int, err error)
		DeploymentInfoRetrieved(namespace, podName, deploymentName, kind string)
		DeploymentInfoFailed(namespace, podName string, err error)
	}
	IgnoredNamespaces   []string
	MonitoredNamespaces []string
	Queue               chan ContainerInfo
	QueueSize           int
	BatchMutex          sync.Mutex
	Cache               *LanguageCache
}

// NewPolylangDetector creates a new language detector
func NewPolylangDetector(config *rest.Config, client *kubernetes.Clientset, domainLogger interface {
	LanguageDetectionStarted(namespace, podName, containerName string)
	LanguageDetected(namespace, podName, containerName, image, language, framework, confidence string)
	LanguageDetectionFailed(namespace, podName, containerName string, err error)
	UnsupportedLanguage(language string)
	CacheHit(image, language string)
	CacheMiss(image string)
	CacheStored(image, language string)
	RPCBatchSent(count int, response string)
	RPCBatchFailed(count int, err error)
	DeploymentInfoRetrieved(namespace, podName, deploymentName, kind string)
	DeploymentInfoFailed(namespace, podName string, err error)
}) *PolylangDetector {
	addr := string(os.Getenv("KM_CFG_UPDATER_RPC_ADDR"))

	// Parse ignored namespaces
	nsEnv := string(os.Getenv("KM_IGNORED_NS"))
	var ignoredNs []string
	if nsEnv != "" {
		ignoredNs = strings.Split(nsEnv, ",")
		// Trim whitespace from each namespace
		for i := range ignoredNs {
			ignoredNs[i] = strings.TrimSpace(ignoredNs[i])
		}
	}

	// Parse monitored namespaces (higher priority than ignored)
	monitoredEnv := string(os.Getenv("KM_K8S_MONITORED_NAMESPACES"))
	var monitoredNs []string
	if monitoredEnv != "" {
		monitoredNs = strings.Split(monitoredEnv, ",")
		// Trim whitespace from each namespace
		for i := range monitoredNs {
			monitoredNs[i] = strings.TrimSpace(monitoredNs[i])
		}
	}

	loggerConfig := zap.NewProductionConfig()
	logger, _ := loggerConfig.Build()

	// Cache TTL - default 1 hour, configurable via env var
	cacheTTL := 1 * time.Hour
	if ttlEnv := os.Getenv("KM_CACHE_TTL_MINUTES"); ttlEnv != "" {
		if minutes, err := time.ParseDuration(ttlEnv + "m"); err == nil {
			cacheTTL = minutes
		}
	}

	return &PolylangDetector{
		Clientset:           client,
		Config:              config,
		IgnoredNamespaces:   ignoredNs,
		MonitoredNamespaces: monitoredNs,
		ServerAddr:          addr,
		Logger:              logger,
		DomainLogger:        domainLogger,
		Queue:               make(chan ContainerInfo, 100), // Queue with a capacity of 100
		QueueSize:           5,                             // Batch size
		Cache:               NewLanguageCache(cacheTTL),
	}
}

// SendBatch sends a batch of container info to the RPC server
func (pd *PolylangDetector) SendBatch(batch []ContainerInfo) {
	if len(batch) == 0 {
		return
	}

	var reply string

	// Ensure we have a connection
	if pd.RpcClient == nil {
		pd.Logger.Warn("RPC client not connected, attempting reconnection")
		if err := pd.DialWithRetry(context.TODO(), time.Second*10); err != nil {
			pd.Logger.Error("Failed to establish RPC connection", zap.Error(err))
			return
		}
	}

	// Try to send the batch
	err := pd.RpcClient.Call("RPCHandler.PushDetectionResults", batch, &reply)
	if err != nil {
		pd.DomainLogger.RPCBatchFailed(len(batch), err)

		// Connection failed, try to reconnect
		pd.RpcClient = nil // Mark connection as dead
		if err := pd.DialWithRetry(context.TODO(), time.Second*10); err != nil {
			pd.Logger.Error("Failed to re-establish RPC connection", zap.Error(err))
			return
		}

		// Retry sending the batch after reconnection
		err = pd.RpcClient.Call("RPCHandler.PushDetectionResults", batch, &reply)
		if err != nil {
			pd.DomainLogger.RPCBatchFailed(len(batch), err)
			pd.Logger.Error("Failed to send batch after reconnection", zap.Error(err))
			return
		}
	}

	pd.DomainLogger.RPCBatchSent(len(batch), reply)
}

// ShouldMonitorNamespace determines if a namespace should be monitored based on configuration
// Priority: KM_K8S_MONITORED_NAMESPACES > KM_IGNORED_NS
func (pd *PolylangDetector) ShouldMonitorNamespace(namespace string) bool {
	// If monitored namespaces are specified, only monitor those (highest priority)
	if len(pd.MonitoredNamespaces) > 0 {
		for _, ns := range pd.MonitoredNamespaces {
			if ns == namespace {
				return true
			}
		}
		return false
	}

	// If no monitored namespaces specified, check ignored list
	if len(pd.IgnoredNamespaces) > 0 {
		for _, ns := range pd.IgnoredNamespaces {
			if ns == namespace {
				return false
			}
		}
	}

	// Default: monitor all namespaces
	return true
}

// DetectLanguageWithProcInspection detects language using /proc filesystem inspection (DaemonSet mode)
func (pd *PolylangDetector) DetectLanguageWithProcInspection(namespace, podName string) ([]ContainerInfo, error) {
	procDetector := NewProcBasedDetector(pd.Clientset, pd.Cache, pd.Logger)
	return procDetector.DetectLanguageForPod(context.TODO(), namespace, podName)
}

// StartEBPFDetection starts eBPF-based real-time process detection (recommended mode)
func (pd *PolylangDetector) StartEBPFDetection(ctx context.Context) error {
	pd.Logger.Info("Starting eBPF-based language detection")

	ebpfDetector, err := NewEBPFDetector(pd.Clientset, pd.Cache, pd.Logger)
	if err != nil {
		return fmt.Errorf("failed to create eBPF detector: %w", err)
	}

	return ebpfDetector.Start(ctx)
}

// getPodDeploymentName finds the name of the deployment that owns a given pod.
func getPodDeploymentName(clientset *kubernetes.Clientset, namespace, podName string) (string, error) {
	// Get the pod object
	pod, err := clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get pod %s: %w", podName, err)
	}

	// Find the pod's owner, which is typically a ReplicaSet, DaemonSet, or StatefulSet
	ownerRef := metav1.GetControllerOf(pod)
	if ownerRef == nil {
		return "Standalone Pod", nil
	}

	// If the owner is a ReplicaSet, we need to go up one more level to find the Deployment
	if ownerRef.Kind == "ReplicaSet" {
		replicaSet, err := clientset.AppsV1().ReplicaSets(namespace).Get(context.TODO(), ownerRef.Name, metav1.GetOptions{})
		if err != nil {
			return "", fmt.Errorf("failed to get ReplicaSet %s: %w", ownerRef.Name, err)
		}

		rsOwnerRef := metav1.GetControllerOf(replicaSet)
		if rsOwnerRef == nil {
			return "ReplicaSet", nil // The ReplicaSet is a top-level owner
		}
		return rsOwnerRef.Name, nil
	}

	// For DaemonSets and StatefulSets, the pod's owner is the top-level controller
	if ownerRef.Kind == "DaemonSet" || ownerRef.Kind == "StatefulSet" {
		return ownerRef.Name, nil
	}

	return ownerRef.Name, fmt.Errorf("unknown owner kind: %s for pod %s", ownerRef.Kind, podName)
}
