package workload

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/charmbracelet/log"
	"github.com/kloudmate/polylang-detector/detector"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

func AnalyzeWorkloads(ctx context.Context, pd *detector.PolylangDetector, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	pd.DomainLogger.(interface {
		InformerStarted()
	}).InformerStarted()

	// Create informer factory with 10-minute resync period
	factory := informers.NewSharedInformerFactory(pd.Clientset, 10*time.Minute)
	podInformer := factory.Core().V1().Pods().Informer()

	// Track processed pods to avoid duplicate processing
	processedPods := sync.Map{}

	// Add event handlers for pod lifecycle
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			handlePodEvent(ctx, pd, pod, &processedPods, "ADD")
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod := newObj.(*corev1.Pod)
			handlePodEvent(ctx, pd, pod, &processedPods, "UPDATE")
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			// Clean up from processed cache
			key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
			processedPods.Delete(key)
			pd.Logger.Sugar().Debugf("Removed pod from cache: %s", key)
		},
	})

	// Start the informer
	go factory.Start(ctx.Done())

	// Wait for cache sync before processing
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		pd.DomainLogger.(interface {
			InformerCacheSyncFailed(err error)
		}).InformerCacheSyncFailed(fmt.Errorf("cache sync failed"))
		return
	}

	pd.DomainLogger.(interface {
		InformerCacheSynced()
	}).InformerCacheSynced()

	// Keep the function running until context is cancelled
	<-ctx.Done()
}

// handlePodEvent processes pod events from the informer
func handlePodEvent(ctx context.Context, pd *detector.PolylangDetector, pod *corev1.Pod, processedPods *sync.Map, eventType string) {
	// Skip ignored namespaces
	if slices.Contains(pd.IgnoredNamespaces, pod.Namespace) {
		pd.DomainLogger.(interface {
			PodEventSkipped(namespace, podName, reason string)
		}).PodEventSkipped(pod.Namespace, pod.Name, "namespace_ignored")
		return
	}

	// Only process running pods
	if pod.Status.Phase != corev1.PodRunning {
		pd.DomainLogger.(interface {
			PodEventSkipped(namespace, podName, reason string)
		}).PodEventSkipped(pod.Namespace, pod.Name, fmt.Sprintf("pod_not_running:phase=%s", pod.Status.Phase))
		return
	}

	// Create unique key for this pod
	key := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)

	// For UPDATE events, skip if already processed
	if eventType == "UPDATE" {
		if _, exists := processedPods.Load(key); exists {
			return
		}
	}

	// Mark as processed
	processedPods.Store(key, true)

	pd.DomainLogger.(interface {
		PodEventProcessing(eventType, namespace, podName string)
	}).PodEventProcessing(eventType, pod.Namespace, pod.Name)

	// Process pod asynchronously to avoid blocking the informer
	go func(podName, namespace string) {
		containerInfos, err := pd.DetectLanguageWithRuntimeInfo(namespace, podName)
		if err != nil {
			pd.DomainLogger.LanguageDetectionFailed(namespace, podName, "", err)
			return
		}

		// Individual container logs are now handled in DetectLanguageWithRuntimeInfo
		_ = containerInfos
	}(pod.Name, pod.Namespace)
}

// ScanPods fetches all running pods and attempts to detect their language using exec.
// This is kept for backward compatibility and initial scanning on startup.
func ScanPods(ctx context.Context, clientset *kubernetes.Clientset, pd *detector.PolylangDetector) {
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching pods: %v\n", err)
		return
	}

	for _, pod := range pods.Items {
		if slices.Contains(pd.IgnoredNamespaces, pod.Namespace) {
			continue
		}
		// Only scan running pods
		if pod.Status.Phase == corev1.PodRunning {
			log.Printf("Starting language detection for pod %s in namespace %s", pod.Name, pod.Namespace)

			containerInfos, err := pd.DetectLanguageWithRuntimeInfo(pod.Namespace, pod.Name)
			if err != nil {
				log.Errorf("Error detecting language for pod %s/%s: %v", pod.Namespace, pod.Name, err)
				continue
			}
			for _, info := range containerInfos {
				pd.Logger.Sugar().Infow("workload analyzer",
					"container_name", info.ContainerName,
					"image", info.Image,
					"language", info.Language,
					"namespace", info.Namespace,
					"deployment_name", info.DeploymentName,
					"deployment_kind", info.Kind,
					"pod_name", info.PodName,
					"detected_at", info.DetectedAt,
				)
			}
		}
	}
}
