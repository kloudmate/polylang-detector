package workload

import (
	"context"
	"sync"
	"time"

	"github.com/kloudmate/polylang-detector/detector"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ScanPodsEbpf continuously scans all running pods using eBPF-based detection
func ScanPodsEbpf(ctx context.Context, clientset *kubernetes.Clientset, pd *detector.PolylangDetector, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	pd.DomainLogger.(interface {
		EbpfScanStarted()
	}).EbpfScanStarted()

	// Track processed pods to avoid duplicate processing
	processedPods := sync.Map{}

	// Periodic scanning with configurable interval
	scanInterval := 30 * time.Second
	ticker := time.NewTicker(scanInterval)
	defer ticker.Stop()

	// Perform initial scan immediately
	scanAllPods(ctx, clientset, pd, &processedPods)

	// Periodic re-sync: Clear processedPods cache every 5 minutes to allow re-detection
	resyncTicker := time.NewTicker(6 * time.Minute)
	defer resyncTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			pd.DomainLogger.(interface {
				EbpfScanStopped()
			}).EbpfScanStopped()
			return
		case <-ticker.C:
			// Scan pods periodically
			scanAllPods(ctx, clientset, pd, &processedPods)
		case <-resyncTicker.C:
			// Clear the processed pods map to allow re-detection
			processedPods.Range(func(key, value interface{}) bool {
				processedPods.Delete(key)
				return true
			})
			pd.Logger.Sugar().Info("Cleared processed pods cache for re-sync")
		}
	}
}

// scanAllPods scans all running pods in the cluster
func scanAllPods(ctx context.Context, clientset *kubernetes.Clientset, pd *detector.PolylangDetector, processedPods *sync.Map) {
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		pd.Logger.Sugar().Errorf("Error fetching pods: %v", err)
		return
	}

	pd.DomainLogger.(interface {
		EbpfScanCycleStarted(count int)
	}).EbpfScanCycleStarted(len(pods.Items))

	var detectedCount int
	for _, pod := range pods.Items {
		// Check if namespace should be monitored
		// Priority: KM_MONITORED_NS > KM_IGNORED_NS
		if !pd.ShouldMonitorNamespace(pod.Namespace) {
			continue
		}

		// Only scan running pods
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}

		// Create unique key for this pod
		key := pod.Namespace + "/" + pod.Name

		// Skip if already processed
		if _, exists := processedPods.Load(key); exists {
			continue
		}

		// Mark as processed
		processedPods.Store(key, true)

		// Detect language using /proc inspection
		go func(p corev1.Pod) {
			containerInfos, err := pd.DetectLanguageWithProcInspection(p.Namespace, p.Name)
			if err != nil {
				pd.DomainLogger.LanguageDetectionFailed(p.Namespace, p.Name, "", err)
				// Remove from processed so we can retry
				processedPods.Delete(p.Namespace + "/" + p.Name)
				return
			}

			for _, info := range containerInfos {
				pd.Logger.Sugar().Infow("/proc inspection completed",
					"container_name", info.ContainerName,
					"image", info.Image,
					"language", info.Language,
					"framework", info.Framework,
					"confidence", info.Confidence,
					"namespace", info.Namespace,
					"deployment_name", info.DeploymentName,
					"deployment_kind", info.Kind,
					"pod_name", info.PodName,
					"detected_at", info.DetectedAt,
				)

				// Send to queue if supported language
				if _, ok := detector.OtelSupportedLanguages[info.Language]; ok {
					pd.Queue <- info
				}
			}
		}(pod)

		detectedCount++
	}

	pd.DomainLogger.(interface {
		EbpfScanCycleCompleted(scanned, detected int)
	}).EbpfScanCycleCompleted(len(pods.Items), detectedCount)
}
