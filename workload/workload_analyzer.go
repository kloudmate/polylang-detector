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
	"k8s.io/client-go/kubernetes"
)

func AnalyzeWorkloads(ctx context.Context, pd *detector.PolylangDetector, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()
	ticker := time.NewTicker(60 * time.Second)

	defer ticker.Stop()
	pd.Logger.Sugar().Infof("analyzing workloads in the cluster")
	ScanPods(ctx, pd.Clientset, pd)
	for {
		select {
		case <-ctx.Done():
			pd.Logger.Sugar().Infof("stopped to analyze workloads in the cluster")

			return
		case <-ticker.C:
			ScanPods(ctx, pd.Clientset, pd)

		}
	}

}

// scanPods fetches all running pods and attempts to detect their language using exec.
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
