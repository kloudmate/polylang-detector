package workload

import (
	"context"
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/kloudmate/polylang-detector/detector"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func AnalyzeWorkloads(ctx context.Context, execD *detector.ExecDetector) {
	ScanPods(ctx, execD.Clientset, execD)
}

// scanPods fetches all running pods and attempts to detect their language using exec.
func ScanPods(ctx context.Context, clientset *kubernetes.Clientset, execD *detector.ExecDetector) {
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching pods: %v\n", err)
		return
	}

	for _, pod := range pods.Items {
		// Only scan running pods
		log.Printf("Starting language detection for pod %s in namespace %s", pod.Name, pod.Namespace)

		if pod.Status.Phase == corev1.PodRunning {

			containerInfos, err := execD.DetectLanguageWithRuntimeInfo(pod.Namespace, pod.Name)
			if err != nil {
				log.Fatalf("Error detecting language: %v", err)
			}
			for _, info := range containerInfos {
				fmt.Printf("\n--- Results for Container: %s ---\n", info.ContainerName)
				fmt.Printf("Image: %s\n", info.Image)
				fmt.Printf("Detected Language: %s (Confidence: %s)\n", info.Language, info.Confidence)
				fmt.Printf("Detected Framework: %s\n", info.Framework)
				fmt.Printf("Evidence:\n")
				for _, evidence := range info.Evidence {
					fmt.Printf("  - %s\n", evidence)
				}
				fmt.Println("---------------------------------------")
			}
		}
	}
}
