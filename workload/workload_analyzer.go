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
	// scanDeployments(ctx, clientset)
	// scanStatefulSets(ctx, clientset)
	// scanDaemonSets(ctx, clientset)
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

			// for _, container := range pod.Spec.Containers {

			// 	execCmd := append(container.Command, container.Args...)
			// 	language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd, container)
			// 	if language == "Unknown" {
			// 		language, err = detector.HardLanguageDetector(ctx, container.Image)
			// 		if err != nil {
			// 			log.Errorf("Pod: %s/%s, Container: %s, Image: %s, Language: %s\n",
			// 				pod.Namespace, pod.Name, container.Name, container.Image, language)
			// 		}
			// 	}
			// 	log.Info(nil, "Pod", pod.Name, "Namespace", pod.Namespace, "Container", container.Name, "Image", container.Image, "Language Detected", language)
			// }
		}
	}
}

// scanDeployments fetches and prints information about all deployments.
func scanDeployments(ctx context.Context, clientset *kubernetes.Clientset) {
	log.Info("Scanning Deployments")
	deployments, err := clientset.AppsV1().Deployments("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching deployments: %v\n", err)
		return
	}

	for _, deploy := range deployments.Items {
		for _, container := range deploy.Spec.Template.Spec.Containers {
			execCmd := append(container.Command, container.Args...)
			language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd, container)
			if language == "Unknown" {
				language, err = detector.HardLanguageDetector(container.Image)
				if err != nil {
					log.Errorf("Deployment: %s/%s, Container: %s, Image: %s, Language: %s\n",
						deploy.Namespace, deploy.Name, container.Name, container.Image, language)
				}
			}
			log.Info(nil, "Deployment", deploy.Name, "Namespace", deploy.Namespace, "Container", container.Name, "Image", container.Image, "Language Detected", language)

		}
	}
}

// scanStatefulSets fetches and prints information about all statefulsets.
func scanStatefulSets(ctx context.Context, clientset *kubernetes.Clientset) {
	log.Info("Scanning StatefulSets")
	statefulsets, err := clientset.AppsV1().StatefulSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching statefulsets: %v\n", err)
		return
	}

	for _, statefulset := range statefulsets.Items {
		for _, container := range statefulset.Spec.Template.Spec.Containers {
			execCmd := append(container.Command, container.Args...)
			language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd, container)
			if language == "Unknown" {
				language, err = detector.HardLanguageDetector(container.Image)
				if err != nil {
					log.Errorf("StatefulSet: %s/%s, Container: %s, Image: %s, Language: %s\n",
						statefulset.Namespace, statefulset.Name, container.Name, container.Image, language)
				}
			}
			log.Info(nil, "StatefulSet", statefulset.Name, "Namespace", statefulset.Namespace, "Container", container.Name, "Image", container.Image, "Language Detected", language)

		}
	}
	fmt.Println()
}

// scanDaemonSets fetches and prints information about all daemonsets.
func scanDaemonSets(ctx context.Context, clientset *kubernetes.Clientset) {
	log.Info("Scanning DaemonSets")
	daemonsets, err := clientset.AppsV1().DaemonSets("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching daemonsets: %v\n", err)
		return
	}

	for _, daemonset := range daemonsets.Items {
		for _, container := range daemonset.Spec.Template.Spec.Containers {
			execCmd := append(container.Command, container.Args...)
			language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd, container)
			if language == "Unknown" {
				language, err = detector.HardLanguageDetector(container.Image)
				if err != nil {
					log.Errorf("DaemonSet: %s/%s, Container: %s, Image: %s, Language: %s\n",
						&daemonset.Namespace, &daemonset.Name, container.Name, container.Image, language)
				}
			}
			log.Info(nil, "DaemonSet", daemonset.Name, "Namespace", daemonset.Namespace, "Container", container.Name, "Image", container.Image, "Language Detected", language)

		}
	}
}
