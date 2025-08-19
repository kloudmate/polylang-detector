package workload

import (
	"bytes"
	"context"
	"fmt"

	"github.com/charmbracelet/log"
	"github.com/kloudmate/polylang-detector/detector"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

func AnalyzeWorkloads(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config) {
	scanDeployments(ctx, clientset)
	scanStatefulSets(ctx, clientset)
	scanDaemonSets(ctx, clientset)
	scanPods(ctx, clientset)
}

// execIntoContainer executes a command in a container and returns the output.
func execIntoContainer(ctx context.Context, clientset *kubernetes.Clientset, config *rest.Config, podName, namespace, containerName string, cmd []string) (string, string, error) {
	scheme.AddToScheme(scheme.Scheme)
	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, scheme.ParameterCodec)
	fmt.Printf("Running Command %v\n", cmd)
	exec, err := remotecommand.NewSPDYExecutor(config, "POST", req.URL())
	if err != nil {
		return "", "", fmt.Errorf("failed to create executor: %w", err)
	}

	var stdout, stderr bytes.Buffer

	streamOptions := remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
		Tty:    false,
	}

	// Stream the command execution.
	err = exec.Stream(streamOptions)
	if err != nil {
		return stdout.String(), stderr.String(), fmt.Errorf("failed to stream command: %w", err)
	}

	return stdout.String(), stderr.String(), nil
}

// scanPods fetches all running pods and attempts to detect their language using exec.
func scanPods(ctx context.Context, clientset *kubernetes.Clientset) {
	log.Info("Scanning Pods")
	pods, err := clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching pods: %v\n", err)
		return
	}

	for _, pod := range pods.Items {
		// Only scan running pods
		if pod.Status.Phase == corev1.PodRunning {
			for _, container := range pod.Spec.Containers {
				execCmd := append(container.Command, container.Args...)
				language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd)
				if language == "Unknown" {
					language, err = detector.HardLanguageDetector(ctx, container.Image)
					if err != nil {
						log.Errorf("Pod: %s/%s, Container: %s, Image: %s, Language: %s\n",
							pod.Namespace, pod.Name, container.Name, container.Image, language)
					}
				}
				log.Info(nil, "Pod", pod.Name, "Namespace", pod.Namespace, "Container", container.Name, "Image", container.Image, "Language Detected", language)
			}
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
			language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd)
			if language == "Unknown" {
				language, err = detector.HardLanguageDetector(ctx, container.Image)
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
			language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd)
			if language == "Unknown" {
				language, err = detector.HardLanguageDetector(ctx, container.Image)
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
			language := detector.SoftLanguageDetector(container.Image, container.Env, execCmd)
			if language == "Unknown" {
				language, err = detector.HardLanguageDetector(ctx, container.Image)
				if err != nil {
					log.Errorf("DaemonSet: %s/%s, Container: %s, Image: %s, Language: %s\n",
						&daemonset.Namespace, &daemonset.Name, container.Name, container.Image, language)
				}
			}
			log.Info(nil, "DaemonSet", daemonset.Name, "Namespace", daemonset.Namespace, "Container", container.Name, "Image", container.Image, "Language Detected", language)

		}
	}
}
