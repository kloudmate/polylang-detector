package workload

import (
	"fmt"
	"log"
	"os"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// getClientSet creates a Kubernetes client based on the running environment.
// It prioritizes in-cluster configuration but falls back to a local kubeconfig file.
func GetClientSet() (*kubernetes.Clientset, *rest.Config, error) {
	// Try to create a clientset from in-cluster config (Service Account).
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Println("Warning: Could not create in-cluster config. Falling back to local kubeconfig.")
		// Fallback to local kubeconfig.
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			kubeconfigPath = clientcmd.RecommendedHomeFile
		}

		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, nil, fmt.Errorf("could not build kubeconfig: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, nil, fmt.Errorf("could not create clientset: %w", err)
	}
	return clientset, config, nil
}
