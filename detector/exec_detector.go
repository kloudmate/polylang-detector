package detector

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/rpc"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

// LanguageDetectionRule defines a rule for detecting a programming language.
type LanguageDetectionRule struct {
	Language      string
	Confidence    string
	Priority      int
	ImagePatterns []string
	EnvVars       []string
	Commands      []string
	Frameworks    map[string][]string
}

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

// ExecDetector contains the Kubernetes client to interact with the cluster.
type ExecDetector struct {
	Clientset  *kubernetes.Clientset
	Config     *rest.Config
	RpcClient  *rpc.Client
	Queue      chan ContainerInfo
	QueueSize  int
	BatchMutex sync.Mutex
}

// ImageInspector provides methods for investigating container images.
type ImageInspector struct{}

// isGoBinary checks an image for the presence of a Go binary signature.
func (ii *ImageInspector) isGoBinary(imageRef string) (bool, []string, error) {
	var evidence []string

	// Pull the image layers using crane
	img, err := crane.Pull(imageRef)
	if err != nil {
		return false, nil, fmt.Errorf("failed to pull image: %w", err)
	}

	layers, err := img.Layers()
	if err != nil {
		return false, nil, fmt.Errorf("failed to get image layers: %w", err)
	}

	for _, layer := range layers {
		// Get the compressed reader for the layer
		rc, err := layer.Compressed()
		if err != nil {
			log.Printf("Warning: Failed to get compressed reader for layer: %v", err)
			continue
		}
		defer rc.Close()

		// Use the tarReader to iterate through files in the layer
		// and check for the "go1." signature.
		tarReader := tar.NewReader(rc)

		isGo, err := ii.scanTarForGoSignature(tarReader)
		if err != nil {
			log.Printf("Warning: Failed to scan tar for Go signature: %v", err)
			continue
		}
		if isGo {
			evidence = append(evidence, "Image layer contains 'go1.' binary signature")
			return true, evidence, nil
		}
	}

	return false, nil, nil
}

// scanTarForGoSignature scans a tarball for files containing the "go1." signature.
func (ii *ImageInspector) scanTarForGoSignature(tarReader *tar.Reader) (bool, error) {
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of tarball
		}
		if err != nil {
			return false, err
		}

		// Check if it's a regular file and has some content
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			// Read file content and search for the signature
			content := make([]byte, 1024)
			if _, err := tarReader.Read(content); err != nil && err != io.EOF {
				return false, err
			}

			if bytes.Contains(content, []byte("go1.")) {
				return true, nil
			}
		}
	}

	return false, nil
}

// All language detection rules.
var advancedLanguageRules = []LanguageDetectionRule{
	{
		Language:   "Ruby",
		Confidence: "medium",
		Priority:   5,
		ImagePatterns: []string{
			"ruby",
		},
		EnvVars: []string{
			"RUBY_VERSION",
			"RBENV_VERSION",
		},
		Commands: []string{
			"ruby",
			"rails",
		},
		Frameworks: map[string][]string{
			"Rails":   {"rails"},
			"Sinatra": {"sinatra"},
		},
	},
	{
		Language:   "Node.js",
		Confidence: "medium",
		Priority:   5,
		ImagePatterns: []string{
			"node",
			"nodejs",
		},
		EnvVars: []string{
			"NODE_ENV",
			"NODE_VERSION",
		},
		Commands: []string{
			"node",
			"npm",
		},
		Frameworks: map[string][]string{
			"Express": {"express"},
			"Next.js": {"next start"},
			"NestJS":  {"nest start"},
		},
	},
	{
		Language:   "Python",
		Confidence: "medium",
		Priority:   5,
		ImagePatterns: []string{
			"python",
			"pypy",
		},
		EnvVars: []string{
			"PYTHONPATH",
			"PYTHON_VERSION",
		},
		Commands: []string{
			"python",
			"gunicorn",
		},
		Frameworks: map[string][]string{
			"Django": {"django"},
			"Flask":  {"flask"},
		},
	},
	{
		Language:   "Go",
		Confidence: "high",
		Priority:   10,
		ImagePatterns: []string{
			"golang",
			"go-build",
			"gcr.io/distroless/static",
			"scratch",
			"alpine",
		},
		EnvVars: []string{
			"GOOS",
			"GOARCH",
			"GOPATH",
		},
		Commands: []string{
			"/app/app",
			"go-app",
		},
	},
	{
		Language:   "Java",
		Confidence: "medium",
		Priority:   5,
		ImagePatterns: []string{
			"java",
			"openjdk",
			"jre",
			"tomcat",
		},
		EnvVars: []string{
			"JAVA_HOME",
			"JAVA_VERSION",
		},
		Commands: []string{
			"java",
			"javac",
		},
		Frameworks: map[string][]string{
			"Spring Boot": {"spring-boot-app.jar"},
			"Micronaut":   {"micronaut"},
			"Quarkus":     {"quarkus"},
		},
	},
	{
		Language:   ".NET",
		Confidence: "medium",
		Priority:   5,
		ImagePatterns: []string{
			"dotnet",
			"mcr.microsoft.com/dotnet",
		},
		EnvVars: []string{
			"DOTNET_RUNNING_IN_CONTAINER",
			"ASPNETCORE_URLS",
		},
		Commands: []string{
			"dotnet",
		},
	},
	{
		Language:   "PHP",
		Confidence: "medium",
		Priority:   5,
		ImagePatterns: []string{
			"php",
			"nginx",
		},
		EnvVars: []string{
			"PHP_VERSION",
		},
		Commands: []string{
			"php-fpm",
		},
		Frameworks: map[string][]string{
			"Laravel": {"artisan"},
			"Symfony": {"bin/console"},
		},
	},
}

func (eld *ExecDetector) getRuntimeEnvironmentVariables(namespace, podName, containerName string) (map[string]string, error) {
	envVars, err := eld.execCommandInPod(namespace, podName, containerName, []string{"env"})
	if err != nil {
		envVars, err = eld.execCommandInPod(namespace, podName, containerName, []string{"sh", "-c", "env"})
		if err != nil {
			return nil, fmt.Errorf("failed to get environment variables: %w", err)
		}
	}
	return eld.parseEnvOutput(envVars), nil
}

func (eld *ExecDetector) execCommandInPod(namespace, podName, containerName string, command []string) (string, error) {
	req := eld.Clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespace).
		SubResource("exec")

	req.VersionedParams(&corev1.PodExecOptions{
		Command:   command,
		Container: containerName,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false,
	}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(eld.Config, "POST", req.URL())
	if err != nil {
		return "", err
	}

	var stdout, stderr bytes.Buffer
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		return "", fmt.Errorf("exec error: %w, stderr: %s", err, stderr.String())
	}
	return stdout.String(), nil
}

func (eld *ExecDetector) parseEnvOutput(envOutput string) map[string]string {
	envVars := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(envOutput), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			envVars[parts[0]] = parts[1]
		}
	}
	return envVars
}

func (eld *ExecDetector) getProcessInfo(namespace, podName, containerName string) ([]string, error) {
	processes, err := eld.execCommandInPod(namespace, podName, containerName, []string{"ps", "aux"})
	if err != nil {
		processes, err = eld.execCommandInPod(namespace, podName, containerName, []string{"ps", "-ef"})
		if err != nil {
			processes, err = eld.execCommandInPod(namespace, podName, containerName, []string{"sh", "-c", "ps"})
			if err != nil {
				return nil, fmt.Errorf("failed to get process information: %w", err)
			}
		}
	}
	return eld.parseProcessOutput(processes), nil
}

func (eld *ExecDetector) parseProcessOutput(processOutput string) []string {
	var commands []string
	lines := strings.Split(strings.TrimSpace(processOutput), "\n")
	for i, line := range lines {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			command := fields[len(fields)-1]
			commands = append(commands, command)
		}
	}
	return commands
}

func (eld *ExecDetector) DetectLanguageWithRuntimeInfo(namespace, podName string) ([]ContainerInfo, error) {
	pod, err := eld.Clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	var results []ContainerInfo
	var errQueue []error
	for _, container := range pod.Spec.Containers {
		ownerRef := metav1.GetControllerOf(pod)
		var oKind string
		if ownerRef == nil {
			oKind = "Pod"
		} else {
			oKind = ownerRef.Kind
		}
		info := ContainerInfo{
			PodName:       podName,
			Namespace:     namespace,
			ContainerName: container.Name,
			Image:         container.Image,
			Kind:          oKind,
			EnvVars:       make(map[string]string),
			DetectedAt:    time.Now(),
		}

		for _, env := range container.Env {
			if env.Value != "" {
				info.EnvVars[env.Name] = env.Value
			}
		}

		runtimeEnvVars, err := eld.getRuntimeEnvironmentVariables(namespace, podName, container.Name)
		if err != nil {
			// log.Printf("Warning: Could not get runtime env vars for %s/%s/%s: %v",
			// 	namespace, podName, container.Name, err)
			errQueue = append(errQueue, fmt.Errorf("warning: could not get runtime env vars for %s/%s/%s: %v",
				namespace, podName, container.Name, err))

		} else {
			for k, v := range runtimeEnvVars {
				info.EnvVars[k] = v
			}
		}

		processes, err := eld.getProcessInfo(namespace, podName, container.Name)
		if err != nil {
			// log.Printf("Warning: Could not get process info for %s/%s/%s: %v",
			// 	namespace, podName, container.Name, err)
			errQueue = append(errQueue, fmt.Errorf("warning: could not get process info for %s/%s/%s: %v",
				namespace, podName, container.Name, err))
		} else {
			info.ProcessCommands = processes
		}
		if len(errQueue) > 0 {

			info.Language, _ = HardLanguageDetector(container.Image)
			results = append(results, info)
		} else {

			language, framework, confidence, evidence := eld.detectAdvancedLanguage(
				container.Image, info.EnvVars, info.ProcessCommands)

			info.Language = language
			info.Framework = framework
			info.Confidence = confidence
			info.Evidence = evidence
		}
		depName, err := getPodDeploymentName(eld.Clientset, namespace, podName)
		if err != nil {
			log.Printf("warning: could not get pod deplyment name for pod : %s ns:%s err: %v",
				podName, namespace, err)

		}
		info.Enabled = IsResourceInstrumented(eld.Clientset, namespace, info.Kind, depName)
		info.DeploymentName = depName
		results = append(results, info)
		_, ok := otelSupportedLanguages[info.Language]
		if ok {
			// Send the result to the queue for batching
			eld.Queue <- info
		} else {
			log.Printf("we currently don't have auto instrumentaion support for : %s Language", info.Language)
		}

	}
	return results, nil
}

func IsResourceInstrumented(client *kubernetes.Clientset, ns, kind, name string) bool {
	k := strings.ToUpper(kind)
	crd := os.Getenv("KM_CRD_NAME")
	if crd == "" {
		crd = "km-agent-instrumentation-crd"
	}
	switch k {
	case "DAEMONSET":
		cfg, err := client.AppsV1().DaemonSets(ns).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			log.Printf("failed to fetch daemonset in namespace %s: %v", ns, err)
		}
		return isOtelInstrumented(cfg.Spec.Template.Annotations, ns, crd)
	case "DEPLOYMENT":
		cfg, err := client.AppsV1().Deployments(ns).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			log.Printf("failed to fetch deployment in namespace %s: %v", ns, err)
		}
		return isOtelInstrumented(cfg.Spec.Template.Annotations, ns, crd)
	case "STATEFULSET":
		cfg, err := client.AppsV1().StatefulSets(ns).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			log.Printf("failed to fetch stateful in namespace %s: %v", ns, err)
		}
		return isOtelInstrumented(cfg.Spec.Template.Annotations, ns, crd)

	}
	return false
}

func (eld *ExecDetector) detectAdvancedLanguage(image string, envVars map[string]string, processes []string) (string, string, string, []string) {
	var candidates []struct {
		language   string
		framework  string
		confidence string
		priority   int
		evidence   []string
	}
	imageLower := strings.ToLower(image)

	// Convert processes to lowercase string for pattern matching
	processString := strings.ToLower(strings.Join(processes, " "))

	// --- FIX: Logic to prioritize lightweight checks before a Go binary scan. ---
	// Run the rule-based detection first for all languages.
	for _, rule := range advancedLanguageRules {
		var ruleEvidence []string
		matched := false
		priority := rule.Priority

		// Check image patterns
		for _, pattern := range rule.ImagePatterns {
			if matched, _ := regexp.MatchString(pattern, imageLower); matched {
				ruleEvidence = append(ruleEvidence, fmt.Sprintf("Image pattern: %s", pattern))
				matched = true
				priority += 3
				break
			}
		}

		// Check environment variables
		for _, envVar := range rule.EnvVars {
			if value, exists := envVars[envVar]; exists {
				ruleEvidence = append(ruleEvidence, fmt.Sprintf("Environment variable: %s=%s", envVar, value))
				matched = true
				priority += 2
			}
		}

		// Check process commands
		for _, cmd := range rule.Commands {
			if strings.Contains(processString, cmd) {
				ruleEvidence = append(ruleEvidence, fmt.Sprintf("Process command: %s", cmd))
				matched = true
				priority += 2
			}
		}

		// Detect version
		version := eld.extractVersion(envVars, rule.Language)
		if version != "" {
			ruleEvidence = append(ruleEvidence, fmt.Sprintf("Version detected: %s", version))
			priority += 1
		}

		// Check for frameworks
		framework := ""
		for fw, patterns := range rule.Frameworks {
			for _, pattern := range patterns {
				if strings.Contains(imageLower, pattern) || strings.Contains(processString, pattern) {
					framework = fw
					ruleEvidence = append(ruleEvidence, fmt.Sprintf("Framework detected: %s", fw))
					priority += 1
					break
				}
			}
			if framework != "" {
				break
			}
		}

		if matched {
			candidates = append(candidates, struct {
				language   string
				framework  string
				confidence string
				priority   int
				evidence   []string
			}{
				language:   rule.Language,
				framework:  framework,
				confidence: rule.Confidence,
				priority:   priority,
				evidence:   ruleEvidence,
			})
		}
	}

	// --- FIX: Go binary scan is now a fallback check. ---
	// Only perform this check if no other language could be confidently identified.
	if len(candidates) == 0 {
		inspector := &ImageInspector{}
		isGo, evidenceFromScan, err := inspector.isGoBinary(image)
		if err != nil {
			log.Printf("Warning: Failed to inspect image layers for Go signature: %v", err)
		} else if isGo {
			// If a Go binary is found, create a high-priority candidate for it.
			candidates = append(candidates, struct {
				language   string
				framework  string
				confidence string
				priority   int
				evidence   []string
			}{
				language:   "Go",
				framework:  "",
				confidence: "high",
				priority:   15, // Highest priority
				evidence:   evidenceFromScan,
			})
		}
	}

	if len(candidates) == 0 {
		return "Unknown", "", "low", []string{"No clear language indicators found"}
	}

	// Sort by priority and return the best match
	bestCandidate := candidates[0]
	for _, candidate := range candidates[1:] {
		if candidate.priority > bestCandidate.priority {
			bestCandidate = candidate
		}
	}
	return bestCandidate.language, bestCandidate.framework, bestCandidate.confidence, bestCandidate.evidence
}

func (eld *ExecDetector) extractVersion(envVars map[string]string, language string) string {
	versionKeys := map[string][]string{
		"Java":    {"JAVA_VERSION", "JDK_VERSION", "OPENJDK_VERSION"},
		"Node.js": {"NODE_VERSION", "NPM_VERSION"},
		"Python":  {"PYTHON_VERSION", "PY_VERSION"},
		"Go":      {"GO_VERSION", "GOLANG_VERSION"},
		"Ruby":    {"RUBY_VERSION", "RBENV_VERSION"},
		"PHP":     {"PHP_VERSION"},
		"Rust":    {"RUST_VERSION", "RUSTC_VERSION"},
		".NET":    {"DOTNET_VERSION", "ASPNETCORE_VERSION"},
	}

	if keys, exists := versionKeys[language]; exists {
		for _, key := range keys {
			if version, found := envVars[key]; found {
				return version
			}
		}
	}
	return ""
}

func NewExecDetector(config *rest.Config, client *kubernetes.Clientset) *ExecDetector {
	return &ExecDetector{
		Clientset: client,
		Config:    config,
		Queue:     make(chan ContainerInfo, 100), // Queue with a capacity of 100
		QueueSize: 5,                             // Batch size

	}
}

func (eld *ExecDetector) SendBatch(batch []ContainerInfo) {
	var reply string
	err := eld.RpcClient.Call("RPCHandler.PushDetectionResults", batch, &reply)
	if err != nil {
		if err == rpc.ErrShutdown {
			log.Printf("RPC server is shutdown : Attempting to reconnect")
			if eld.ConnectWithRetry() {
				// reconnected with the server retry to send the batch
				eld.SendBatch(batch)
			}
		}
		log.Printf("Error sending batch via RPC: %v", err)
		return
	}
	log.Printf("RPC call successful: %s", reply)
}

// ConnectWithRetry attempts to establish an RPC connection with exponential backoff.
func (eld *ExecDetector) ConnectWithRetry() bool {
	var err error
	for i := 0; i < 15; i++ {
		eld.RpcClient, err = rpc.Dial("tcp", os.Getenv("KM_CFG_UPDATER_RPC_ADDR"))
		if err == nil {
			log.Println("Successfully reconnected to RPC server.")
			return true
		}
		log.Printf("Reconnection attempt %d failed: %v", i+1, err)
		time.Sleep(time.Duration(i+1) * time.Second) // Exponential backoff
	}
	log.Println("Max reconnection attempts reached. Rpc Client will remain disconnected.")
	return false
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

func isOtelInstrumented(annotations map[string]string, ns, crd string) bool {
	for k, v := range annotations {
		if strings.HasPrefix(k, "instrumentation.opentelemetry.io/inject-") && !strings.HasPrefix(v, "false") ||
			strings.HasPrefix(k, "instrumentation.opentelemetry.io/inject-") && strings.HasPrefix(v, fmt.Sprintf("%s/%s", ns, crd)) {
			return true
		} else {
			fmt.Print("Not Instrumented")
		}
	}
	return false
}
