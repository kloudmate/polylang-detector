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
	"go.uber.org/zap"

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

// DetectionResult represents the result of language detection
type DetectionResult struct {
	Language   string
	Framework  string
	Confidence string
	Evidence   []string
	Tier       string // Which detection tier found the result
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
	IgnoredNamespaces []string
	Queue             chan ContainerInfo
	QueueSize         int
	BatchMutex        sync.Mutex
	Cache             *LanguageCache
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
		Language:   "nodejs",
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

func (eld *PolylangDetector) getRuntimeEnvironmentVariables(namespace, podName, containerName string) (map[string]string, error) {
	envVars, err := eld.execCommandInPod(namespace, podName, containerName, []string{"env"})
	if err != nil {
		envVars, err = eld.execCommandInPod(namespace, podName, containerName, []string{"sh", "-c", "env"})
		if err != nil {
			return nil, fmt.Errorf("failed to get environment variables: %w", err)
		}
	}
	return eld.parseEnvOutput(envVars), nil
}

func (eld *PolylangDetector) execCommandInPod(namespace, podName, containerName string, command []string) (string, error) {
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

func (eld *PolylangDetector) parseEnvOutput(envOutput string) map[string]string {
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

func (eld *PolylangDetector) getProcessInfo(namespace, podName, containerName string) ([]string, error) {
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

func (eld *PolylangDetector) parseProcessOutput(processOutput string) []string {
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

func (eld *PolylangDetector) DetectLanguageWithRuntimeInfo(namespace, podName string) ([]ContainerInfo, error) {
	pod, err := eld.Clientset.CoreV1().Pods(namespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod: %w", err)
	}

	// Initialize inspectors
	metadataInspector := NewMetadataInspector(eld.Clientset)
	imageAnalyzer := &ImageAnalyzer{}
	runtimeInspector := &RuntimeInspector{}

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

		// Check cache first
		if cachedInfo, found := eld.Cache.Get(container.Image, info.EnvVars); found {
			eld.DomainLogger.CacheHit(container.Image, cachedInfo.Language)
			// Update pod-specific information
			cachedInfo.PodName = podName
			cachedInfo.Namespace = namespace
			cachedInfo.ContainerName = container.Name
			cachedInfo.DetectedAt = time.Now()

			// Get deployment name
			depName, err := getPodDeploymentName(eld.Clientset, namespace, podName)
			if err != nil {
				eld.DomainLogger.DeploymentInfoFailed(namespace, podName, err)
			} else {
				eld.DomainLogger.DeploymentInfoRetrieved(namespace, podName, depName, cachedInfo.Kind)
			}
			cachedInfo.DeploymentName = depName

			results = append(results, *cachedInfo)

			// Send to queue if supported
			_, ok := otelSupportedLanguages[cachedInfo.Language]
			if ok {
				eld.Queue <- *cachedInfo
			} else {
				eld.DomainLogger.UnsupportedLanguage(cachedInfo.Language)
			}
			continue
		}

		eld.DomainLogger.CacheMiss(container.Image)

		// ============================================
		// TIER 1: Kubernetes Metadata (Fast, No Exec)
		// ============================================
		var detectionResult DetectionResult

		// Check pod annotations first
		lang, fw, conf, evidence := metadataInspector.InspectPodAnnotations(pod)
		if lang != "" {
			detectionResult = DetectionResult{
				Language:   lang,
				Framework:  fw,
				Confidence: conf,
				Evidence:   evidence,
				Tier:       "metadata-annotations",
			}
		}

		// Check container environment variables from spec (no exec needed)
		if detectionResult.Language == "" {
			lang, evidence := metadataInspector.InspectEnvironmentVariables(container)
			if lang != "" {
				detectionResult = DetectionResult{
					Language:   lang,
					Confidence: "medium",
					Evidence:   evidence,
					Tier:       "metadata-envvars",
				}
			}
		}

		// ============================================
		// TIER 2: Image Name Analysis (Fast)
		// ============================================
		if detectionResult.Language == "" || detectionResult.Confidence == "low" {
			lang, fw, conf, evidence := imageAnalyzer.AnalyzeImageName(container.Image)
			if lang != "" && (detectionResult.Language == "" || conf == "high") {
				detectionResult = DetectionResult{
					Language:   lang,
					Framework:  fw,
					Confidence: conf,
					Evidence:   append(detectionResult.Evidence, evidence...),
					Tier:       "image-name",
				}
			}
		}

		// ============================================
		// TIER 3: Runtime Inspection (Slower, Requires Exec)
		// ============================================
		if detectionResult.Confidence != "high" {
			// Get runtime environment variables
			runtimeEnvVars, err := eld.getRuntimeEnvironmentVariables(namespace, podName, container.Name)
			if err == nil {
				for k, v := range runtimeEnvVars {
					info.EnvVars[k] = v
				}
			} else {
				errQueue = append(errQueue, fmt.Errorf("warning: could not get runtime env vars for %s/%s/%s: %v",
					namespace, podName, container.Name, err))
			}

			// Get process information
			processes, err := eld.getProcessInfo(namespace, podName, container.Name)
			if err == nil {
				info.ProcessCommands = processes

				// Analyze processes with enhanced pattern matching
				lang, fw, conf, evidence := runtimeInspector.AnalyzeProcesses(processes)
				if lang != "" && (detectionResult.Language == "" || conf == "high") {
					detectionResult = DetectionResult{
						Language:   lang,
						Framework:  fw,
						Confidence: conf,
						Evidence:   append(detectionResult.Evidence, evidence...),
						Tier:       "runtime-process",
					}
				}
			} else {
				errQueue = append(errQueue, fmt.Errorf("warning: could not get process info for %s/%s/%s: %v",
					namespace, podName, container.Name, err))
			}

			// Try filesystem signature detection if we still don't have high confidence
			// But don't override if we already have a medium/high confidence detection from earlier tiers
			if detectionResult.Confidence != "high" && detectionResult.Language == "" {
				lang, conf, evidence := runtimeInspector.DetectFileSystemSignatures(
					namespace, podName, container.Name, eld.execCommandInPod)
				if lang != "" {
					detectionResult = DetectionResult{
						Language:   lang,
						Confidence: conf,
						Evidence:   append(detectionResult.Evidence, evidence...),
						Tier:       "runtime-filesystem",
					}
				}
			}

			// Try package manager detection
			// Don't override if we already have a detection from earlier tiers
			if detectionResult.Confidence != "high" && detectionResult.Language == "" {
				lang, conf, evidence := runtimeInspector.DetectPackageManagers(
					namespace, podName, container.Name, eld.execCommandInPod)
				if lang != "" {
					detectionResult = DetectionResult{
						Language:   lang,
						Confidence: conf,
						Evidence:   append(detectionResult.Evidence, evidence...),
						Tier:       "runtime-package-manager",
					}
				}
			}

			// Try binary analysis
			// Don't override if we already have a detection from earlier tiers
			if detectionResult.Confidence != "high" && detectionResult.Language == "" {
				lang, conf, evidence := runtimeInspector.DetectBinarySignature(
					namespace, podName, container.Name, eld.execCommandInPod)
				if lang != "" {
					detectionResult = DetectionResult{
						Language:   lang,
						Confidence: conf,
						Evidence:   append(detectionResult.Evidence, evidence...),
						Tier:       "runtime-binary-analysis",
					}
				}
			}

			// Try port-based detection as last resort
			// Don't override if we already have a detection from earlier tiers
			if detectionResult.Confidence != "high" && detectionResult.Language == "" {
				lang, fw, conf, evidence := runtimeInspector.DetectByPort(
					namespace, podName, container.Name, eld.execCommandInPod)
				if lang != "" {
					detectionResult = DetectionResult{
						Language:   lang,
						Framework:  fw,
						Confidence: conf,
						Evidence:   append(detectionResult.Evidence, evidence...),
						Tier:       "runtime-port-detection",
					}
				}
			}
		}

		// ============================================
		// FALLBACK: Old detection method
		// ============================================
		if detectionResult.Language == "" {
			// Fall back to legacy detection
			if len(errQueue) > 0 {
				detectionResult.Language, _ = HardLanguageDetector(container.Image)
				detectionResult.Confidence = "low"
				detectionResult.Tier = "fallback-hard-detector"
			} else {
				language, framework, confidence, evidence := eld.detectAdvancedLanguage(
					container.Image, info.EnvVars, info.ProcessCommands)
				detectionResult = DetectionResult{
					Language:   language,
					Framework:  framework,
					Confidence: confidence,
					Evidence:   evidence,
					Tier:       "fallback-advanced",
				}
			}
		}

		// Apply detection result to container info
		info.Language = detectionResult.Language
		info.Framework = detectionResult.Framework
		info.Confidence = detectionResult.Confidence
		info.Evidence = detectionResult.Evidence
		depName, err := getPodDeploymentName(eld.Clientset, namespace, podName)
		if err != nil {
			eld.DomainLogger.DeploymentInfoFailed(namespace, podName, err)
		} else {
			eld.DomainLogger.DeploymentInfoRetrieved(namespace, podName, depName, info.Kind)
		}
		// info.Enabled = IsResourceInstrumented(eld.Clientset, namespace, info.Kind, depName)
		info.DeploymentName = depName

		// Store in cache for future lookups
		eld.Cache.Set(container.Image, info.EnvVars, info)
		eld.DomainLogger.CacheStored(container.Image, info.Language)

		// Log detection result with tier information
		if tierLogger, ok := eld.DomainLogger.(interface {
			LanguageDetectedWithTier(namespace, podName, containerName, image, language, framework, confidence, tier string)
		}); ok {
			tierLogger.LanguageDetectedWithTier(namespace, podName, container.Name, container.Image, info.Language, info.Framework, info.Confidence, detectionResult.Tier)
		} else {
			eld.DomainLogger.LanguageDetected(namespace, podName, container.Name, container.Image, info.Language, info.Framework, info.Confidence)
		}

		results = append(results, info)
		_, ok := otelSupportedLanguages[info.Language]
		if ok {
			// Send the result to the queue for batching
			eld.Queue <- info
		} else {
			eld.DomainLogger.UnsupportedLanguage(info.Language)
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

func (eld *PolylangDetector) detectAdvancedLanguage(image string, envVars map[string]string, processes []string) (string, string, string, []string) {
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

	// --- OPTIONAL: Go binary scan is now a fallback check (disabled by default) ---
	// Only perform this check if:
	// 1. No other language could be confidently identified
	// 2. KM_ENABLE_IMAGE_INSPECTION environment variable is set to "true"
	//
	// Note: Image inspection requires pulling container images, which needs:
	// - Public images: No credentials needed
	// - Private registries (ECR/GCR/ACR): Requires cloud provider credentials
	//
	// To enable: Set KM_ENABLE_IMAGE_INSPECTION=true and configure registry credentials
	enableImageInspection := os.Getenv("KM_ENABLE_IMAGE_INSPECTION") == "true"

	if len(candidates) == 0 && enableImageInspection {
		inspector := &ImageInspector{}
		isGo, evidenceFromScan, err := inspector.isGoBinary(image)
		if err != nil {
			// Skip image inspection errors for private registries or inaccessible images
			eld.Logger.Debug("Image layer inspection failed",
				zap.String("image", image),
				zap.String("reason", "image_pull_failed"),
				zap.Error(err),
			)
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

func (eld *PolylangDetector) extractVersion(envVars map[string]string, language string) string {
	versionKeys := map[string][]string{
		"Java":   {"JAVA_VERSION", "JDK_VERSION", "OPENJDK_VERSION"},
		"nodejs": {"NODE_VERSION", "NPM_VERSION"},
		"Python": {"PYTHON_VERSION", "PY_VERSION"},
		"Go":     {"GO_VERSION", "GOLANG_VERSION"},
		"Ruby":   {"RUBY_VERSION", "RBENV_VERSION"},
		"PHP":    {"PHP_VERSION"},
		"Rust":   {"RUST_VERSION", "RUSTC_VERSION"},
		".NET":   {"DOTNET_VERSION", "ASPNETCORE_VERSION"},
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
	nsEnv := string(os.Getenv("KM_IGNORED_NS"))
	ignoredNs := strings.Split(nsEnv, ",")
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
		Clientset:         client,
		Config:            config,
		IgnoredNamespaces: ignoredNs,
		ServerAddr:        addr,
		Logger:            logger,
		DomainLogger:      domainLogger,
		Queue:             make(chan ContainerInfo, 100), // Queue with a capacity of 100
		QueueSize:         5,                             // Batch size
		Cache:             NewLanguageCache(cacheTTL),
	}
}

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
