package detector

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// MetadataInspector analyzes Kubernetes metadata for language hints
type MetadataInspector struct {
	clientset *kubernetes.Clientset
}

// NewMetadataInspector creates a new metadata inspector
func NewMetadataInspector(clientset *kubernetes.Clientset) *MetadataInspector {
	return &MetadataInspector{
		clientset: clientset,
	}
}

// InspectPodAnnotations checks pod annotations for language hints
func (mi *MetadataInspector) InspectPodAnnotations(pod *corev1.Pod) (string, string, string, []string) {
	var evidence []string

	annotations := pod.Annotations
	if annotations == nil {
		return "", "", "", evidence
	}

	// Check standard Kubernetes app annotations
	standardKeys := []string{
		"app.kubernetes.io/language",
		"app.kubernetes.io/runtime",
		"app.kubernetes.io/framework",
	}

	for _, key := range standardKeys {
		if val, exists := annotations[key]; exists && val != "" {
			evidence = append(evidence, "Annotation: "+key+"="+val)

			// Try to determine language/framework
			valLower := strings.ToLower(val)
			if strings.Contains(valLower, "java") || strings.Contains(valLower, "spring") {
				return "Java", mi.extractFramework(val), "high", evidence
			} else if strings.Contains(valLower, "node") || strings.Contains(valLower, "javascript") {
				return "nodejs", mi.extractFramework(val), "high", evidence
			} else if strings.Contains(valLower, "python") || strings.Contains(valLower, "django") || strings.Contains(valLower, "flask") {
				return "Python", mi.extractFramework(val), "high", evidence
			} else if strings.Contains(valLower, "ruby") || strings.Contains(valLower, "rails") {
				return "Ruby", mi.extractFramework(val), "high", evidence
			} else if strings.Contains(valLower, "go") || strings.Contains(valLower, "golang") {
				return "Go", "", "high", evidence
			} else if strings.Contains(valLower, "dotnet") || strings.Contains(valLower, ".net") || strings.Contains(valLower, "csharp") {
				return ".NET", "", "high", evidence
			} else if strings.Contains(valLower, "php") {
				return "PHP", mi.extractFramework(val), "high", evidence
			}
		}
	}

	return "", "", "", evidence
}

// extractFramework attempts to extract framework name from annotation value
func (mi *MetadataInspector) extractFramework(value string) string {
	frameworks := map[string]string{
		"spring":    "Spring Boot",
		"express":   "Express",
		"nextjs":    "Next.js",
		"next":      "Next.js",
		"nestjs":    "NestJS",
		"django":    "Django",
		"flask":     "Flask",
		"fastapi":   "FastAPI",
		"rails":     "Rails",
		"sinatra":   "Sinatra",
		"laravel":   "Laravel",
		"symfony":   "Symfony",
		"aspnet":    "ASP.NET Core",
		"quarkus":   "Quarkus",
		"micronaut": "Micronaut",
	}

	valueLower := strings.ToLower(value)
	for key, framework := range frameworks {
		if strings.Contains(valueLower, key) {
			return framework
		}
	}

	return ""
}

// normalizeLanguage converts various language names to standardized form
func (mi *MetadataInspector) normalizeLanguage(value string) string {
	valueLower := strings.ToLower(value)

	languageMap := map[string]string{
		"javascript": "nodejs",
		"node":       "nodejs",
		"nodejs":     "nodejs",
		"python":     "Python",
		"py":         "Python",
		"java":       "Java",
		"golang":     "Go",
		"go":         "Go",
		"ruby":       "Ruby",
		"rb":         "Ruby",
		"php":        "PHP",
		"dotnet":     ".NET",
		"csharp":     ".NET",
		"c#":         ".NET",
		"rust":       "Rust",
	}

	for key, normalized := range languageMap {
		if strings.Contains(valueLower, key) {
			return normalized
		}
	}

	return value
}

// InspectEnvironmentVariables checks container env vars for language-specific variables
func (mi *MetadataInspector) InspectEnvironmentVariables(container corev1.Container) (string, []string) {
	var evidence []string

	for _, env := range container.Env {
		envName := strings.ToUpper(env.Name)

		// Java indicators
		if strings.HasPrefix(envName, "JAVA_") || envName == "CLASSPATH" || envName == "CATALINA_HOME" {
			evidence = append(evidence, "Env var: "+env.Name)
			return "Java", evidence
		}

		// Node.js indicators
		if strings.HasPrefix(envName, "NODE_") || strings.HasPrefix(envName, "NPM_") || envName == "NODE_ENV" {
			evidence = append(evidence, "Env var: "+env.Name)
			return "nodejs", evidence
		}

		// Python indicators
		if strings.HasPrefix(envName, "PYTHON") || envName == "PYTHONPATH" || strings.HasPrefix(envName, "DJANGO_") {
			evidence = append(evidence, "Env var: "+env.Name)
			return "Python", evidence
		}

		// Go indicators
		if strings.HasPrefix(envName, "GO") {
			evidence = append(evidence, "Env var: "+env.Name)
			return "Go", evidence
		}

		// Ruby indicators
		if strings.HasPrefix(envName, "RUBY_") || strings.HasPrefix(envName, "RAILS_") || envName == "RBENV_VERSION" {
			evidence = append(evidence, "Env var: "+env.Name)
			return "Ruby", evidence
		}

		// .NET indicators
		if strings.HasPrefix(envName, "DOTNET_") || strings.HasPrefix(envName, "ASPNETCORE_") {
			evidence = append(evidence, "Env var: "+env.Name)
			return ".NET", evidence
		}

		// PHP indicators
		if strings.HasPrefix(envName, "PHP_") {
			evidence = append(evidence, "Env var: "+env.Name)
			return "PHP", evidence
		}
	}

	return "", evidence
}
