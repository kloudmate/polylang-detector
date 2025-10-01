package detector

import (
	"regexp"
	"strings"
)

// ImageAnalyzer provides image name and metadata analysis
type ImageAnalyzer struct{}

// ImagePattern represents patterns to match in image names
type ImagePattern struct {
	Language   string
	Framework  string
	Patterns   []string
	Priority   int
	Confidence string
}

var imagePatterns = []ImagePattern{
	// Official language images
	{
		Language:   "nodejs",
		Patterns:   []string{"node:", "nodejs:"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Python",
		Patterns:   []string{"python:", "pypy:"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Java",
		Patterns:   []string{"openjdk:", "java:", "eclipse-temurin:", "amazoncorretto:"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Go",
		Patterns:   []string{"golang:", "go:"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Ruby",
		Patterns:   []string{"ruby:", "jruby:"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   ".NET",
		Patterns:   []string{"dotnet:", "mcr.microsoft.com/dotnet", "aspnet:"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "PHP",
		Patterns:   []string{"php:", "php-fpm:"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Rust",
		Patterns:   []string{"rust:"},
		Priority:   10,
		Confidence: "high",
	},

	// Framework-specific images
	{
		Language:   "Java",
		Framework:  "Spring Boot",
		Patterns:   []string{"spring-boot", "springboot"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "Java",
		Framework:  "Tomcat",
		Patterns:   []string{"tomcat:"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "nodejs",
		Framework:  "Next.js",
		Patterns:   []string{"nextjs:", "next-app:"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "Python",
		Framework:  "Django",
		Patterns:   []string{"django:"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "Ruby",
		Framework:  "Rails",
		Patterns:   []string{"rails:"},
		Priority:   15,
		Confidence: "high",
	},

	// Common base images (lower confidence)
	{
		Language:   "Go",
		Patterns:   []string{"alpine", "scratch", "distroless/static"},
		Priority:   3,
		Confidence: "low",
	},

	// Database and service images
	{
		Language:   "MongoDB",
		Framework:  "Database",
		Patterns:   []string{"mongo:", "mongodb:", "bitnami/mongodb"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "PostgreSQL",
		Framework:  "Database",
		Patterns:   []string{"postgres:", "postgresql:", "bitnami/postgresql"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "MySQL",
		Framework:  "Database",
		Patterns:   []string{"mysql:", "mariadb:", "bitnami/mysql"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "Redis",
		Framework:  "Cache",
		Patterns:   []string{"redis:", "bitnami/redis"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "Elasticsearch",
		Framework:  "Search",
		Patterns:   []string{"elasticsearch:", "elastic/elasticsearch"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "Nginx",
		Framework:  "Web Server",
		Patterns:   []string{"nginx:", "bitnami/nginx"},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language:   "Apache",
		Framework:  "Web Server",
		Patterns:   []string{"httpd:", "apache:", "bitnami/apache"},
		Priority:   15,
		Confidence: "high",
	},
}

// AnalyzeImageName extracts language and framework information from image name
func (ia *ImageAnalyzer) AnalyzeImageName(image string) (string, string, string, []string) {
	imageLower := strings.ToLower(image)
	var evidence []string
	bestMatch := struct {
		language   string
		framework  string
		confidence string
		priority   int
	}{}

	for _, pattern := range imagePatterns {
		for _, patternStr := range pattern.Patterns {
			if strings.Contains(imageLower, patternStr) {
				evidence = append(evidence, "Image name pattern: "+patternStr)
				if pattern.Priority > bestMatch.priority {
					bestMatch.language = pattern.Language
					bestMatch.framework = pattern.Framework
					bestMatch.confidence = pattern.Confidence
					bestMatch.priority = pattern.Priority
				}
			}
		}
	}

	if bestMatch.language != "" {
		return bestMatch.language, bestMatch.framework, bestMatch.confidence, evidence
	}

	return "", "", "", evidence
}

// ExtractVersionFromImage attempts to extract version from image tag
func (ia *ImageAnalyzer) ExtractVersionFromImage(image string) string {
	// Pattern to match common version formats in image tags
	patterns := []string{
		`:([\d]+\.[\d]+\.[\d]+)`,      // :1.2.3
		`:([\d]+\.[\d]+)`,              // :1.2
		`-v([\d]+\.[\d]+\.[\d]+)`,      // -v1.2.3
		`-([\d]+\.[\d]+\.[\d]+)-`,      // -1.2.3-
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(image)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

// IsApplicationImage determines if an image is likely an application vs infrastructure
func (ia *ImageAnalyzer) IsApplicationImage(image string) bool {
	imageLower := strings.ToLower(image)

	// Infrastructure/system images (not applications)
	infraPatterns := []string{
		"nginx", "apache", "httpd",
		"envoy", "haproxy", "traefik",
		"prometheus", "grafana",
		"fluentd", "fluent-bit",
		"istio", "linkerd",
		"busybox", "alpine",
	}

	for _, pattern := range infraPatterns {
		if strings.Contains(imageLower, pattern) {
			return false
		}
	}

	return true
}

// DetectPrivateRegistry identifies if image is from a private registry
func (ia *ImageAnalyzer) DetectPrivateRegistry(image string) (bool, string) {
	imageLower := strings.ToLower(image)

	registries := map[string]string{
		"ecr":               "AWS ECR",
		".amazonaws.com":    "AWS ECR",
		"gcr.io":            "Google GCR",
		"azurecr.io":        "Azure ACR",
		"registry.gitlab":   "GitLab Registry",
		"ghcr.io":           "GitHub Registry",
		"quay.io":           "Quay.io",
		"docker.pkg.github": "GitHub Packages",
	}

	for pattern, name := range registries {
		if strings.Contains(imageLower, pattern) {
			return true, name
		}
	}

	// Check if it's not from Docker Hub (no domain = Docker Hub)
	if !strings.Contains(image, "/") || strings.Count(image, "/") == 1 {
		return false, "Docker Hub"
	}

	// Has a domain but not recognized = likely private
	parts := strings.Split(image, "/")
	if len(parts) > 0 && strings.Contains(parts[0], ".") {
		return true, "Private Registry"
	}

	return false, "Docker Hub"
}
