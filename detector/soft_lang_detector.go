package detector

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// SoftLanguageDetector infers the programming language from a container's exec command,
// image name, or environment variables.
// This is a best-effort approach based on common keywords.
func SoftLanguageDetector(image string, envVars []corev1.EnvVar, execCmd []string, container corev1.Container) string {
	if len(execCmd) > 0 {
		lowerCmd := strings.ToLower(execCmd[0])
		if strings.Contains(lowerCmd, "python") {
			return "Python"
		}
		if strings.Contains(lowerCmd, "node") || strings.Contains(lowerCmd, "npm") {
			return "Node.js"
		}
		if strings.Contains(lowerCmd, "java") {
			return "Java"
		}
		if strings.Contains(lowerCmd, "dotnet") {
			return ".NET"
		}
		if strings.Contains(lowerCmd, "go") {
			return "Go"
		}
		// Fallback check for Go: look for a .go file in the arguments.
		// This is a more specific and reliable heuristic than a generic binary name.
	}

	lowerImage := strings.ToLower(image)

	// check for keywords in the image name.
	imageKeywords := map[string]string{
		"golang":                   "Go",
		"node":                     "Node.js",
		"python":                   "Python",
		"openjdk":                  "Java",
		"java":                     "Java",
		"mcr.microsoft.com/dotnet": "dotnet",
	}

	for keyword, language := range imageKeywords {
		if strings.Contains(lowerImage, keyword) {
			return language
		}
	}

	for _, envVar := range envVars {
		for keyword, language := range envVarKeywords {
			if strings.HasPrefix(strings.ToUpper(envVar.Name), keyword) {
				return language
			}
		}
	}

	return "Unknown"
}
