package detector

import (
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// SoftLanguageDetector infers the programming language from a container's exec command,
// image name, or environment variables.
// This is a best-effort approach based on common keywords.
func SoftLanguageDetector(image string, envVars []corev1.EnvVar, execCmd []string) string {
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
		for _, arg := range execCmd {
			if strings.HasSuffix(strings.ToLower(arg), ".go") {
				return "Go"
			}
		}
	}

	lowerImage := strings.ToLower(image)

	// check for keywords in the image name.
	imageKeywords := map[string]string{
		"golang":                   "Go",
		"node":                     "Node.js",
		"python":                   "Python",
		"openjdk":                  "Java",
		"java":                     "Java",
		"alpine":                   "Base Image (Alpine Linux)",
		"ubuntu":                   "Base Image (Ubuntu Linux)",
		"busybox":                  "Base Image (BusyBox)",
		"mcr.microsoft.com/dotnet": "dotnet",
	}

	for keyword, language := range imageKeywords {
		if strings.Contains(lowerImage, keyword) {
			return language
		}
	}

	// if no language is found in the image name, check environment variables.
	envVarKeywords := map[string]string{
		"GODEBUG":                     "Go",
		"GOENV":                       "Go",
		"GOOS":                        "Go",
		"GOPATH":                      "Go",
		"NODE_ENV":                    "Node.js",
		"NPM_CONFIG":                  "Node.js",
		"npm_package_":                "Node.js",
		"PYTHONPATH":                  "Python",
		"VIRTUAL_ENV":                 "Python",
		"PYTHONDONTWRITEBYTECODE":     "Python",
		"JAVA_HOME":                   "Java",
		"JRE_HOME":                    "Java",
		"MAVEN_HOME":                  "Java",
		"GRADLE_HOME":                 "Java",
		"CLASSPATH":                   "Java",
		"ASPNETCORE_URLS":             ".NET",
		"DOTNET_RUNNING_IN_CONTAINER": ".NET",
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
