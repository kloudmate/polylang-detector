package inspectors

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

type JavaInspector struct{}

func NewJavaInspector() *JavaInspector {
	return &JavaInspector{}
}

func (j *JavaInspector) GetLanguage() Language {
	return LanguageJava
}

func (j *JavaInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	exeName := filepath.Base(ctx.Executable)
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	// Check if process name is "java"
	if exeName == "java" {
		framework := j.detectFramework(ctx)
		version := j.extractVersion(ctx)
		return &DetectionResult{
			Language:   LanguageJava,
			Framework:  framework,
			Version:    version,
			Confidence: "high",
		}
	}

	// Check for common Java patterns in command line
	javaPatterns := []string{"openjdk", "java -jar", "javac", "jre", "jdk"}
	for _, pattern := range javaPatterns {
		if strings.Contains(cmdlineLower, pattern) {
			return &DetectionResult{
				Language:   LanguageJava,
				Framework:  j.detectFramework(ctx),
				Version:    j.extractVersion(ctx),
				Confidence: "medium",
			}
		}
	}

	return nil
}

func (j *JavaInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Read memory maps
	mapsFile, err := process.ReadMapsFile(ctx.PID)
	if err != nil {
		return nil
	}

	// Check for JVM libraries
	jvmLibraries := []string{"libjvm.so", "libjava.so"}
	if process.ContainsBinary(mapsFile, jvmLibraries) {
		return &DetectionResult{
			Language:   LanguageJava,
			Framework:  j.detectFramework(ctx),
			Version:    j.extractVersion(ctx),
			Confidence: "high",
		}
	}

	return nil
}

func (j *JavaInspector) detectFramework(ctx *process.ProcessContext) string {
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	frameworks := map[string][]string{
		"Spring Boot": {"spring-boot", "org.springframework.boot"},
		"Micronaut":   {"micronaut"},
		"Quarkus":     {"quarkus"},
		"Tomcat":      {"tomcat", "catalina"},
		"Jetty":       {"jetty"},
		"Wildfly":     {"wildfly", "jboss"},
	}

	for framework, patterns := range frameworks {
		for _, pattern := range patterns {
			if strings.Contains(cmdlineLower, pattern) {
				return framework
			}
		}
	}

	return ""
}

func (j *JavaInspector) extractVersion(ctx *process.ProcessContext) string {
	versionKeys := []string{"JAVA_VERSION", "JDK_VERSION", "OPENJDK_VERSION"}

	for _, key := range versionKeys {
		if version, exists := ctx.Environ[key]; exists {
			// Clean up version string (e.g., "1.8.0_292" or "11.0.12")
			versionRegex := regexp.MustCompile(`(\d+\.[\d._]+)`)
			matches := versionRegex.FindStringSubmatch(version)
			if len(matches) > 1 {
				return matches[1]
			}
			return version
		}
	}

	return ""
}
