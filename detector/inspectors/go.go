package inspectors

import (
	"regexp"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

type GoInspector struct {
	elfAnalyzer *process.ELFAnalyzer
}

func NewGoInspector() *GoInspector {
	return &GoInspector{
		elfAnalyzer: process.NewELFAnalyzer(),
	}
}

func (g *GoInspector) GetLanguage() Language {
	return LanguageGo
}

func (g *GoInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	// Use debug/buildinfo to check if it's a Go binary
	if isGo, version, _ := g.elfAnalyzer.IsGoBinary(ctx.Executable); isGo {
		// Filter false positives (e.g., Dynatrace wrappers)
		if !strings.Contains(strings.ToLower(ctx.Cmdline), "dynatrace") {
			return &DetectionResult{
				Language:   LanguageGo,
				Framework:  "",
				Version:    g.cleanVersion(version),
				Confidence: "high",
			}
		}
	}

	// Check environment variables for Go indicators
	goEnvVars := []string{"GOOS", "GOARCH", "GOPATH"}
	for _, envVar := range goEnvVars {
		if _, exists := ctx.Environ[envVar]; exists {
			return &DetectionResult{
				Language:   LanguageGo,
				Framework:  "",
				Version:    g.extractVersion(ctx),
				Confidence: "medium",
			}
		}
	}

	return nil
}

func (g *GoInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Deep scan not needed for Go - buildinfo check in QuickScan is sufficient
	return nil
}

func (g *GoInspector) cleanVersion(version string) string {
	// Extract version from "go1.21.3" -> "1.21.3"
	versionRegex := regexp.MustCompile(`go(\d+\.\d+\.?\d*)`)
	matches := versionRegex.FindStringSubmatch(version)
	if len(matches) > 1 {
		return matches[1]
	}
	return strings.TrimPrefix(version, "go")
}

func (g *GoInspector) extractVersion(ctx *process.ProcessContext) string {
	versionKeys := []string{"GO_VERSION", "GOLANG_VERSION"}

	for _, key := range versionKeys {
		if version, exists := ctx.Environ[key]; exists {
			return g.cleanVersion(version)
		}
	}

	return ""
}
