package inspectors

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

type PHPInspector struct {
	elfAnalyzer *process.ELFAnalyzer
}

func NewPHPInspector() *PHPInspector {
	return &PHPInspector{
		elfAnalyzer: process.NewELFAnalyzer(),
	}
}

func (p *PHPInspector) GetLanguage() Language {
	return LanguagePHP
}

func (p *PHPInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	exeName := filepath.Base(ctx.Executable)
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	// Check for PHP executable
	phpProcesses := []string{"php", "php-fpm"}
	for _, proc := range phpProcesses {
		if exeName == proc || strings.Contains(cmdlineLower, proc) {
			framework := p.detectFramework(ctx)
			version := p.extractVersion(ctx)
			return &DetectionResult{
				Language:   LanguagePHP,
				Framework:  framework,
				Version:    version,
				Confidence: "high",
			}
		}
	}

	return nil
}

func (p *PHPInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Check memory maps for PHP libraries
	mapsFile, err := process.ReadMapsFile(ctx.PID)
	if err != nil {
		return nil
	}

	phpLibs := []string{"libphp", "php-fpm"}
	if process.ContainsBinary(mapsFile, phpLibs) {
		// Try to extract version from ELF .rodata section
		version, _ := p.elfAnalyzer.ExtractPHPVersion(ctx.Executable)
		if version == "" {
			version = p.extractVersion(ctx)
		}

		return &DetectionResult{
			Language:   LanguagePHP,
			Framework:  p.detectFramework(ctx),
			Version:    version,
			Confidence: "high",
		}
	}

	return nil
}

func (p *PHPInspector) detectFramework(ctx *process.ProcessContext) string {
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	frameworks := map[string][]string{
		"Laravel": {"artisan", "laravel"},
		"Symfony": {"bin/console", "symfony"},
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

func (p *PHPInspector) extractVersion(ctx *process.ProcessContext) string {
	if version, exists := ctx.Environ["PHP_VERSION"]; exists {
		// Clean up version string (e.g., "8.2.10")
		versionRegex := regexp.MustCompile(`(\d+\.\d+\.?\d*)`)
		matches := versionRegex.FindStringSubmatch(version)
		if len(matches) > 1 {
			return matches[1]
		}
		return version
	}

	return ""
}
