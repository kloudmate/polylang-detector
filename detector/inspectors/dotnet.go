package inspectors

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

type DotNetInspector struct{}

func NewDotNetInspector() *DotNetInspector {
	return &DotNetInspector{}
}

func (d *DotNetInspector) GetLanguage() Language {
	return LanguageDotNet
}

func (d *DotNetInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	exeName := filepath.Base(ctx.Executable)
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	// Check if executable is "dotnet"
	if exeName == "dotnet" {
		framework := d.detectFramework(ctx)
		version := d.extractVersion(ctx)
		return &DetectionResult{
			Language:   LanguageDotNet,
			Framework:  framework,
			Version:    version,
			Confidence: "high",
		}
	}

	// Check for .NET patterns in command line
	dotnetPatterns := []string{"/dotnet ", "\\dotnet.exe", "/usr/bin/dotnet", "/usr/share/dotnet"}
	for _, pattern := range dotnetPatterns {
		if strings.Contains(cmdlineLower, pattern) {
			return &DetectionResult{
				Language:   LanguageDotNet,
				Framework:  d.detectFramework(ctx),
				Version:    d.extractVersion(ctx),
				Confidence: "medium",
			}
		}
	}

	return nil
}

func (d *DotNetInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Check memory maps for .NET Core libraries
	mapsFile, err := process.ReadMapsFile(ctx.PID)
	if err != nil {
		return nil
	}

	dotnetLibs := []string{"libcoreclr.so", "System.Private.CoreLib.dll"}
	if process.ContainsBinary(mapsFile, dotnetLibs) {
		return &DetectionResult{
			Language:   LanguageDotNet,
			Framework:  d.detectFramework(ctx),
			Version:    d.extractVersion(ctx),
			Confidence: "high",
		}
	}

	return nil
}

func (d *DotNetInspector) detectFramework(ctx *process.ProcessContext) string {
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	frameworks := map[string][]string{
		"ASP.NET Core": {"aspnetcore", "Microsoft.AspNetCore"},
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

func (d *DotNetInspector) extractVersion(ctx *process.ProcessContext) string {
	versionKeys := []string{"DOTNET_VERSION", "ASPNETCORE_VERSION", "DOTNET_RUNNING_IN_CONTAINER"}

	for _, key := range versionKeys {
		if version, exists := ctx.Environ[key]; exists {
			// Clean up version string (e.g., "6.0.10")
			versionRegex := regexp.MustCompile(`(\d+\.\d+\.?\d*)`)
			matches := versionRegex.FindStringSubmatch(version)
			if len(matches) > 1 {
				return matches[1]
			}
			return version
		}
	}

	return ""
}
