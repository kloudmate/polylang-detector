package inspectors

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

type RubyInspector struct{}

func NewRubyInspector() *RubyInspector {
	return &RubyInspector{}
}

func (r *RubyInspector) GetLanguage() Language {
	return LanguageRuby
}

func (r *RubyInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	exeName := filepath.Base(ctx.Executable)
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	// Check for Ruby executable and common Ruby processes
	rubyProcesses := []string{"ruby", "rails", "rails server", "rake", "rackup", "puma", "unicorn", "gem", "bundler", "irb", "pry"}
	for _, proc := range rubyProcesses {
		if exeName == proc || strings.Contains(cmdlineLower, proc) {
			framework := r.detectFramework(ctx)
			version := r.extractVersion(ctx)
			return &DetectionResult{
				Language:   LanguageRuby,
				Framework:  framework,
				Version:    version,
				Confidence: "high",
			}
		}
	}

	return nil
}

func (r *RubyInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Check memory maps for Ruby libraries
	mapsFile, err := process.ReadMapsFile(ctx.PID)
	if err != nil {
		return nil
	}

	rubyLibs := []string{"libruby.so"}
	if process.ContainsBinary(mapsFile, rubyLibs) {
		return &DetectionResult{
			Language:   LanguageRuby,
			Framework:  r.detectFramework(ctx),
			Version:    r.extractVersion(ctx),
			Confidence: "high",
		}
	}

	return nil
}

func (r *RubyInspector) detectFramework(ctx *process.ProcessContext) string {
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	frameworks := map[string][]string{
		"Rails":   {"rails", "actionpack", "activerecord"},
		"Sinatra": {"sinatra"},
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

func (r *RubyInspector) extractVersion(ctx *process.ProcessContext) string {
	versionKeys := []string{"RUBY_VERSION", "RBENV_VERSION"}

	for _, key := range versionKeys {
		if version, exists := ctx.Environ[key]; exists {
			// Clean up version string (e.g., "3.2.2")
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
