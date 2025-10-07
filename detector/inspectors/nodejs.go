package inspectors

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

type NodeJSInspector struct{}

func NewNodeJSInspector() *NodeJSInspector {
	return &NodeJSInspector{}
}

func (n *NodeJSInspector) GetLanguage() Language {
	return LanguageNodeJS
}

func (n *NodeJSInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	exeName := filepath.Base(ctx.Executable)
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	// Check for Node.js executable
	nodeProcesses := []string{"node", "npm", "npx", "yarn", "pnpm"}
	for _, proc := range nodeProcesses {
		if exeName == proc || strings.Contains(cmdlineLower, "/"+proc+" ") {
			framework := n.detectFramework(ctx)
			version := n.extractVersion(ctx)
			return &DetectionResult{
				Language:   LanguageNodeJS,
				Framework:  framework,
				Version:    version,
				Confidence: "high",
			}
		}
	}

	// Check for Node.js patterns in command line
	nodePatterns := []string{"node_modules", "npm start", "yarn start", "pnpm start"}
	for _, pattern := range nodePatterns {
		if strings.Contains(cmdlineLower, pattern) {
			return &DetectionResult{
				Language:   LanguageNodeJS,
				Framework:  n.detectFramework(ctx),
				Version:    n.extractVersion(ctx),
				Confidence: "medium",
			}
		}
	}

	return nil
}

func (n *NodeJSInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Check memory maps for Node.js libraries
	mapsFile, err := process.ReadMapsFile(ctx.PID)
	if err != nil {
		return nil
	}

	nodeLibs := []string{"libnode.so", "libnode.so.", "node"}
	if process.ContainsBinary(mapsFile, nodeLibs) {
		return &DetectionResult{
			Language:   LanguageNodeJS,
			Framework:  n.detectFramework(ctx),
			Version:    n.extractVersion(ctx),
			Confidence: "high",
		}
	}

	return nil
}

func (n *NodeJSInspector) detectFramework(ctx *process.ProcessContext) string {
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	frameworks := map[string][]string{
		"Next.js": {"next start", "next dev", ".next/server", "next-server"},
		"NestJS":  {"@nestjs/core", "nest start", "nestjs"},
		"Express": {"express", "express.js", "expressjs"},
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

func (n *NodeJSInspector) extractVersion(ctx *process.ProcessContext) string {
	versionKeys := []string{"NODE_VERSION", "NPM_VERSION"}

	for _, key := range versionKeys {
		if version, exists := ctx.Environ[key]; exists {
			// Clean up version string (e.g., "v18.17.1" -> "18.17.1")
			versionRegex := regexp.MustCompile(`v?(\d+\.\d+\.?\d*)`)
			matches := versionRegex.FindStringSubmatch(version)
			if len(matches) > 1 {
				return matches[1]
			}
			return strings.TrimPrefix(version, "v")
		}
	}

	return ""
}
