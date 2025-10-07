package inspectors

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

type PythonInspector struct {
	elfAnalyzer *process.ELFAnalyzer
}

func NewPythonInspector() *PythonInspector {
	return &PythonInspector{
		elfAnalyzer: process.NewELFAnalyzer(),
	}
}

func (p *PythonInspector) GetLanguage() Language {
	return LanguagePython
}

func (p *PythonInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	exeName := filepath.Base(ctx.Executable)

	// Check for Python executable patterns
	pythonRegex := regexp.MustCompile(`^(python|python3|python\d+|python3\.\d+)$`)
	if pythonRegex.MatchString(exeName) {
		framework := p.detectFramework(ctx)
		version := p.extractVersion(ctx)
		return &DetectionResult{
			Language:   LanguagePython,
			Framework:  framework,
			Version:    version,
			Confidence: "high",
		}
	}

	// Check command line for Python patterns
	cmdlineLower := strings.ToLower(ctx.Cmdline)
	pythonPatterns := []string{"python", "gunicorn", "uvicorn", "pip ", "poetry run", "pipenv run"}
	for _, pattern := range pythonPatterns {
		if strings.Contains(cmdlineLower, pattern) {
			return &DetectionResult{
				Language:   LanguagePython,
				Framework:  p.detectFramework(ctx),
				Version:    p.extractVersion(ctx),
				Confidence: "medium",
			}
		}
	}

	return nil
}

func (p *PythonInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Check for Python library dependencies via ELF
	if hasPython, version, _ := p.elfAnalyzer.HasPythonSymbols(ctx.Executable); hasPython {
		return &DetectionResult{
			Language:   LanguagePython,
			Framework:  p.detectFramework(ctx),
			Version:    version,
			Confidence: "high",
		}
	}

	// Check memory maps for Python libraries
	mapsFile, err := process.ReadMapsFile(ctx.PID)
	if err != nil {
		return nil
	}

	pythonLibs := []string{"libpython3", "libpython2", "python3.", "python2."}
	if process.ContainsBinary(mapsFile, pythonLibs) {
		return &DetectionResult{
			Language:   LanguagePython,
			Framework:  p.detectFramework(ctx),
			Version:    p.extractVersion(ctx),
			Confidence: "high",
		}
	}

	return nil
}

func (p *PythonInspector) detectFramework(ctx *process.ProcessContext) string {
	cmdlineLower := strings.ToLower(ctx.Cmdline)

	frameworks := map[string][]string{
		"Django":   {"django", "manage.py", "django.core", "django-admin", "wsgi.py"},
		"FastAPI":  {"fastapi", "uvicorn", "starlette", "asgi"},
		"Flask":    {"flask", "werkzeug", "flask run"},
		"Gunicorn": {"gunicorn", "gunicorn.app"},
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

func (p *PythonInspector) extractVersion(ctx *process.ProcessContext) string {
	versionKeys := []string{"PYTHON_VERSION", "PY_VERSION"}

	for _, key := range versionKeys {
		if version, exists := ctx.Environ[key]; exists {
			// Clean up version string (e.g., "3.11.5")
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
