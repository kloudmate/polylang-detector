package inspectors

import (
	"github.com/kloudmate/polylang-detector/detector/process"
)

// Language represents a detected programming language
type Language string

const (
	LanguageJava    Language = "Java"
	LanguagePython  Language = "Python"
	LanguageNodeJS  Language = "nodejs"
	LanguageGo      Language = "Go"
	LanguageDotNet  Language = ".NET"
	LanguagePHP     Language = "PHP"
	LanguageRuby    Language = "Ruby"
	LanguageRust    Language = "Rust"
	LanguageUnknown Language = "Unknown"
)

// DetectionResult contains the result of language detection
type DetectionResult struct {
	Language   Language
	Framework  string
	Version    string
	Confidence string // "high", "medium", "low"
}

// LanguageInspector defines the interface for language detection
type LanguageInspector interface {
	// QuickScan performs fast detection (process name, basic checks)
	QuickScan(ctx *process.ProcessContext) *DetectionResult

	// DeepScan performs thorough detection (memory maps, ELF analysis)
	DeepScan(ctx *process.ProcessContext) *DetectionResult

	// GetLanguage returns the language this inspector detects
	GetLanguage() Language
}

// AllInspectors returns all available language inspectors
func AllInspectors() []LanguageInspector {
	return []LanguageInspector{
		NewJavaInspector(),
		NewPythonInspector(),
		NewNodeJSInspector(),
		NewGoInspector(),
		NewDotNetInspector(),
		NewPHPInspector(),
		NewRubyInspector(),
		NewRustInspector(),
	}
}
