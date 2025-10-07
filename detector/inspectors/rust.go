package inspectors

import (
	"github.com/kloudmate/polylang-detector/detector/process"
)

type RustInspector struct {
	elfAnalyzer *process.ELFAnalyzer
}

func NewRustInspector() *RustInspector {
	return &RustInspector{
		elfAnalyzer: process.NewELFAnalyzer(),
	}
}

func (r *RustInspector) GetLanguage() Language {
	return LanguageRust
}

func (r *RustInspector) QuickScan(ctx *process.ProcessContext) *DetectionResult {
	// QuickScan not implemented for Rust - requires deep analysis
	return nil
}

func (r *RustInspector) DeepScan(ctx *process.ProcessContext) *DetectionResult {
	// Check for Rust symbols in ELF binary
	if hasRust, _ := r.elfAnalyzer.HasRustSymbols(ctx.Executable); hasRust {
		return &DetectionResult{
			Language:   LanguageRust,
			Framework:  "",
			Version:    "", // TODO: Extract Rust version
			Confidence: "high",
		}
	}

	return nil
}
