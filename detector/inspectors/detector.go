package inspectors

import (
	"fmt"
	"strings"

	"github.com/kloudmate/polylang-detector/detector/process"
)

// LanguageDetector orchestrates the two-stage detection process
type LanguageDetector struct {
	inspectors []LanguageInspector
}

// NewLanguageDetector creates a new language detector
func NewLanguageDetector() *LanguageDetector {
	return &LanguageDetector{
		inspectors: AllInspectors(),
	}
}

// DetectionError represents a language detection error
type DetectionError struct {
	Message string
}

func (e *DetectionError) Error() string {
	return e.Message
}

// ErrLanguageDetectionConflict occurs when multiple languages are detected
type ErrLanguageDetectionConflict struct {
	Languages []Language
}

func (e *ErrLanguageDetectionConflict) Error() string {
	langs := make([]string, len(e.Languages))
	for i, l := range e.Languages {
		langs[i] = string(l)
	}
	return fmt.Sprintf("detected more than one language: [%s]", strings.Join(langs, ", "))
}

// Detect performs two-stage language detection
func (ld *LanguageDetector) Detect(ctx *process.ProcessContext) (*DetectionResult, error) {
	// Stage 1: QuickScan
	quickResults := make([]*DetectionResult, 0)
	for _, inspector := range ld.inspectors {
		if result := inspector.QuickScan(ctx); result != nil {
			quickResults = append(quickResults, result)
		}
	}

	// If we have exactly one high-confidence quick result, return it
	if len(quickResults) == 1 && quickResults[0].Confidence == "high" {
		return quickResults[0], nil
	}

	// If we have multiple quick results, check for conflicts
	if len(quickResults) > 1 {
		// Check if they're all the same language
		firstLang := quickResults[0].Language
		allSame := true
		for _, result := range quickResults[1:] {
			if result.Language != firstLang {
				allSame = false
				break
			}
		}

		if allSame {
			// Return the highest confidence result
			return ld.selectBestResult(quickResults), nil
		}

		// Conflict detected
		languages := make([]Language, len(quickResults))
		for i, r := range quickResults {
			languages[i] = r.Language
		}
		return nil, &ErrLanguageDetectionConflict{Languages: languages}
	}

	// Stage 2: DeepScan (only if QuickScan didn't find anything conclusive)
	deepResults := make([]*DetectionResult, 0)
	for _, inspector := range ld.inspectors {
		if result := inspector.DeepScan(ctx); result != nil {
			deepResults = append(deepResults, result)
		}
	}

	// If we have exactly one deep result, return it
	if len(deepResults) == 1 {
		return deepResults[0], nil
	}

	// If we have multiple deep results, check for conflicts
	if len(deepResults) > 1 {
		// Check if they're all the same language
		firstLang := deepResults[0].Language
		allSame := true
		for _, result := range deepResults[1:] {
			if result.Language != firstLang {
				allSame = false
				break
			}
		}

		if allSame {
			// Return the highest confidence result
			return ld.selectBestResult(deepResults), nil
		}

		// Conflict detected
		languages := make([]Language, len(deepResults))
		for i, r := range deepResults {
			languages[i] = r.Language
		}
		return nil, &ErrLanguageDetectionConflict{Languages: languages}
	}

	// No language detected
	return &DetectionResult{
		Language:   LanguageUnknown,
		Framework:  "",
		Version:    "",
		Confidence: "low",
	}, nil
}

// VerifyLanguage verifies if a previously detected language still matches
func (ld *LanguageDetector) VerifyLanguage(ctx *process.ProcessContext, expectedLang Language) bool {
	for _, inspector := range ld.inspectors {
		if inspector.GetLanguage() != expectedLang {
			continue
		}

		// Try QuickScan first
		if result := inspector.QuickScan(ctx); result != nil && result.Language == expectedLang {
			return true
		}

		// Try DeepScan
		if result := inspector.DeepScan(ctx); result != nil && result.Language == expectedLang {
			return true
		}
	}

	return false
}

// selectBestResult selects the best result based on confidence and framework detection
func (ld *LanguageDetector) selectBestResult(results []*DetectionResult) *DetectionResult {
	if len(results) == 0 {
		return nil
	}

	best := results[0]
	for _, result := range results[1:] {
		// Prefer high confidence over medium/low
		if result.Confidence == "high" && best.Confidence != "high" {
			best = result
			continue
		}

		// If same confidence, prefer result with framework detected
		if result.Confidence == best.Confidence && result.Framework != "" && best.Framework == "" {
			best = result
			continue
		}

		// If same confidence, prefer result with version detected
		if result.Confidence == best.Confidence && result.Version != "" && best.Version == "" {
			best = result
		}
	}

	return best
}
