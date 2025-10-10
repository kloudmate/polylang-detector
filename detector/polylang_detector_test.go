package detector

import (
	"testing"
)

func TestShouldMonitorNamespace(t *testing.T) {
	tests := []struct {
		name           string
		ignoredNs      []string
		monitoredNs    []string
		testNamespace  string
		expectedResult bool
		description    string
	}{
		{
			name:           "No filters - should monitor all",
			ignoredNs:      []string{},
			monitoredNs:    []string{},
			testNamespace:  "default",
			expectedResult: true,
			description:    "When no filters configured, monitor all namespaces",
		},
		{
			name:           "Ignored namespace",
			ignoredNs:      []string{"kube-system", "kube-public"},
			monitoredNs:    []string{},
			testNamespace:  "kube-system",
			expectedResult: false,
			description:    "Namespace in ignored list should not be monitored",
		},
		{
			name:           "Not ignored namespace",
			ignoredNs:      []string{"kube-system", "kube-public"},
			monitoredNs:    []string{},
			testNamespace:  "default",
			expectedResult: true,
			description:    "Namespace not in ignored list should be monitored",
		},
		{
			name:           "Monitored namespace only",
			ignoredNs:      []string{},
			monitoredNs:    []string{"production", "staging"},
			testNamespace:  "production",
			expectedResult: true,
			description:    "Namespace in monitored list should be monitored",
		},
		{
			name:           "Not in monitored namespace",
			ignoredNs:      []string{},
			monitoredNs:    []string{"production", "staging"},
			testNamespace:  "default",
			expectedResult: false,
			description:    "When monitored list exists, only those namespaces should be monitored",
		},
		{
			name:           "Monitored overrides ignored",
			ignoredNs:      []string{"kube-system", "production"},
			monitoredNs:    []string{"production", "staging"},
			testNamespace:  "production",
			expectedResult: true,
			description:    "KM_K8S_MONITORED_NAMESPACES has higher priority - production should be monitored even if ignored",
		},
		{
			name:           "Monitored takes precedence - namespace not in monitored",
			ignoredNs:      []string{"kube-system"},
			monitoredNs:    []string{"production", "staging"},
			testNamespace:  "default",
			expectedResult: false,
			description:    "When monitored list exists, ignored list is not checked - default not monitored",
		},
		{
			name:           "Monitored takes precedence - ignored namespace not in monitored",
			ignoredNs:      []string{"kube-system"},
			monitoredNs:    []string{"production", "staging"},
			testNamespace:  "kube-system",
			expectedResult: false,
			description:    "When monitored list exists, kube-system not monitored (not in monitored list)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := &PolylangDetector{
				IgnoredNamespaces:   tt.ignoredNs,
				MonitoredNamespaces: tt.monitoredNs,
			}

			result := pd.ShouldMonitorNamespace(tt.testNamespace)

			if result != tt.expectedResult {
				t.Errorf("%s: expected %v, got %v\nTest: %s\nIgnored: %v\nMonitored: %v\nNamespace: %s",
					tt.name, tt.expectedResult, result, tt.description,
					tt.ignoredNs, tt.monitoredNs, tt.testNamespace)
			}
		})
	}
}

func TestShouldMonitorNamespace_EdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		ignoredNs      []string
		monitoredNs    []string
		testNamespace  string
		expectedResult bool
	}{
		{
			name:           "Empty string namespace with no filters",
			ignoredNs:      []string{},
			monitoredNs:    []string{},
			testNamespace:  "",
			expectedResult: true,
		},
		{
			name:           "Empty string in ignored list",
			ignoredNs:      []string{""},
			monitoredNs:    []string{},
			testNamespace:  "",
			expectedResult: false,
		},
		{
			name:           "Whitespace in namespace (after trim)",
			ignoredNs:      []string{},
			monitoredNs:    []string{"production"},
			testNamespace:  "production",
			expectedResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pd := &PolylangDetector{
				IgnoredNamespaces:   tt.ignoredNs,
				MonitoredNamespaces: tt.monitoredNs,
			}

			result := pd.ShouldMonitorNamespace(tt.testNamespace)

			if result != tt.expectedResult {
				t.Errorf("expected %v, got %v", tt.expectedResult, result)
			}
		})
	}
}
