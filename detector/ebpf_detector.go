package detector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EbpfDetector provides eBPF-based language detection by analyzing process information
// This is a lightweight alternative that uses kernel data without requiring eBPF programs
type EbpfDetector struct {
	cache      map[int]*ProcessInfo
	cacheMutex sync.RWMutex
}

// ProcessInfo contains information about a running process
type ProcessInfo struct {
	PID         int
	PPID        int
	Executable  string
	Cmdline     string
	Language    string
	Framework   string
	Confidence  string
	DetectedAt  time.Time
	ContainerID string
}

// LanguageSignature defines patterns for detecting programming languages
type LanguageSignature struct {
	Language   string
	Framework  string
	Patterns   []string
	Libraries  []string
	Priority   int
	Confidence string
}

var languageSignatures = []LanguageSignature{
	// Go - compiled binary patterns
	{
		Language:   "Go",
		Framework:  "",
		Patterns:   []string{"go build", "go-build", "Go BuildID", "runtime.main", "runtime.goexit"},
		Libraries:  []string{"libgo.so", "runtime/internal"},
		Priority:   15,
		Confidence: "high",
	},
	// Java - JVM based
	{
		Language:   "Java",
		Framework:  "Spring Boot",
		Patterns:   []string{"spring-boot", "org.springframework.boot"},
		Libraries:  []string{"libjvm.so", "libjava.so"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "Java",
		Framework:  "",
		Patterns:   []string{"java", "openjdk", "jre", "jdk"},
		Libraries:  []string{"libjvm.so", "libjava.so"},
		Priority:   15,
		Confidence: "high",
	},
	// Node.js
	{
		Language:   "nodejs",
		Framework:  "Next.js",
		Patterns:   []string{"next start", "next dev", ".next/server"},
		Libraries:  []string{"libnode.so"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "nodejs",
		Framework:  "NestJS",
		Patterns:   []string{"@nestjs/core", "nest start"},
		Libraries:  []string{"libnode.so"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "nodejs",
		Framework:  "",
		Patterns:   []string{"node", "/usr/bin/node", "/usr/local/bin/node"},
		Libraries:  []string{"libnode.so"},
		Priority:   15,
		Confidence: "high",
	},
	// Python
	{
		Language:   "Python",
		Framework:  "Django",
		Patterns:   []string{"django", "manage.py", "django.core"},
		Libraries:  []string{"libpython", "python3"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "Python",
		Framework:  "FastAPI",
		Patterns:   []string{"fastapi", "uvicorn", "starlette"},
		Libraries:  []string{"libpython", "python3"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "Python",
		Framework:  "Flask",
		Patterns:   []string{"flask", "werkzeug"},
		Libraries:  []string{"libpython", "python3"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "Python",
		Framework:  "",
		Patterns:   []string{"python", "python3", "/usr/bin/python"},
		Libraries:  []string{"libpython", "python3"},
		Priority:   15,
		Confidence: "high",
	},
	// .NET
	{
		Language:   ".NET",
		Framework:  "ASP.NET Core",
		Patterns:   []string{"dotnet", "aspnetcore", "Microsoft.AspNetCore"},
		Libraries:  []string{"libcoreclr.so", "System.Private.CoreLib.dll"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   ".NET",
		Framework:  "",
		Patterns:   []string{"dotnet", "/usr/bin/dotnet"},
		Libraries:  []string{"libcoreclr.so"},
		Priority:   15,
		Confidence: "high",
	},
	// Ruby
	{
		Language:   "Ruby",
		Framework:  "Rails",
		Patterns:   []string{"rails", "actionpack", "activerecord"},
		Libraries:  []string{"libruby.so"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "Ruby",
		Framework:  "",
		Patterns:   []string{"ruby", "/usr/bin/ruby"},
		Libraries:  []string{"libruby.so"},
		Priority:   15,
		Confidence: "high",
	},
	// PHP
	{
		Language:   "PHP",
		Framework:  "Laravel",
		Patterns:   []string{"artisan", "laravel"},
		Libraries:  []string{"libphp", "php-fpm"},
		Priority:   20,
		Confidence: "high",
	},
	{
		Language:   "PHP",
		Framework:  "",
		Patterns:   []string{"php", "php-fpm", "/usr/bin/php"},
		Libraries:  []string{"libphp"},
		Priority:   15,
		Confidence: "high",
	},
	// Rust
	{
		Language:   "Rust",
		Framework:  "",
		Patterns:   []string{"cargo", "rustc"},
		Libraries:  []string{},
		Priority:   15,
		Confidence: "medium",
	},
}

// NewEbpfDetector creates a new eBPF-based language detector
func NewEbpfDetector() *EbpfDetector {
	return &EbpfDetector{
		cache: make(map[int]*ProcessInfo),
	}
}

// DetectLanguageByPID detects the programming language of a process by its PID
func (ed *EbpfDetector) DetectLanguageByPID(pid int) (*ProcessInfo, error) {
	// Check cache first
	ed.cacheMutex.RLock()
	if cached, found := ed.cache[pid]; found {
		ed.cacheMutex.RUnlock()
		return cached, nil
	}
	ed.cacheMutex.RUnlock()

	// Read process information from /proc
	procInfo, err := ed.readProcInfo(pid)
	if err != nil {
		return nil, fmt.Errorf("failed to read proc info: %w", err)
	}

	// Detect language based on signatures
	lang, fw, conf := ed.matchLanguageSignatures(procInfo)
	procInfo.Language = lang
	procInfo.Framework = fw
	procInfo.Confidence = conf
	procInfo.DetectedAt = time.Now()

	// Cache the result
	ed.cacheMutex.Lock()
	ed.cache[pid] = procInfo
	ed.cacheMutex.Unlock()

	return procInfo, nil
}

// DetectLanguageForContainer detects languages for all processes in a container
func (ed *EbpfDetector) DetectLanguageForContainer(ctx context.Context, containerID string) ([]ProcessInfo, error) {
	pids, err := ed.getContainerPIDs(containerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get container PIDs: %w", err)
	}

	var results []ProcessInfo
	for _, pid := range pids {
		procInfo, err := ed.DetectLanguageByPID(pid)
		if err != nil {
			continue // Skip processes we can't read
		}
		if procInfo.Language != "" {
			results = append(results, *procInfo)
		}
	}

	// Return the highest priority detection
	if len(results) > 0 {
		return ed.filterBestMatches(results), nil
	}

	return nil, fmt.Errorf("no language detected for container %s", containerID)
}

// readProcInfo reads process information from /proc filesystem
func (ed *EbpfDetector) readProcInfo(pid int) (*ProcessInfo, error) {
	procPath := fmt.Sprintf("/proc/%d", pid)

	// Read executable path
	exe, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err != nil {
		exe = ""
	}

	// Read command line
	cmdlineBytes, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
	if err != nil {
		return nil, err
	}
	cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

	// Read parent PID
	statusFile := filepath.Join(procPath, "status")
	ppid := 0
	if data, err := os.ReadFile(statusFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ppid, _ = strconv.Atoi(fields[1])
					break
				}
			}
		}
	}

	return &ProcessInfo{
		PID:        pid,
		PPID:       ppid,
		Executable: exe,
		Cmdline:    cmdline,
	}, nil
}

// matchLanguageSignatures matches process info against language signatures
func (ed *EbpfDetector) matchLanguageSignatures(procInfo *ProcessInfo) (string, string, string) {
	cmdlineLower := strings.ToLower(procInfo.Cmdline)
	exeLower := strings.ToLower(procInfo.Executable)
	combined := cmdlineLower + " " + exeLower

	var bestMatch *LanguageSignature
	for i := range languageSignatures {
		sig := &languageSignatures[i]
		matched := false

		// Check command line patterns
		for _, pattern := range sig.Patterns {
			if strings.Contains(combined, strings.ToLower(pattern)) {
				matched = true
				break
			}
		}

		// Check library dependencies if available
		if !matched && procInfo.PID > 0 {
			mapsPath := fmt.Sprintf("/proc/%d/maps", procInfo.PID)
			if mapsData, err := os.ReadFile(mapsPath); err == nil {
				mapsContent := strings.ToLower(string(mapsData))
				for _, lib := range sig.Libraries {
					if strings.Contains(mapsContent, strings.ToLower(lib)) {
						matched = true
						break
					}
				}
			}
		}

		if matched {
			if bestMatch == nil || sig.Priority > bestMatch.Priority {
				bestMatch = sig
			}
		}
	}

	if bestMatch != nil {
		return bestMatch.Language, bestMatch.Framework, bestMatch.Confidence
	}

	return "", "", ""
}

// getContainerPIDs gets all PIDs running in a container
func (ed *EbpfDetector) getContainerPIDs(containerID string) ([]int, error) {
	// Try to find PIDs through cgroup
	cgroupPaths := []string{
		fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope/cgroup.procs", containerID),
		fmt.Sprintf("/sys/fs/cgroup/kubepods/pod*/docker-%s/cgroup.procs", containerID),
		fmt.Sprintf("/sys/fs/cgroup/kubepods.slice/kubepods-pod*.slice/docker-%s.scope/cgroup.procs", containerID),
	}

	for _, pattern := range cgroupPaths {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			continue
		}

		for _, cgroupFile := range matches {
			file, err := os.Open(cgroupFile)
			if err != nil {
				continue
			}
			defer file.Close()

			var pids []int
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if pid, err := strconv.Atoi(scanner.Text()); err == nil {
					pids = append(pids, pid)
				}
			}

			if len(pids) > 0 {
				return pids, nil
			}
		}
	}

	return nil, fmt.Errorf("no PIDs found for container %s", containerID)
}

// filterBestMatches returns the best language detection from multiple processes
func (ed *EbpfDetector) filterBestMatches(results []ProcessInfo) []ProcessInfo {
	if len(results) == 0 {
		return results
	}

	// Group by language
	languageMap := make(map[string]*ProcessInfo)
	for i := range results {
		proc := &results[i]
		key := proc.Language
		if proc.Framework != "" {
			key = proc.Language + ":" + proc.Framework
		}

		if existing, found := languageMap[key]; !found || getPriority(proc) > getPriority(existing) {
			languageMap[key] = proc
		}
	}

	// Return unique detections
	var filtered []ProcessInfo
	for _, proc := range languageMap {
		filtered = append(filtered, *proc)
	}

	return filtered
}

// getPriority returns the priority score for a process detection
func getPriority(proc *ProcessInfo) int {
	for _, sig := range languageSignatures {
		if sig.Language == proc.Language && sig.Framework == proc.Framework {
			return sig.Priority
		}
	}
	return 0
}

// ClearCache clears the process info cache
func (ed *EbpfDetector) ClearCache() {
	ed.cacheMutex.Lock()
	defer ed.cacheMutex.Unlock()
	ed.cache = make(map[int]*ProcessInfo)
}
