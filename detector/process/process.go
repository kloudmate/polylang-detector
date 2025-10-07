package process

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessContext contains detailed information about a running process
type ProcessContext struct {
	PID         int
	PPID        int
	Executable  string
	Cmdline     string
	Environ     map[string]string
	CgroupPath  string
	ContainerID string
}

// ProcessFile represents a file in /proc/[pid]/
type ProcessFile struct {
	Path    string
	Content string
}

var procDir = "/proc" // Can be overridden for testing or host /proc access

// SetProcDir sets the proc directory (e.g., /host/proc for DaemonSet mode)
func SetProcDir(dir string) {
	procDir = dir
}

// GetProcDir returns the current proc directory
func GetProcDir() string {
	return procDir
}

// FindAllProcesses scans /proc and returns all process PIDs
func FindAllProcesses() ([]int, error) {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read proc dir: %w", err)
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		pids = append(pids, pid)
	}

	return pids, nil
}

// GetProcessContext retrieves detailed information about a process
func GetProcessContext(pid int) (*ProcessContext, error) {
	procPath := filepath.Join(procDir, strconv.Itoa(pid))

	ctx := &ProcessContext{
		PID:     pid,
		Environ: make(map[string]string),
	}

	// Read executable path
	exe, err := os.Readlink(filepath.Join(procPath, "exe"))
	if err != nil {
		// Process might have terminated or we don't have permission
		exe = ""
	}
	ctx.Executable = exe

	// Read command line
	cmdlineBytes, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
	if err != nil {
		return nil, fmt.Errorf("failed to read cmdline: %w", err)
	}
	ctx.Cmdline = strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")

	// Read environment variables
	envBytes, err := os.ReadFile(filepath.Join(procPath, "environ"))
	if err == nil {
		envPairs := strings.Split(string(envBytes), "\x00")
		for _, pair := range envPairs {
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				ctx.Environ[parts[0]] = parts[1]
			}
		}
	}

	// Read parent PID
	statusFile := filepath.Join(procPath, "status")
	if data, err := os.ReadFile(statusFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					ctx.PPID, _ = strconv.Atoi(fields[1])
					break
				}
			}
		}
	}

	// Read cgroup to get container ID
	cgroupFile := filepath.Join(procPath, "cgroup")
	if data, err := os.ReadFile(cgroupFile); err == nil {
		ctx.CgroupPath = string(data)
		ctx.ContainerID = extractContainerID(string(data))
	}

	return ctx, nil
}

// ReadMapsFile reads /proc/[pid]/maps file
func ReadMapsFile(pid int) (*ProcessFile, error) {
	mapsPath := filepath.Join(procDir, strconv.Itoa(pid), "maps")
	content, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read maps file: %w", err)
	}

	return &ProcessFile{
		Path:    mapsPath,
		Content: string(content),
	}, nil
}

// extractContainerID extracts container ID from cgroup path
func extractContainerID(cgroupContent string) string {
	// Parse cgroup content to find container ID
	// Format examples:
	// 0::/kubepods/besteffort/pod<pod-uid>/container-id
	// 0::/docker/container-id
	// 12:pids:/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/docker-<container-id>.scope

	lines := strings.Split(cgroupContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Docker container ID pattern
		if strings.Contains(line, "docker-") {
			parts := strings.Split(line, "docker-")
			if len(parts) > 1 {
				containerID := strings.TrimSuffix(parts[1], ".scope")
				if len(containerID) >= 12 {
					return containerID[:12] // Return first 12 chars
				}
			}
		}

		// Containerd pattern
		if strings.Contains(line, "cri-containerd-") {
			parts := strings.Split(line, "cri-containerd-")
			if len(parts) > 1 {
				containerID := strings.TrimSuffix(parts[1], ".scope")
				if len(containerID) >= 12 {
					return containerID[:12]
				}
			}
		}

		// CRI-O pattern
		if strings.Contains(line, "crio-") {
			parts := strings.Split(line, "crio-")
			if len(parts) > 1 {
				containerID := strings.TrimSuffix(parts[1], ".scope")
				if len(containerID) >= 12 {
					return containerID[:12]
				}
			}
		}
	}

	return ""
}

// GetContainerPIDs returns all PIDs belonging to a specific container
func GetContainerPIDs(containerID string) ([]int, error) {
	if containerID == "" {
		return nil, fmt.Errorf("container ID is empty")
	}

	// Try cgroup v2 first
	cgroupPaths := []string{
		// Docker
		fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope/cgroup.procs", containerID),
		// Kubernetes with Docker
		fmt.Sprintf("/sys/fs/cgroup/kubepods/pod*/docker-%s/cgroup.procs", containerID),
		fmt.Sprintf("/sys/fs/cgroup/kubepods.slice/kubepods-pod*.slice/docker-%s.scope/cgroup.procs", containerID),
		// Containerd
		fmt.Sprintf("/sys/fs/cgroup/system.slice/cri-containerd-%s.scope/cgroup.procs", containerID),
		// CRI-O
		fmt.Sprintf("/sys/fs/cgroup/system.slice/crio-%s.scope/cgroup.procs", containerID),
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

// IsProcessEqualToAny checks if process executable or cmdline matches any of the given names
func IsProcessEqualToAny(ctx *ProcessContext, processNames []string) bool {
	exeName := filepath.Base(ctx.Executable)
	cmdlineLower := strings.ToLower(ctx.Cmdline)
	exeLower := strings.ToLower(exeName)

	for _, name := range processNames {
		nameLower := strings.ToLower(name)
		if exeLower == nameLower || strings.Contains(cmdlineLower, nameLower) {
			return true
		}
	}

	return false
}

// ContainsBinary checks if maps file contains any of the specified binaries/libraries
func ContainsBinary(mapsFile *ProcessFile, binaries []string) bool {
	contentLower := strings.ToLower(mapsFile.Content)

	for _, binary := range binaries {
		if strings.Contains(contentLower, strings.ToLower(binary)) {
			return true
		}
	}

	return false
}
