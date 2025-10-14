package detector

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// LanguageCache provides thread-safe caching of language detection results
// It maintains both image-based cache and workload-based cache for cluster state synchronization
// Cache entries persist until workload is explicitly deleted - no time-based expiration
type LanguageCache struct {
	mu            sync.RWMutex
	cache         map[string]*CacheEntry         // Image-based cache: key -> CacheEntry
	workloadCache map[string]*WorkloadCacheEntry // Workload-based cache: namespace/workloadName -> WorkloadCacheEntry
}

// CacheEntry represents a cached detection result (no expiration)
type CacheEntry struct {
	Info ContainerInfo
}

// WorkloadCacheEntry represents detection results for a specific workload (deployment/daemonset/replicaset)
type WorkloadCacheEntry struct {
	Namespace    string
	WorkloadName string
	WorkloadKind string
	Containers   map[string]ContainerInfo // containerName -> ContainerInfo
}

// NewLanguageCache creates a new cache (ttl parameter kept for compatibility but not used)
func NewLanguageCache(ttl time.Duration) *LanguageCache {
	return &LanguageCache{
		cache:         make(map[string]*CacheEntry),
		workloadCache: make(map[string]*WorkloadCacheEntry),
	}
}

// generateKey creates a cache key from image and environment variables
func (lc *LanguageCache) generateKey(image string, envVars map[string]string) string {
	// Use image as primary key - most reliable identifier
	// For same image, results should be the same
	h := sha256.New()
	h.Write([]byte(image))

	// Include critical env vars that might affect detection
	criticalEnvVars := []string{
		"JAVA_VERSION", "NODE_VERSION", "PYTHON_VERSION", "GO_VERSION",
		"RUBY_VERSION", "PHP_VERSION", "DOTNET_VERSION",
	}

	for _, key := range criticalEnvVars {
		if val, exists := envVars[key]; exists {
			h.Write([]byte(fmt.Sprintf("%s=%s", key, val)))
		}
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// Get retrieves a cached result if it exists (no expiration check)
func (lc *LanguageCache) Get(image string, envVars map[string]string) (*ContainerInfo, bool) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	key := lc.generateKey(image, envVars)
	entry, exists := lc.cache[key]

	if !exists {
		return nil, false
	}

	return &entry.Info, true
}

// Set stores a detection result in the cache (persists until manually removed)
func (lc *LanguageCache) Set(image string, envVars map[string]string, info ContainerInfo) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	key := lc.generateKey(image, envVars)
	lc.cache[key] = &CacheEntry{
		Info: info,
	}
}

// SetWorkload stores detection results for a specific workload
func (lc *LanguageCache) SetWorkload(namespace, workloadName, workloadKind string, containers map[string]ContainerInfo) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	key := namespace + "/" + workloadName
	lc.workloadCache[key] = &WorkloadCacheEntry{
		Namespace:    namespace,
		WorkloadName: workloadName,
		WorkloadKind: workloadKind,
		Containers:   containers,
	}
}

// UpdateWorkloadContainer updates a single container in a workload's cache
func (lc *LanguageCache) UpdateWorkloadContainer(namespace, workloadName, workloadKind string, info ContainerInfo) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	key := namespace + "/" + workloadName
	entry, exists := lc.workloadCache[key]

	if !exists {
		entry = &WorkloadCacheEntry{
			Namespace:    namespace,
			WorkloadName: workloadName,
			WorkloadKind: workloadKind,
			Containers:   make(map[string]ContainerInfo),
		}
		lc.workloadCache[key] = entry
	}

	entry.Containers[info.ContainerName] = info
}

// GetWorkload retrieves cached detection results for a workload
func (lc *LanguageCache) GetWorkload(namespace, workloadName string) (*WorkloadCacheEntry, bool) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	key := namespace + "/" + workloadName
	entry, exists := lc.workloadCache[key]
	return entry, exists
}

// RemoveWorkload completely removes a workload from the cache
func (lc *LanguageCache) RemoveWorkload(namespace, workloadName string) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	key := namespace + "/" + workloadName
	delete(lc.workloadCache, key)
}

// GetAllActiveWorkloads returns all workloads in the cache
func (lc *LanguageCache) GetAllActiveWorkloads() []WorkloadCacheEntry {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	var workloads []WorkloadCacheEntry
	for _, entry := range lc.workloadCache {
		workloads = append(workloads, *entry)
	}

	return workloads
}

// GetAllActiveContainers returns all container infos from all workloads
func (lc *LanguageCache) GetAllActiveContainers() []ContainerInfo {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	var containers []ContainerInfo
	for _, entry := range lc.workloadCache {
		for _, containerInfo := range entry.Containers {
			containers = append(containers, containerInfo)
		}
	}

	return containers
}
