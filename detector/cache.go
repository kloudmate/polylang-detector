package detector

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// LanguageCache provides thread-safe caching of language detection results
type LanguageCache struct {
	mu    sync.RWMutex
	cache map[string]*CacheEntry
	ttl   time.Duration
}

// CacheEntry represents a cached detection result with expiration
type CacheEntry struct {
	Info      ContainerInfo
	ExpiresAt time.Time
}

// NewLanguageCache creates a new cache with the specified TTL
func NewLanguageCache(ttl time.Duration) *LanguageCache {
	cache := &LanguageCache{
		cache: make(map[string]*CacheEntry),
		ttl:   ttl,
	}

	// Start background cleanup goroutine
	go cache.cleanup()

	return cache
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

// Get retrieves a cached result if it exists and hasn't expired
func (lc *LanguageCache) Get(image string, envVars map[string]string) (*ContainerInfo, bool) {
	lc.mu.RLock()
	defer lc.mu.RUnlock()

	key := lc.generateKey(image, envVars)
	entry, exists := lc.cache[key]

	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return &entry.Info, true
}

// Set stores a detection result in the cache
func (lc *LanguageCache) Set(image string, envVars map[string]string, info ContainerInfo) {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	key := lc.generateKey(image, envVars)
	lc.cache[key] = &CacheEntry{
		Info:      info,
		ExpiresAt: time.Now().Add(lc.ttl),
	}
}

// cleanup periodically removes expired entries
func (lc *LanguageCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		lc.mu.Lock()
		now := time.Now()
		for key, entry := range lc.cache {
			if now.After(entry.ExpiresAt) {
				delete(lc.cache, key)
			}
		}
		lc.mu.Unlock()
	}
}
