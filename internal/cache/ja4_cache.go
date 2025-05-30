package cache

import (
	"sync"
)

// Глобальный кеш для хранения JA4 отпечатков по IP
var (
	ja4Cache = make(map[string]string)
	cacheMu  sync.RWMutex
)

// SaveJA4 сохраняет JA4 отпечаток для указанного IP
func SaveJA4(clientIP, ja4Fingerprint string) {
	cacheMu.Lock()
	ja4Cache[clientIP] = ja4Fingerprint
	cacheMu.Unlock()
}

// GetJA4 получает JA4 отпечаток для указанного IP
func GetJA4(clientIP string) (string, bool) {
	cacheMu.RLock()
	fingerprint, exists := ja4Cache[clientIP]
	cacheMu.RUnlock()
	return fingerprint, exists
}
