package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

type DatabaseEntry struct {
	Application      string    `json:"application"`
	UserAgentString  string    `json:"user_agent_string"`
	JA4Fingerprint   string    `json:"ja4_fingerprint"`
	ClientIP         string    `json:"client_ip,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
	ObservationCount int       `json:"observation_count"`
}

func main() {
	databaseFile := "ja4_database.json"
	backupFile := "ja4_database_backup.json"

	// Создаем бэкап
	if err := copyFile(databaseFile, backupFile); err != nil {
		log.Printf("Warning: failed to create backup: %v", err)
	} else {
		fmt.Printf("Backup created: %s\n", backupFile)
	}

	// Загружаем существующую базу
	file, err := os.Open(databaseFile)
	if err != nil {
		log.Fatal("Error opening database file:", err)
	}
	defer file.Close()

	var entries []DatabaseEntry
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&entries); err != nil {
		log.Fatal("Error decoding database:", err)
	}

	fmt.Printf("Original entries: %d\n", len(entries))

	// Объединяем дубликаты
	merged := make(map[string]*DatabaseEntry)

	for _, entry := range entries {
		key := entry.JA4Fingerprint + ":" + entry.UserAgentString

		if existing, exists := merged[key]; exists {
			// Объединяем счетчики наблюдений
			existing.ObservationCount += entry.ObservationCount
			// Берем более свежую временную метку
			if entry.Timestamp.After(existing.Timestamp) {
				existing.Timestamp = entry.Timestamp
				existing.ClientIP = entry.ClientIP
			}
		} else {
			// Создаем копию записи
			merged[key] = &DatabaseEntry{
				Application:      entry.Application,
				UserAgentString:  entry.UserAgentString,
				JA4Fingerprint:   entry.JA4Fingerprint,
				ClientIP:         entry.ClientIP,
				Timestamp:        entry.Timestamp,
				ObservationCount: entry.ObservationCount,
			}
		}
	}

	// Конвертируем обратно в слайс
	cleanedEntries := make([]DatabaseEntry, 0, len(merged))
	for _, entry := range merged {
		cleanedEntries = append(cleanedEntries, *entry)
	}

	fmt.Printf("Cleaned entries: %d\n", len(cleanedEntries))
	fmt.Printf("Removed duplicates: %d\n", len(entries)-len(cleanedEntries))

	// Сохраняем очищенную базу
	outFile, err := os.Create(databaseFile)
	if err != nil {
		log.Fatal("Error creating output file:", err)
	}
	defer outFile.Close()

	encoder := json.NewEncoder(outFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cleanedEntries); err != nil {
		log.Fatal("Error encoding cleaned database:", err)
	}

	fmt.Printf("Database cleaned successfully!\n")
	fmt.Printf("Backup saved as: %s\n", backupFile)
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}
