package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mssola/user_agent"
	"golang.org/x/crypto/acme/autocert"
)

type JA4Response struct {
	Fingerprint string      `json:"fingerprint"`
	Analysis    JA4Analysis `json:"analysis"`
	Timestamp   time.Time   `json:"timestamp"`
	ClientIP    string      `json:"client_ip"`
}

type JA4Analysis struct {
	Protocol       string `json:"protocol"`
	ProtocolDesc   string `json:"protocol_description"`
	TLSVersion     string `json:"tls_version"`
	TLSVersionDesc string `json:"tls_version_description"`
	SNI            string `json:"sni"`
	SNIDesc        string `json:"sni_description"`
	CipherCount    string `json:"cipher_count"`
	ExtCount       string `json:"extension_count"`
	ALPN           string `json:"alpn"`
	CipherHash     string `json:"cipher_hash"`
	ExtensionHash  string `json:"extension_hash"`
}

type DatabaseEntry struct {
	Application      string    `json:"application"`
	UserAgentString  string    `json:"user_agent_string"`
	JA4Fingerprint   string    `json:"ja4_fingerprint"`
	ClientIP         string    `json:"client_ip,omitempty"`
	Timestamp        time.Time `json:"timestamp"`
	ObservationCount int       `json:"observation_count"`
	Browser          string    `json:"browser,omitempty"`
	BrowserVersion   string    `json:"browser_version,omitempty"`
	OS               string    `json:"os,omitempty"`
	Mobile           bool      `json:"mobile,omitempty"`
	Bot              bool      `json:"bot,omitempty"`
}

type PendingEntry struct {
	JA4Fingerprint string
	ClientIP       string
	Timestamp      time.Time
}

var (
	ja4Cache       = make(map[string]*JA4Response)
	userAgentCache = make(map[string]string)
	cacheMux       = sync.RWMutex{}

	database     = make(map[string]*DatabaseEntry)
	databaseMux  = sync.RWMutex{}
	saveMux      = sync.Mutex{}
	databaseFile = "ja4_database.json"

	// Система ожидающих записей
	pendingEntries = make(map[string]*PendingEntry) // key: clientIP
	pendingMux     = sync.RWMutex{}
	pendingTimeout = 30 * time.Second
)

// GREASE values as defined in RFC 8701
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

func isGREASE(value uint16) bool {
	return greaseValues[value]
}

func filterGREASE(values []uint16) []uint16 {
	var filtered []uint16
	for _, v := range values {
		if !isGREASE(v) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func sha256Hash12(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:6])
}

func cipherSuitesToString(ciphers []uint16) string {
	var parts []string
	for _, cipher := range ciphers {
		parts = append(parts, fmt.Sprintf("%04x", cipher))
	}
	return strings.Join(parts, ",")
}

func extensionsToString(extensions []uint16) string {
	var parts []string
	for _, ext := range extensions {
		// Exclude SNI (0x0000) and ALPN (0x0010) as per JA4 spec
		if ext != 0x0000 && ext != 0x0010 {
			parts = append(parts, fmt.Sprintf("%04x", ext))
		}
	}
	return strings.Join(parts, ",")
}

func identifyApplication(userAgentString string) (string, string, string, string, bool, bool) {
	if userAgentString == "" || userAgentString == "Unknown" {
		return "", "", "", "", false, false
	}

	ua := user_agent.New(userAgentString)

	// Определяем браузер и версию
	browser, version := ua.Browser()
	engineName, engineVersion := ua.Engine()
	osInfo := ua.OS()
	isMobile := ua.Mobile()
	isBot := ua.Bot()

	var application string
	var browserInfo string
	var browserVersion string
	var osName string

	// Обработка ботов
	if isBot {
		application = "Bot/Crawler"
		browserInfo = browser
		if browser == "" {
			// Fallback для специфичных ботов
			uaLower := strings.ToLower(userAgentString)
			if strings.Contains(uaLower, "googlebot") {
				browserInfo = "Googlebot"
			} else if strings.Contains(uaLower, "bingbot") {
				browserInfo = "Bingbot"
			} else if strings.Contains(uaLower, "facebookexternalhit") {
				browserInfo = "Facebook Bot"
			} else if strings.Contains(uaLower, "twitterbot") {
				browserInfo = "Twitter Bot"
			} else {
				browserInfo = "Unknown Bot"
			}
		}
		return application, browserInfo, version, osInfo, isMobile, isBot
	}

	// Обработка командных утилит
	uaLower := strings.ToLower(userAgentString)
	if strings.Contains(uaLower, "curl") {
		application = "curl"
		browserInfo = "curl"
		// Извлекаем версию curl
		if strings.Contains(uaLower, "curl/") {
			parts := strings.Split(userAgentString, "curl/")
			if len(parts) > 1 {
				versionPart := strings.Fields(parts[1])[0]
				browserVersion = versionPart
			}
		}
		return application, browserInfo, browserVersion, osInfo, false, false
	}

	if strings.Contains(uaLower, "wget") {
		application = "wget"
		browserInfo = "wget"
		if strings.Contains(uaLower, "wget/") {
			parts := strings.Split(userAgentString, "Wget/")
			if len(parts) > 1 {
				versionPart := strings.Fields(parts[1])[0]
				browserVersion = versionPart
			}
		}
		return application, browserInfo, browserVersion, osInfo, false, false
	}

	if strings.Contains(uaLower, "postman") {
		application = "Postman"
		browserInfo = "Postman"
		return application, browserInfo, "", osInfo, false, false
	}

	if strings.Contains(uaLower, "python") {
		application = "Python"
		browserInfo = "Python"
		if strings.Contains(uaLower, "python/") {
			parts := strings.Split(userAgentString, "Python/")
			if len(parts) > 1 {
				versionPart := strings.Fields(parts[1])[0]
				browserVersion = versionPart
			}
		}
		return application, browserInfo, browserVersion, osInfo, false, false
	}

	if strings.Contains(uaLower, "go-http-client") {
		application = "Go HTTP Client"
		browserInfo = "Go"
		return application, browserInfo, "", osInfo, false, false
	}

	// Обработка браузеров
	browserInfo = browser
	browserVersion = version
	osName = osInfo

	// Определяем тип приложения для браузеров
	if isMobile {
		switch browser {
		case "Chrome":
			application = "Chrome Mobile"
		case "Safari":
			application = "Safari Mobile"
		case "Firefox":
			application = "Firefox Mobile"
		case "Opera":
			application = "Opera Mobile"
		case "Edge":
			application = "Edge Mobile"
		default:
			application = "Mobile Browser"
		}
	} else {
		switch browser {
		case "Chrome":
			application = "Chrome Browser"
		case "Safari":
			application = "Safari Browser"
		case "Firefox":
			application = "Firefox Browser"
		case "Opera":
			application = "Opera Browser"
		case "Edge":
			application = "Microsoft Edge"
		case "Internet Explorer":
			application = "Internet Explorer"
		default:
			if browser != "" {
				application = browser + " Browser"
			} else {
				// Fallback анализ
				if strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "edg") {
					application = "Chrome Browser"
					browserInfo = "Chrome"
				} else if strings.Contains(uaLower, "firefox") {
					application = "Firefox Browser"
					browserInfo = "Firefox"
				} else if strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome") {
					application = "Safari Browser"
					browserInfo = "Safari"
				} else if strings.Contains(uaLower, "edg") {
					application = "Microsoft Edge"
					browserInfo = "Edge"
				} else {
					application = "Unknown Browser"
					browserInfo = "Unknown"
				}
			}
		}
	}

	// Если engine информация доступна и browser пустой
	if browserInfo == "" && engineName != "" {
		browserInfo = engineName
		browserVersion = engineVersion
	}

	return application, browserInfo, browserVersion, osName, isMobile, isBot
}

func loadDatabase() {
	databaseMux.Lock()
	defer databaseMux.Unlock()

	file, err := os.Open(databaseFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Database file doesn't exist, creating new one")
			return
		}
		log.Printf("Error opening database file: %v", err)
		return
	}
	defer file.Close()

	var entries []DatabaseEntry
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&entries); err != nil {
		log.Printf("Error decoding database: %v", err)
		return
	}

	// Load entries into map
	for _, entry := range entries {
		key := entry.JA4Fingerprint + ":" + entry.UserAgentString
		database[key] = &entry
	}

	log.Printf("Loaded %d entries from database", len(entries))
}

func saveDatabaseAtomic() error {
	saveMux.Lock()
	defer saveMux.Unlock()

	databaseMux.RLock()
	entries := make([]DatabaseEntry, 0, len(database))
	for _, entry := range database {
		entries = append(entries, *entry)
	}
	databaseMux.RUnlock()

	// Атомарная запись через временный файл
	tempFile := databaseFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		log.Printf("Error creating temp database file: %v", err)
		return err
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(entries); err != nil {
		file.Close()
		os.Remove(tempFile)
		log.Printf("Error encoding database: %v", err)
		return err
	}

	if err := file.Close(); err != nil {
		os.Remove(tempFile)
		log.Printf("Error closing temp database file: %v", err)
		return err
	}

	// Атомарное переименование
	if err := os.Rename(tempFile, databaseFile); err != nil {
		os.Remove(tempFile)
		log.Printf("Error renaming temp database file: %v", err)
		return err
	}

	log.Printf("Successfully saved %d entries to database", len(entries))
	return nil
}

func saveDatabaseAsync() {
	go func() {
		if err := saveDatabaseAtomic(); err != nil {
			log.Printf("Async database save failed: %v", err)
		}
	}()
}

func cleanupPendingEntries() {
	pendingMux.Lock()
	defer pendingMux.Unlock()

	cutoff := time.Now().Add(-pendingTimeout)
	for key, entry := range pendingEntries {
		if entry.Timestamp.Before(cutoff) {
			delete(pendingEntries, key)
			log.Printf("Removed expired pending entry for %s", key)
		}
	}
}

func startPendingCleanup() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			cleanupPendingEntries()
		}
	}()
}

func updateDatabaseWithUserAgent(ja4Fingerprint, userAgentString, clientIP string) {
	if userAgentString == "" || userAgentString == "Unknown" {
		return
	}

	databaseMux.Lock()
	defer databaseMux.Unlock()

	baseIP := strings.Split(clientIP, ":")[0]
	updated := false

	// Парсим User-Agent
	application, browser, browserVersion, os, isMobile, isBot := identifyApplication(userAgentString)

	for keyStr, entry := range database {
		if entry.JA4Fingerprint == ja4Fingerprint {
			entryBaseIP := strings.Split(entry.ClientIP, ":")[0]
			if entryBaseIP == baseIP && (entry.UserAgentString == "Unknown" || entry.UserAgentString == "") {
				delete(database, keyStr)

				newKey := ja4Fingerprint + ":" + userAgentString
				entry.UserAgentString = userAgentString
				entry.Application = application
				entry.Browser = browser
				entry.BrowserVersion = browserVersion
				entry.OS = os
				entry.Mobile = isMobile
				entry.Bot = isBot
				entry.Timestamp = time.Now()
				entry.ClientIP = clientIP
				database[newKey] = entry

				log.Printf("Updated database entry: %s -> %s (%s %s on %s)",
					ja4Fingerprint, userAgentString, browser, browserVersion, os)
				updated = true
				break
			}
		}
	}

	if updated {
		saveDatabaseAsync()
	}
}

func addToDatabase(ja4Fingerprint, userAgentString, clientIP string) {
	databaseMux.Lock()
	defer databaseMux.Unlock()

	// Если User-Agent неизвестен, добавляем в pending
	if userAgentString == "" || userAgentString == "Unknown" {
		pendingMux.Lock()
		pendingEntries[clientIP] = &PendingEntry{
			JA4Fingerprint: ja4Fingerprint,
			ClientIP:       clientIP,
			Timestamp:      time.Now(),
		}
		pendingMux.Unlock()
		log.Printf("Added pending entry for %s: %s", clientIP, ja4Fingerprint)
		return
	}

	key := ja4Fingerprint + ":" + userAgentString

	if entry, exists := database[key]; exists {
		entry.ObservationCount++
		entry.Timestamp = time.Now()
		entry.ClientIP = clientIP
		log.Printf("Updated observation count for %s: %d", ja4Fingerprint, entry.ObservationCount)
	} else {
		// Парсим User-Agent
		application, browser, browserVersion, os, isMobile, isBot := identifyApplication(userAgentString)

		database[key] = &DatabaseEntry{
			Application:      application,
			UserAgentString:  userAgentString,
			JA4Fingerprint:   ja4Fingerprint,
			ClientIP:         clientIP,
			Timestamp:        time.Now(),
			ObservationCount: 1,
			Browser:          browser,
			BrowserVersion:   browserVersion,
			OS:               os,
			Mobile:           isMobile,
			Bot:              isBot,
		}
		log.Printf("Added new database entry: %s (%s %s %s on %s)",
			ja4Fingerprint, application, browser, browserVersion, os)
	}

	saveDatabaseAsync()
}

// Official JA4 implementation based on FoxIO specification
func generateJA4(hello *tls.ClientHelloInfo) string {
	// 1. Protocol type
	protocol := "t" // TCP by default
	if hello.Conn != nil {
		switch hello.Conn.LocalAddr().Network() {
		case "udp", "sctp":
			protocol = "d"
		case "quic":
			protocol = "q"
		}
	}

	// 2. TLS Version (highest supported)
	var version string
	if len(hello.SupportedVersions) > 0 {
		supportedVersions := slices.Clone(hello.SupportedVersions)
		slices.Sort(supportedVersions)
		maxVersion := supportedVersions[len(supportedVersions)-1]

		switch maxVersion {
		case tls.VersionTLS10:
			version = "10"
		case tls.VersionTLS11:
			version = "11"
		case tls.VersionTLS12:
			version = "12"
		case tls.VersionTLS13:
			version = "13"
		case 0x0300: // SSL 3.0
			version = "s3"
		case 0x0002: // SSL 2.0
			version = "s2"
		case 0xfeff: // DTLS 1.0
			version = "d1"
		case 0xfefd: // DTLS 1.2
			version = "d2"
		case 0xfefc: // DTLS 1.3
			version = "d3"
		default:
			version = "00"
		}
	} else {
		version = "00"
	}

	// 3. SNI present/absent
	sni := "i" // absent
	if hello.ServerName != "" {
		sni = "d" // present
	}

	// 4. Cipher Suites
	filteredCiphers := filterGREASE(hello.CipherSuites)
	cipherCount := fmt.Sprintf("%02d", min(len(filteredCiphers), 99))

	// Sort ciphers for hash calculation
	sortedCiphers := slices.Clone(filteredCiphers)
	slices.Sort(sortedCiphers)
	cipherHash := sha256Hash12(cipherSuitesToString(sortedCiphers))

	// 5. Extensions
	filteredExtensions := filterGREASE(hello.Extensions)
	extCount := fmt.Sprintf("%02d", min(len(filteredExtensions), 99))

	// Sort extensions for hash calculation (excluding SNI and ALPN)
	sortedExtensions := slices.Clone(filteredExtensions)
	slices.Sort(sortedExtensions)
	extensionString := extensionsToString(sortedExtensions)

	// Add signature algorithms if present
	if slices.Contains(hello.Extensions, 0x000d) {
		var sigAlgs []string
		for _, sigAlg := range hello.SignatureSchemes {
			if !isGREASE(uint16(sigAlg)) {
				sigAlgs = append(sigAlgs, fmt.Sprintf("%04x", sigAlg))
			}
		}
		if len(sigAlgs) > 0 {
			extensionString += "_" + strings.Join(sigAlgs, ",")
		}
	}

	extensionHash := sha256Hash12(extensionString)

	// 6. ALPN
	alpn := "00"
	if len(hello.SupportedProtos) > 0 {
		firstALPN := hello.SupportedProtos[0]
		if len(firstALPN) >= 2 {
			alpn = fmt.Sprintf("%c%c", firstALPN[0], firstALPN[len(firstALPN)-1])
		} else if len(firstALPN) == 1 {
			alpn = fmt.Sprintf("%c%c", firstALPN[0], firstALPN[0])
		}

		// Check for non-ASCII characters
		if firstALPN[0] > 127 || (len(firstALPN) > 1 && firstALPN[len(firstALPN)-1] > 127) {
			alpn = "99"
		}
	}

	// Construct final JA4 fingerprint
	return fmt.Sprintf("%s%s%s%s%s%s_%s_%s",
		protocol, version, sni, cipherCount, extCount, alpn,
		cipherHash, extensionHash)
}

func parseJA4(fingerprint, clientIP string) *JA4Response {
	parts := strings.Split(fingerprint, "_")
	analysis := JA4Analysis{}

	if len(parts) >= 3 {
		firstPart := parts[0]
		if len(firstPart) >= 7 {
			protocol := string(firstPart[0])
			version := firstPart[1:3]
			sni := string(firstPart[3])
			cipherCount := firstPart[4:6]
			extCount := firstPart[6:8]

			analysis.Protocol = protocol
			switch protocol {
			case "t":
				analysis.ProtocolDesc = "TCP"
			case "d":
				analysis.ProtocolDesc = "UDP/DTLS"
			case "q":
				analysis.ProtocolDesc = "QUIC"
			default:
				analysis.ProtocolDesc = "Unknown"
			}

			analysis.TLSVersion = version
			switch version {
			case "13":
				analysis.TLSVersionDesc = "TLS 1.3"
			case "12":
				analysis.TLSVersionDesc = "TLS 1.2"
			case "11":
				analysis.TLSVersionDesc = "TLS 1.1"
			case "10":
				analysis.TLSVersionDesc = "TLS 1.0"
			case "s3":
				analysis.TLSVersionDesc = "SSL 3.0"
			case "s2":
				analysis.TLSVersionDesc = "SSL 2.0"
			default:
				analysis.TLSVersionDesc = "Unknown"
			}

			analysis.SNI = sni
			if sni == "d" {
				analysis.SNIDesc = "Present"
			} else {
				analysis.SNIDesc = "Absent"
			}

			analysis.CipherCount = cipherCount
			analysis.ExtCount = extCount

			if len(firstPart) >= 9 {
				analysis.ALPN = firstPart[8:]
			}
		}

		if len(parts) >= 2 {
			analysis.CipherHash = parts[1]
		}
		if len(parts) >= 3 {
			analysis.ExtensionHash = parts[2]
		}
	}

	return &JA4Response{
		Fingerprint: fingerprint,
		Analysis:    analysis,
		Timestamp:   time.Now(),
		ClientIP:    clientIP,
	}
}

func ja4Handler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}

	cacheMux.Lock()
	userAgentCache[clientIP] = userAgent
	cacheMux.Unlock()

	// Проверяем pending записи
	if userAgent != "Unknown" && userAgent != "" {
		pendingMux.Lock()
		if pendingEntry, exists := pendingEntries[clientIP]; exists {
			delete(pendingEntries, clientIP)
			pendingMux.Unlock()

			// Добавляем запись с реальным User-Agent
			addToDatabase(pendingEntry.JA4Fingerprint, userAgent, clientIP)
			log.Printf("Processed pending entry for %s with User-Agent: %s", clientIP, userAgent)
		} else {
			pendingMux.Unlock()
		}
	}

	cacheMux.RLock()
	response, exists := ja4Cache[clientIP]
	cacheMux.RUnlock()

	if !exists {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"error": "JA4 fingerprint not captured. Make sure to connect via HTTPS.",
		})
		return
	}

	if userAgent != "Unknown" && userAgent != "" {
		updateDatabaseWithUserAgent(response.Fingerprint, userAgent, clientIP)
	}

	application, browser, browserVersion, os, isMobile, isBot := identifyApplication(userAgent)

	enhancedResponse := struct {
		*JA4Response
		UserAgent      string `json:"user_agent"`
		Application    string `json:"application"`
		Browser        string `json:"browser,omitempty"`
		BrowserVersion string `json:"browser_version,omitempty"`
		OS             string `json:"os,omitempty"`
		Mobile         bool   `json:"mobile,omitempty"`
		Bot            bool   `json:"bot,omitempty"`
	}{
		JA4Response:    response,
		UserAgent:      userAgent,
		Application:    application,
		Browser:        browser,
		BrowserVersion: browserVersion,
		OS:             os,
		Mobile:         isMobile,
		Bot:            isBot,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enhancedResponse)
}

func databaseHandler(w http.ResponseWriter, r *http.Request) {
	databaseMux.RLock()
	entries := make([]DatabaseEntry, 0, len(database))
	for _, entry := range database {
		entries = append(entries, *entry)
	}
	databaseMux.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(entries)
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	saveDatabaseAtomic()

	file, err := os.Open(databaseFile)
	if err != nil {
		http.Error(w, "Database file not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=ja4_database.json")
	io.Copy(w, file)
}

func startPeriodicSave() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			if err := saveDatabaseAtomic(); err != nil {
				log.Printf("Periodic database save failed: %v", err)
			}
		}
	}()
}

// HTTP redirect server
func redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	target := "https://" + r.Host + r.URL.Path
	if len(r.URL.RawQuery) > 0 {
		target += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

func pendingHandler(w http.ResponseWriter, r *http.Request) {
	pendingMux.RLock()
	entries := make([]PendingEntry, 0, len(pendingEntries))
	for _, entry := range pendingEntries {
		entries = append(entries, *entry)
	}
	pendingMux.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(map[string]interface{}{
		"pending_count": len(entries),
		"entries":       entries,
	})
}

func main() {
	// Проверяем переменные окружения
	domain := os.Getenv("DOMAIN")
	if domain == "" {
		log.Fatal("DOMAIN environment variable is required (e.g. ja4.yourdomain.com)")
	}

	email := os.Getenv("EMAIL")
	if email == "" {
		log.Fatal("EMAIL environment variable is required for Let's Encrypt")
	}

	// Load existing database
	loadDatabase()

	// Запускаем периодическое автосохранение
	startPeriodicSave()

	// Запускаем периодическое очищение pending записей
	startPendingCleanup()

	// Let's Encrypt autocert manager
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domain),   // Только наш домен
		Cache:      autocert.DirCache("certs-cache"), // Кеш сертификатов
		Email:      email,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ja4", ja4Handler)
	mux.HandleFunc("/database", databaseHandler)
	mux.HandleFunc("/export", exportHandler)
	mux.HandleFunc("/pending", pendingHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Official JA4 Fingerprint Server with Let's Encrypt",
			"endpoints": map[string]string{
				"/ja4":      "Get your JA4 fingerprint",
				"/database": "View collected fingerprints database",
				"/export":   "Download database as JSON file",
				"/pending":  "View pending TLS sessions without User-Agent",
			},
			"usage":    "Connect via HTTPS to capture your TLS fingerprint",
			"standard": "Based on official FoxIO JA4 specification",
			"ssl":      "Powered by Let's Encrypt automatic certificates",
		})
	})

	// HTTPS server
	httpsServer := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				ja4Fingerprint := generateJA4(hello)
				clientIP := hello.Conn.RemoteAddr().String()

				response := parseJA4(ja4Fingerprint, clientIP)

				cacheMux.Lock()
				ja4Cache[clientIP] = response
				cacheMux.Unlock()

				cacheMux.RLock()
				userAgent := userAgentCache[clientIP]
				cacheMux.RUnlock()

				if userAgent == "" {
					userAgent = "Unknown"
				}

				addToDatabase(ja4Fingerprint, userAgent, clientIP)

				log.Printf("JA4 fingerprint captured for %s: %s (UA: %s)", clientIP, ja4Fingerprint, userAgent)
				return nil, nil
			},
		},
	}

	// HTTP redirect server
	httpServer := &http.Server{
		Addr:    ":80",
		Handler: certManager.HTTPHandler(http.HandlerFunc(redirectToHTTPS)),
	}

	fmt.Printf("🔐 JA4 Fingerprint Server with Let's Encrypt\n")
	fmt.Printf("Domain: %s\n", domain)
	fmt.Printf("Email: %s\n", email)
	fmt.Printf("Database: %s\n", databaseFile)
	fmt.Printf("Certificate cache: certs-cache/\n")
	fmt.Printf("\n")
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  GET https://%s/ja4 - получить JA4 fingerprint\n", domain)
	fmt.Printf("  GET https://%s/database - просмотр собранной базы\n", domain)
	fmt.Printf("  GET https://%s/export - скачать базу в JSON\n", domain)
	fmt.Printf("  GET https://%s/pending - просмотр ожидающих TLS сессий\n", domain)
	fmt.Printf("  GET https://%s/ - информация о сервере\n", domain)
	fmt.Printf("\n")
	fmt.Printf("Starting servers...\n")
	fmt.Printf("HTTP :80 -> redirect to HTTPS\n")
	fmt.Printf("HTTPS :443 -> JA4 server\n")

	// Финальное сохранение при завершении
	defer func() {
		log.Printf("Saving database before exit...")
		saveDatabaseAtomic()
	}()

	// Запускаем HTTP сервер в горутине
	go func() {
		log.Printf("Starting HTTP redirect server on :80")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// Запускаем HTTPS сервер
	log.Printf("Starting HTTPS server on :443")
	log.Fatal(httpsServer.ListenAndServeTLS("", ""))
}
