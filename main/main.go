package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
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
}

var (
	ja4Cache       = make(map[string]*JA4Response)
	userAgentCache = make(map[string]string)
	cacheMux       = sync.RWMutex{}

	database     = make(map[string]*DatabaseEntry)
	databaseMux  = sync.RWMutex{}
	saveMux      = sync.Mutex{} // Отдельный мьютекс для сохранения файла
	databaseFile = "ja4_database.json"
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

func identifyApplication(userAgent string) string {
	ua := strings.ToLower(userAgent)

	// Common browsers
	if strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg") {
		if strings.Contains(ua, "opr") || strings.Contains(ua, "opera") {
			return "Opera Browser"
		}
		return "Chromium Browser"
	}
	if strings.Contains(ua, "firefox") {
		return "Firefox Browser"
	}
	if strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome") {
		return "Safari Browser"
	}
	if strings.Contains(ua, "edg") {
		return "Microsoft Edge"
	}

	// Common tools
	if strings.Contains(ua, "curl") {
		return "curl"
	}
	if strings.Contains(ua, "wget") {
		return "wget"
	}
	if strings.Contains(ua, "postman") {
		return "Postman"
	}
	if strings.Contains(ua, "python") {
		return "Python"
	}
	if strings.Contains(ua, "go-http-client") {
		return "Go HTTP Client"
	}
	if strings.Contains(ua, "java") {
		return "Java Application"
	}
	if strings.Contains(ua, "node") {
		return "Node.js Application"
	}

	// Mobile browsers
	if strings.Contains(ua, "mobile") || strings.Contains(ua, "android") {
		if strings.Contains(ua, "chrome") {
			return "Chrome Mobile"
		}
		return "Mobile Browser"
	}

	// Bots and crawlers
	if strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "spider") {
		return "Bot/Crawler"
	}

	// If we can't identify, return empty string
	return ""
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

// Асинхронное сохранение без блокировки
func saveDatabaseAsync() {
	go func() {
		if err := saveDatabaseAtomic(); err != nil {
			log.Printf("Async database save failed: %v", err)
		}
	}()
}

// Старая функция для совместимости
func saveDatabase() {
	saveDatabaseAtomic()
}

func updateDatabaseWithUserAgent(ja4Fingerprint, userAgent, clientIP string) {
	if userAgent == "" || userAgent == "Unknown" {
		return
	}

	databaseMux.Lock()
	defer databaseMux.Unlock()

	// Find entry by JA4 fingerprint and similar base IP (without port)
	baseIP := strings.Split(clientIP, ":")[0]
	updated := false

	for keyStr, entry := range database {
		if entry.JA4Fingerprint == ja4Fingerprint {
			entryBaseIP := strings.Split(entry.ClientIP, ":")[0]
			if entryBaseIP == baseIP && (entry.UserAgentString == "Unknown" || entry.UserAgentString == "") {
				// Remove old entry with Unknown UA
				delete(database, keyStr)

				// Create new entry with correct UA
				newKey := ja4Fingerprint + ":" + userAgent
				entry.UserAgentString = userAgent
				entry.Application = identifyApplication(userAgent)
				entry.Timestamp = time.Now()
				entry.ClientIP = clientIP
				database[newKey] = entry

				log.Printf("Updated database entry: %s -> %s (%s)", ja4Fingerprint, userAgent, entry.Application)
				updated = true
				break
			}
		}
	}

	if updated {
		// Немедленное сохранение после обновления
		saveDatabaseAsync()
	}
}

func addToDatabase(ja4Fingerprint, userAgent, clientIP string) {
	databaseMux.Lock()
	defer databaseMux.Unlock()

	// Используем только JA4 + UserAgent как ключ, без IP
	key := ja4Fingerprint + ":" + userAgent

	if entry, exists := database[key]; exists {
		// Update existing entry
		entry.ObservationCount++
		entry.Timestamp = time.Now()
		// Обновляем IP если это более свежая запись
		entry.ClientIP = clientIP
		log.Printf("Updated observation count for %s: %d", ja4Fingerprint, entry.ObservationCount)
	} else {
		// Create new entry
		application := identifyApplication(userAgent)
		database[key] = &DatabaseEntry{
			Application:      application,
			UserAgentString:  userAgent,
			JA4Fingerprint:   ja4Fingerprint,
			ClientIP:         clientIP,
			Timestamp:        time.Now(),
			ObservationCount: 1,
		}
		log.Printf("Added new database entry: %s (%s)", ja4Fingerprint, application)
	}

	// Немедленное сохранение после любого изменения
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

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"JA4 Demo"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("185.21.15.114"), net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func loadCertificate() (tls.Certificate, error) {
	certFile := "certs/server.crt"
	keyFile := "certs/server.key"

	// Проверяем существование файлов сертификата
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Printf("Certificate file not found: %s", certFile)
		return generateSelfSignedCert()
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Printf("Key file not found: %s", keyFile)
		return generateSelfSignedCert()
	}

	// Загружаем сертификат из файлов
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Printf("Failed to load certificate from files: %v", err)
		return generateSelfSignedCert()
	}

	log.Printf("Successfully loaded certificate from files: %s, %s", certFile, keyFile)
	return cert, nil
}

func ja4Handler(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		clientIP = forwarded
	}

	// Get User-Agent from HTTP headers
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}

	// Store User-Agent for this client
	cacheMux.Lock()
	userAgentCache[clientIP] = userAgent
	cacheMux.Unlock()

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

	// Update database with real User-Agent if we have it
	if userAgent != "Unknown" && userAgent != "" {
		updateDatabaseWithUserAgent(response.Fingerprint, userAgent, clientIP)
	}

	// Add user agent and application info to response
	enhancedResponse := struct {
		*JA4Response
		UserAgent   string `json:"user_agent"`
		Application string `json:"application"`
	}{
		JA4Response: response,
		UserAgent:   userAgent,
		Application: identifyApplication(userAgent),
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

	// Pretty print JSON
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.Encode(entries)
}

func exportHandler(w http.ResponseWriter, r *http.Request) {
	// Force save current database
	saveDatabase()

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

func certHandler(w http.ResponseWriter, r *http.Request) {
	certFile := "certs/server.crt"

	file, err := os.Open(certFile)
	if err != nil {
		http.Error(w, "Certificate file not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", "attachment; filename=ja4_server.crt")

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

func main() {
	// Load existing database
	loadDatabase()

	// Запускаем периодическое автосохранение каждые 30 секунд
	startPeriodicSave()

	cert, err := loadCertificate()
	if err != nil {
		log.Fatal("Ошибка загрузки сертификата:", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ja4", ja4Handler)
	mux.HandleFunc("/database", databaseHandler)
	mux.HandleFunc("/export", exportHandler)
	mux.HandleFunc("/cert", certHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Official JA4 Fingerprint Server",
			"endpoints": map[string]string{
				"/ja4":      "Get your JA4 fingerprint",
				"/database": "View collected fingerprints database",
				"/export":   "Download database as JSON file",
				"/cert":     "Download SSL certificate for browser trust",
			},
			"usage":     "Connect via HTTPS to capture your TLS fingerprint",
			"standard":  "Based on official FoxIO JA4 specification",
			"ssl_setup": "Download /cert and install in browser for secure connection",
		})
	})

	server := &http.Server{
		Addr:    ":8443",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				ja4Fingerprint := generateJA4(hello)
				clientIP := hello.Conn.RemoteAddr().String()

				response := parseJA4(ja4Fingerprint, clientIP)

				cacheMux.Lock()
				ja4Cache[clientIP] = response
				cacheMux.Unlock()

				// Get User-Agent from cache if available
				cacheMux.RLock()
				userAgent := userAgentCache[clientIP]
				cacheMux.RUnlock()

				if userAgent == "" {
					userAgent = "Unknown"
				}

				// Add to database
				addToDatabase(ja4Fingerprint, userAgent, clientIP)

				log.Printf("JA4 fingerprint captured for %s: %s (UA: %s)", clientIP, ja4Fingerprint, userAgent)
				return nil, nil
			},
		},
	}

	fmt.Printf("Официальный JA4 сервер запускается на https://185.21.15.114:8443\n")
	fmt.Printf("Основанный на спецификации FoxIO JA4+\n")
	fmt.Printf("База данных автоматически сохраняется в файл: %s\n", databaseFile)
	fmt.Printf("Автосохранение каждые 30 секунд + немедленное сохранение при изменениях\n")
	fmt.Printf("Endpoints:\n")
	fmt.Printf("  GET https://185.21.15.114:8443/ja4 - получить JA4 fingerprint\n")
	fmt.Printf("  GET https://185.21.15.114:8443/database - просмотр собранной базы\n")
	fmt.Printf("  GET https://185.21.15.114:8443/export - скачать базу в JSON\n")
	fmt.Printf("  GET https://185.21.15.114:8443/cert - скачать сертификат для доверия браузеру\n")
	fmt.Printf("  GET https://185.21.15.114:8443/ - информация о сервере\n")

	// Финальное сохранение при завершении
	defer func() {
		log.Printf("Saving database before exit...")
		saveDatabaseAtomic()
	}()

	log.Fatal(server.ListenAndServeTLS("", ""))
}
