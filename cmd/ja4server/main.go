package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/voukatas/go-ja4/internal/cache"
	"github.com/voukatas/go-ja4/internal/model"
	"github.com/voukatas/go-ja4/internal/parser"
	"github.com/voukatas/go-ja4/internal/tcp"
)

type JA4ServerResponse struct {
	JA4Fingerprint string `json:"ja4_fingerprint"`
	ClientIP       string `json:"client_ip"`
	TLSVersion     string `json:"tls_version"`
	UserAgent      string `json:"user_agent,omitempty"`
}

var (
	ja4Cache = make(map[string]string)
	cacheMu  sync.RWMutex
)

type TLSInterceptor struct {
	handler http.Handler
}

func (t *TLSInterceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Пытаемся получить информацию о TLS соединении
	if r.TLS != nil {
		clientIP := getClientIP(r)
		ja4 := generateJA4FromTLS(r.TLS, clientIP)

		cacheMu.Lock()
		ja4Cache[clientIP] = ja4
		cacheMu.Unlock()
	}

	t.handler.ServeHTTP(w, r)
}

func ja4ServerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	clientIP := getClientIP(r)

	// Получаем JA4 отпечаток из кеша
	ja4Fingerprint, exists := cache.GetJA4(clientIP)
	if !exists {
		ja4Fingerprint = "Not captured yet - make HTTPS request to trigger JA4 detection"
	}

	response := JA4ServerResponse{
		JA4Fingerprint: ja4Fingerprint,
		ClientIP:       clientIP,
		TLSVersion:     "Detected from packet capture",
		UserAgent:      r.Header.Get("User-Agent"),
	}

	json.NewEncoder(w).Encode(response)
}

func getClientIP(r *http.Request) string {
	// Проверяем заголовки прокси
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		return forwarded
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Извлекаем IP из RemoteAddr
	host := r.RemoteAddr
	if colon := len(host) - 1; colon >= 0 && host[colon] == ']' {
		// IPv6
		if bracket := len(host) - 1; bracket >= 0 && host[0] == '[' {
			host = host[1:bracket]
		}
	} else {
		// IPv4
		if colon := len(host); colon >= 0 {
			for i := len(host) - 1; i >= 0; i-- {
				if host[i] == ':' {
					host = host[:i]
					break
				}
			}
		}
	}
	return host
}

func generateJA4FromTLS(connState *tls.ConnectionState, clientIP string) string {
	// Упрощенная генерация JA4-подобного отпечатка на основе доступной TLS информации
	// В реальности JA4 требует данных из Client Hello, которые здесь недоступны

	version := ""
	switch connState.Version {
	case tls.VersionTLS10:
		version = "10"
	case tls.VersionTLS11:
		version = "11"
	case tls.VersionTLS12:
		version = "12"
	case tls.VersionTLS13:
		version = "13"
	default:
		version = "00"
	}

	cipher := fmt.Sprintf("%04x", connState.CipherSuite)

	// Генерируем псевдо-JA4 на основе доступных данных
	return fmt.Sprintf("t%s_%s_%s", version, cipher, "simplified")
}

func startPacketCapture(ja4Map map[string]*model.FingerprintRecord) {
	// Открываем сетевой интерфейс для перехвата пакетов
	handle, err := pcap.OpenLive("ens3", 65535, true, pcap.BlockForever)
	if err != nil {
		// Пробуем другие интерфейсы
		handle, err = pcap.OpenLive("eth0", 65535, true, pcap.BlockForever)
		if err != nil {
			log.Printf("Failed to open network interface: %v", err)
			return
		}
	}
	defer handle.Close()

	// Фильтруем только TCP трафик на порт 443 (HTTPS)
	err = handle.SetBPFFilter("tcp port 443")
	if err != nil {
		log.Printf("Failed to set BPF filter: %v", err)
		return
	}

	// Создаем stream factory для обработки TCP потоков
	streamFactory := &tcp.StreamFactory{
		JA4Map: ja4Map,
	}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Printf("Started packet capture on interface, DLT: %v", handle.LinkType())

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				return
			}
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp := tcpLayer.(*layers.TCP)
				assembler.AssembleWithTimestamp(
					packet.NetworkLayer().NetworkFlow(),
					tcp,
					packet.Metadata().Timestamp,
				)
			}
		case <-ticker.C:
			// Очистка старых соединений
			cutoff := time.Now().Add(-2 * time.Minute)
			flushedConn, closedConn := assembler.FlushWithOptions(tcpassembly.FlushOptions{CloseAll: false, T: cutoff})
			log.Printf("FlushWithOptions - flushed: %v closed: %v", flushedConn, closedConn)
		}
	}
}

func main() {
	// Загружаем fingerprints (опционально)
	ja4Map, err := parser.LoadFingerPrints("fingerprints.json")
	if err != nil {
		log.Printf("Warning: Could not load fingerprints: %v", err)
		ja4Map = make(map[string]*model.FingerprintRecord)
	}

	// Запускаем packet capture в отдельной горутине
	go startPacketCapture(ja4Map)

	// Настраиваем HTTP роуты
	mux := http.NewServeMux()
	mux.HandleFunc("/ja4", ja4ServerHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "JA4 Fingerprinting Service\n\nEndpoints:\n- GET /ja4 - Get JA4 fingerprint\n\nMake HTTPS requests to trigger JA4 detection\n")
	})

	// Проверяем наличие Let's Encrypt сертификатов
	certFile := "/etc/letsencrypt/live/djsakli2.online-0001/fullchain.pem"
	keyFile := "/etc/letsencrypt/live/djsakli2.online-0001/privkey.pem"

	// Проверяем существование сертификатов
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		log.Fatal("Certificate file not found:", certFile)
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		log.Fatal("Key file not found:", keyFile)
	}

	// Запускаем HTTP сервер на порту 80
	go func() {
		log.Println("Starting HTTP server on :80")
		if err := http.ListenAndServe(":80", mux); err != nil {
			log.Printf("HTTP server failed: %v", err)
		}
	}()

	// Запускаем HTTPS сервер на порту 443
	log.Println("Starting HTTPS server on :443 with Let's Encrypt certificate")
	log.Println("Starting packet capture for JA4 detection...")
	if err := http.ListenAndServeTLS(":443", certFile, keyFile, mux); err != nil {
		log.Fatal("HTTPS server failed:", err)
	}
}

func generateServerSelfSignedCert() ([]byte, []byte, error) {
	// Генерируем приватный ключ
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Создаем шаблон сертификата
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"JA4 Test"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:    []string{"localhost"},
	}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Кодируем сертификат в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Кодируем приватный ключ в PEM
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return certPEM, keyPEM, nil
}
