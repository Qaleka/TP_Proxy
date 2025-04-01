package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"web_security/cert"
)

var (
	caCert tls.Certificate
	mu     sync.Mutex
)

func main() {
	var err error
	caCert, err = tls.LoadX509KeyPair("ca_cert.pem", "ca_key.pem")
	if err != nil {
		log.Fatal("Ошибка загрузки CA сертификата:", err)
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: http.HandlerFunc(handleRequest),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println("Прокси-сервер запущен на :8080")
	log.Fatal(server.ListenAndServe())
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		handleHTTPS(w, r)
	} else {
		handleHTTP(w, r)
	}
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	log.Println("HTTP-запрос:", r.Method, r.URL)

	r.Header.Del("Proxy-Connection")

	targetURL := *r.URL
	if targetURL.Host == "" {
		targetURL.Host = r.Host
	}
	targetURL.Scheme = "http"

	log.Println("Перенаправление запроса на:", targetURL.String())

	req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
	if err != nil {
		log.Println("Ошибка создания запроса:", err)
		http.Error(w, "Ошибка запроса", http.StatusInternalServerError)
		return
	}

	req.Header = r.Header.Clone()

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println("Ошибка при отправке запроса:", err)
		http.Error(w, "Ошибка запроса", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, v := range resp.Header {
		w.Header()[k] = v
	}

	w.WriteHeader(resp.StatusCode)

	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Println("Ошибка при копировании тела ответа:", err)
	}
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
    hostPort := r.URL.Host
    if hostPort == "" {
        hostPort = r.Host
    }
    if !strings.Contains(hostPort, ":") {
        hostPort += ":443"
    }

    hijacker, ok := w.(http.Hijacker)
    if !ok {
        http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
        return
    }

    clientConn, _, err := hijacker.Hijack()
    if err != nil {
        http.Error(w, "Hijacking failed", http.StatusServiceUnavailable)
        return
    }
    defer clientConn.Close()

    if _, err := clientConn.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n")); err != nil {
        log.Printf("Failed to send connection established: %v", err)
        return
    }

    tlsConfig := generateTLSConfig(strings.Split(hostPort, ":")[0])
    tlsConn := tls.Server(clientConn, tlsConfig)
    defer tlsConn.Close()

    targetConn, err := tls.Dial("tcp", hostPort, &tls.Config{
        InsecureSkipVerify: true,
    })
    if err != nil {
        log.Printf("Failed to connect to target: %v", err)
        return
    }
    defer targetConn.Close()

    errChan := make(chan error, 1)
    go func() {
        _, err := io.Copy(targetConn, tlsConn)
        errChan <- err
    }()
    
    if _, err := io.Copy(tlsConn, targetConn); err != nil {
        log.Printf("Copy error: %v", err)
    }
    
    <-errChan
}

func generateTLSConfig(host string) *tls.Config {
    host = strings.Split(host, ":")[0]
    
    cert, err := cert.GenCert(&caCert, []string{host, "*." + host})
    if err != nil {
        log.Printf("Failed to generate cert: %v", err)
        return &tls.Config{
            InsecureSkipVerify: true,
        }
    }

    return &tls.Config{
        Certificates: []tls.Certificate{*cert},
        MinVersion:   tls.VersionTLS12,
        ServerName:   host,
        NextProtos:   []string{"http/1.1"},
        CipherSuites: []uint16{
            tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_AES_128_GCM_SHA256,
        },
    }
}