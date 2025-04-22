package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
	"web_security/cert"
)

type ParsedRequest struct {
	Host            string            `json:"host"`
	ID              int               `json:"id"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	QueryParams     map[string]string `json:"get_params"`
	Headers         map[string]string `json:"headers"`
	Cookies         map[string]string `json:"cookies"`
	PostParams      map[string]string `json:"post_params"`
	Body            string            `json:"body"`
	ResponseCode    int               `json:"response_code"`
	ResponseBody    string            `json:"response_body"`
	ResponseHeaders map[string]string `json:"response_headers"`
}

var (
	caCert tls.Certificate
	mu     sync.Mutex
	db     *sql.DB
)

func main() {
	var err error
	caCert, err = tls.LoadX509KeyPair("ca_cert.pem", "ca_key.pem")
	if err != nil {
		log.Fatal("Ошибка загрузки CA сертификата:", err)
	}
	initDB()
	go startAPI()

	server := &http.Server{
		Addr:           ":8080",
		Handler:        http.HandlerFunc(handleRequest),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println("Прокси-сервер запущен на :8080")
	log.Fatal(server.ListenAndServe())
}

func initDB() {
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	dbname := os.Getenv("POSTGRES_DB")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal("Ошибка подключения к PostgreSQL:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS requests (
		host TEXT,
		id SERIAL PRIMARY KEY,
		method TEXT, path TEXT, query_params TEXT,
		headers TEXT, cookies TEXT, post_params TEXT,
		body TEXT, response_code INTEGER,
		response_headers TEXT, response_body TEXT);`)
	if err != nil {
		log.Fatal("Ошибка создания таблицы:", err)
	}
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

	parsed := parseRequest(r)
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

	respBody, respHeaders, respCode := parseResponse(resp)
	parsed.ResponseBody = respBody
	parsed.ResponseCode = respCode
	parsed.ResponseHeaders = respHeaders
	parsed.ID = int(saveRequest(parsed))

	for k, v := range resp.Header {
		w.Header()[k] = v
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, bytes.NewBufferString(respBody))
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
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake failed: %v", err)
		return
	}
	defer tlsConn.Close()

	req, err := http.ReadRequest(bufio.NewReader(tlsConn))
	if err != nil {
		log.Printf("Failed to read HTTPS request: %v", err)
		return
	}

	parsed := parseRequest(req)
	req.URL.Scheme = "https"
	req.URL.Host = hostPort
	req.RequestURI = ""

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error forwarding HTTPS request: %v", err)
		return
	}
	defer resp.Body.Close()

	respBody, respHeaders, respCode := parseResponse(resp)
	parsed.ResponseBody = respBody
	parsed.ResponseCode = respCode
	parsed.ResponseHeaders = respHeaders
	parsed.ID = int(saveRequest(parsed))

	resp.Write(tlsConn)
}

func generateTLSConfig(host string) *tls.Config {
	host = strings.Split(host, ":")[0]
	cert, err := cert.GenCert(&caCert, []string{host, "*." + host})
	if err != nil {
		log.Printf("Failed to generate cert: %v", err)
		return &tls.Config{InsecureSkipVerify: true}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		ServerName:   host,
		NextProtos:   []string{"http/1.1"},
	}
}

func parseRequest(r *http.Request) ParsedRequest {
	parsed := ParsedRequest{Method: r.Method, Path: r.URL.Path, Host: r.Host, QueryParams: map[string]string{}, Headers: map[string]string{}, Cookies: map[string]string{}, PostParams: map[string]string{}}
	for k, v := range r.URL.Query() {
		parsed.QueryParams[k] = v[0]
	}
	for k, v := range r.Header {
		parsed.Headers[k] = v[0]
	}
	for _, c := range r.Cookies() {
		parsed.Cookies[c.Name] = c.Value
	}
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		r.ParseForm()
		for k, v := range r.PostForm {
			parsed.PostParams[k] = v[0]
		}
	}
	body, _ := ioutil.ReadAll(r.Body)
	parsed.Body = string(body)
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	return parsed
}

func parseResponse(resp *http.Response) (string, map[string]string, int) {
	bodyBytes, _ := ioutil.ReadAll(resp.Body)
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, _ := gzip.NewReader(bytes.NewReader(bodyBytes))
		bodyBytes, _ = ioutil.ReadAll(reader)
		reader.Close()
	}
	headers := map[string]string{}
	for k, v := range resp.Header {
		headers[k] = v[0]
	}
	return string(bodyBytes), headers, resp.StatusCode
}

func saveRequest(req ParsedRequest) int64 {
	qp, _ := json.Marshal(req.QueryParams)
	h, _ := json.Marshal(req.Headers)
	c, _ := json.Marshal(req.Cookies)
	pp, _ := json.Marshal(req.PostParams)
	rh, _ := json.Marshal(req.ResponseHeaders)
	_, err := db.Exec(`INSERT INTO requests (host, method, path, query_params, headers, cookies, post_params, body, response_code, response_headers, response_body) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, req.Host, req.Method, req.Path, qp, h, c, pp, req.Body, req.ResponseCode, rh, req.ResponseBody)
	if err != nil {
		log.Println("Ошибка сохранения запроса:", err)
		return -1
	}
	id := int64(0)
	db.QueryRow("SELECT LASTVAL()").Scan(&id)
	return id
}

func startAPI() {
	r := mux.NewRouter()
	r.HandleFunc("/requests", listRequests).Methods("GET")
	r.HandleFunc("/requests/{id}", getRequest).Methods("GET")
	r.HandleFunc("/repeat/{id}", repeatRequest).Methods("POST")
	r.HandleFunc("/scan/{id}", scanRequest).Methods("POST")
	log.Println("API слушает на :8000")
	http.ListenAndServe(":8000", r)
}

func listRequests(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, method, path FROM requests ORDER BY id DESC")
	if err != nil {
		http.Error(w, "DB error", 500)
		return
	}
	defer rows.Close()
	type Summary struct {
		ID           int
		Method, Path string
	}
	var result []Summary
	for rows.Next() {
		var s Summary
		rows.Scan(&s.ID, &s.Method, &s.Path)
		result = append(result, s)
	}
	json.NewEncoder(w).Encode(result)
}

func repeatRequest(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	row := db.QueryRow("SELECT host, method, path, query_params, headers, cookies, post_params, body FROM requests WHERE id = $1", id)
	var host, method, path, qp, h, c, pp, body string
	err := row.Scan(&host, &method, &path, &qp, &h, &c, &pp, &body)
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	url := "http://" + host + path
	req, _ := http.NewRequest(method, url, bytes.NewBufferString(body))

	var headers, cookies, postParams map[string]string
	json.Unmarshal([]byte(h), &headers)
	json.Unmarshal([]byte(c), &cookies)
	json.Unmarshal([]byte(pp), &postParams)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for k, v := range cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Ошибка повторного запроса", 500)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func scanRequest(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	row := db.QueryRow("SELECT host, method, path, query_params, headers, cookies, post_params, body FROM requests WHERE id = $1", id)

	var host, method, path, qp, h, c, pp, body string
	err := row.Scan(&host, &method, &path, &qp, &h, &c, &pp, &body)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		log.Println("Scan error: not found")
		return
	}

	file, err := os.Open("dicc.txt")
	if err != nil {
		http.Error(w, "Не найден словарь dicc.txt", http.StatusInternalServerError)
		log.Println("File open error:", err)
		return
	}
	defer file.Close()

	var headers map[string]string
	if err := json.Unmarshal([]byte(h), &headers); err != nil || headers == nil {
		headers = make(map[string]string)
	}

	scanner := bufio.NewScanner(file)
	client := &http.Client{Timeout: 1 * time.Second}

	results := make(chan string, 1000)
	var wg sync.WaitGroup
	maxGoroutines := 5
	sem := make(chan struct{}, maxGoroutines)

	for scanner.Scan() {
		word := scanner.Text()
		wg.Add(1)
		sem <- struct{}{}

		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()

			target := fmt.Sprintf("http://%s/%s", host, word)
			req, err := http.NewRequest(method, target, bytes.NewBufferString(body))
			if err != nil {
				log.Printf("Ошибка создания запроса для %s: %v", target, err)
				return
			}

			for k, v := range headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Ошибка выполнения запроса к %s: %v", target, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 429 {
				log.Printf("Сервер заблокировал запрос (429): %s", target)
				return
			}
			if resp.StatusCode != 404 {
				fmt.Println(word, resp.StatusCode)
				results <- fmt.Sprintf("%s -> %d", word, resp.StatusCode)
			}
		}(word)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	found := []string{}
	for r := range results {
		found = append(found, r)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"found": found,
	})
}

func getRequest(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	row := db.QueryRow("SELECT host, method, path, query_params, headers, cookies, post_params, body, response_code, response_headers, response_body FROM requests WHERE id = $1", id)
	var pr ParsedRequest
	var qp, h, c, pp, rh string
	err := row.Scan(&pr.Host, &pr.Method, &pr.Path, &qp, &h, &c, &pp, &pr.Body, &pr.ResponseCode, &rh, &pr.ResponseBody)
	if err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	json.Unmarshal([]byte(qp), &pr.QueryParams)
	json.Unmarshal([]byte(h), &pr.Headers)
	json.Unmarshal([]byte(c), &pr.Cookies)
	json.Unmarshal([]byte(pp), &pr.PostParams)
	json.Unmarshal([]byte(rh), &pr.ResponseHeaders)
	pr.ID, _ = strconv.Atoi(id)
	json.NewEncoder(w).Encode(pr)
}
