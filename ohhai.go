package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Helper function to convert a slice of slog.Attr to a slice of any.
// This is necessary to pass a pre-built slice of attributes to variadic functions
// like slog.Info() or slog.Group().
func attrsToAnys(attrs []slog.Attr) []any {
	anys := make([]any, len(attrs))
	for i, attr := range attrs {
		anys[i] = attr
	}
	return anys
}

// Running context
type RunningContext struct {
	SystemHostname string `json:"system_hostname"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
	UIDMapContent  string `json:"uid_map_content,omitempty"`
	GIDMapContent  string `json:"gid_map_content,omitempty"`
}

// CertificateInfo holds details about a single TLS certificate.
type CertificateInfo struct {
	SubjectCommonName  string   `json:"subject_common_name"`
	IssuerCommonName   string   `json:"issuer_common_name"`
	DNSNames           []string `json:"dns_names"`
	IPAddresses        []string `json:"ip_addresses"`
	NotBefore          string   `json:"not_before"`
	NotAfter           string   `json:"not_after"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
}

// TLSInfo holds details about the TLS connection.
type TLSInfo struct {
	VerificationError string            `json:"verification_error,omitempty"`
	CertificateChain  []CertificateInfo `json:"certificate_chain,omitempty"`
}

// ExternalFetchResult structure for the fetched URL response
type ExternalFetchResult struct {
	URL              string   `json:"url"`
	StatusCode       int      `json:"status_code,omitempty"`
	ContentType      string   `json:"content_type,omitempty"`
	RedirectLocation string   `json:"redirect_location,omitempty"` // For 3xx responses
	Body             string   `json:"body,omitempty"`
	Error            string   `json:"error,omitempty"`
	ResolvedIP       string   `json:"resolved_ip,omitempty"`
	SourcePort       int      `json:"source_port,omitempty"`
	TLSInfo          *TLSInfo `json:"tls_info,omitempty"`
}

// DNSQueryResult holds the result of a DNS lookup.
type DNSQueryResult struct {
	Query   string   `json:"query"`
	Records []string `json:"records,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// RequestInfo structure to organize our response
type RequestInfo struct {
	Method              string               `json:"method"`
	Path                string               `json:"path"`
	HTTPVersion         string               `json:"http_version"`
	Host                string               `json:"host"`
	RemoteAddr          string               `json:"remote_addr"`
	Timestamp           string               `json:"timestamp"`
	Headers             map[string]string    `json:"headers"`
	RunContext          RunningContext       `json:"running_context"`
	ExternalFetchResult *ExternalFetchResult `json:"external_fetch_result,omitempty"`
	DNSQueryResult      *DNSQueryResult      `json:"dns_query_result,omitempty"`
}

const (
	defaultPort          = "8080"
	externalFetchTimeout = 10 * time.Second
	maxExternalBodySize  = 1 * 1024 * 1024 // 1MB
	envFetchURL          = "FETCH_URL"     // Environment variable name
	schemeHTTP           = "http"
	schemeHTTPS          = "https"
	headerContentType    = "Content-Type" // Defined constant for Content-Type header
)

var (
	globalFetchURL string
)

func readFileContent(filePath string) (string, error) {
	contentBytes, err := os.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("could not read %s: %w", filePath, err)
	}
	return strings.TrimSpace(string(contentBytes)), nil
}

func getRunningContext() RunningContext {
	systemHostname, err := os.Hostname()
	if err != nil {
		// *** MODIFIED: Using slog
		slog.Error("failed to get system hostname", "error", err)
		systemHostname = "unknown"
	}
	runCtx := RunningContext{
		SystemHostname: systemHostname,
		UID:            os.Getuid(),
		GID:            os.Getgid(),
	}
	uidMapContent, err := readFileContent("/proc/self/uid_map")
	if err == nil {
		runCtx.UIDMapContent = uidMapContent
	} else if !errors.Is(err, os.ErrNotExist) {
		// *** MODIFIED: Using slog
		slog.Warn("could not read uid_map", "error", err)
	}
	gidMapContent, err := readFileContent("/proc/self/gid_map")
	if err == nil {
		runCtx.GIDMapContent = gidMapContent
	} else if !errors.Is(err, os.ErrNotExist) {
		// *** MODIFIED: Using slog
		slog.Warn("could not read gid_map", "error", err)
	}
	return runCtx
}

func performDNSQuery(query string) *DNSQueryResult {
	if query == "" {
		return nil
	}

	result := &DNSQueryResult{Query: query}

	lastDot := strings.LastIndex(query, ".")
	if lastDot == -1 || lastDot == 0 || lastDot == len(query)-1 {
		result.Error = "Invalid query format. Expected format: 'domain.com.TYPE' (e.g., example.com.A)"
		return result
	}

	domain := query[:lastDot]
	recordType := strings.ToUpper(query[lastDot+1:])

	var err error
	switch recordType {
	case "A":
		ips, errLookup := net.LookupHost(domain)
		if errLookup != nil {
			err = errLookup
		} else {
			result.Records = ips
		}
	case "AAAA":
		ips, errLookup := net.LookupIP(domain)
		if errLookup != nil {
			err = errLookup
		} else {
			for _, ip := range ips {
				if ip.To4() == nil {
					result.Records = append(result.Records, ip.String())
				}
			}
		}
	case "CNAME":
		cname, errLookup := net.LookupCNAME(domain)
		if errLookup != nil {
			err = errLookup
		} else {
			result.Records = []string{cname}
		}
	case "TXT":
		txts, errLookup := net.LookupTXT(domain)
		if errLookup != nil {
			err = errLookup
		} else {
			result.Records = txts
		}
	case "MX":
		mxs, errLookup := net.LookupMX(domain)
		if errLookup != nil {
			err = errLookup
		} else {
			for _, mx := range mxs {
				result.Records = append(result.Records, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
			}
		}
	case "NS":
		nss, errLookup := net.LookupNS(domain)
		if errLookup != nil {
			err = errLookup
		} else {
			for _, ns := range nss {
				result.Records = append(result.Records, ns.Host)
			}
		}
	default:
		err = fmt.Errorf("unsupported record type: %s", recordType)
	}

	if err != nil {
		result.Error = err.Error()
	}

	if len(result.Records) == 0 && result.Error == "" {
		result.Error = "No records found"
	}

	return result
}

func fetchExternalURL(parentCtx context.Context, fetchURL string) *ExternalFetchResult {
	if fetchURL == "" {
		return nil
	}

	efr := &ExternalFetchResult{URL: fetchURL}

	parsedURL, errURLParse := url.ParseRequestURI(fetchURL)
	if errURLParse != nil {
		efr.Error = fmt.Sprintf("Invalid FETCH_URL: %v", errURLParse)
		return efr
	}
	if parsedURL.Scheme != schemeHTTP && parsedURL.Scheme != schemeHTTPS {
		efr.Error = "Invalid FETCH_URL scheme: only http and https are allowed."
		return efr
	}

	ctx, cancel := context.WithTimeout(parentCtx, externalFetchTimeout)
	defer cancel()

	var resolvedIP string
	var sourcePort int
	var tlsInfo *TLSInfo

	transport := http.DefaultTransport.(*http.Transport).Clone()

	if parsedURL.Scheme == "https" {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				tlsInfo = &TLSInfo{}
				certs := cs.PeerCertificates
				if len(certs) > 0 {
					opts := x509.VerifyOptions{
						DNSName:       parsedURL.Hostname(),
						Intermediates: x509.NewCertPool(),
					}
					for _, cert := range certs[1:] {
						opts.Intermediates.AddCert(cert)
					}
					if _, err := certs[0].Verify(opts); err != nil {
						tlsInfo.VerificationError = err.Error()
					}
				}
				for _, cert := range certs {
					var ips []string
					for _, ip := range cert.IPAddresses {
						ips = append(ips, ip.String())
					}
					tlsInfo.CertificateChain = append(tlsInfo.CertificateChain, CertificateInfo{
						SubjectCommonName:  cert.Subject.CommonName,
						IssuerCommonName:   cert.Issuer.CommonName,
						DNSNames:           cert.DNSNames,
						IPAddresses:        ips,
						NotBefore:          cert.NotBefore.Format(time.RFC3339),
						NotAfter:           cert.NotAfter.Format(time.RFC3339),
						SignatureAlgorithm: cert.SignatureAlgorithm.String(),
					})
				}
				return nil
			},
		}
	}

	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if remoteTCPAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			resolvedIP = remoteTCPAddr.IP.String()
		}
		if localTCPAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			sourcePort = localTCPAddr.Port
		}
		return conn, nil
	}

	client := http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fetchURL, nil)
	if err != nil {
		efr.Error = fmt.Sprintf("Error creating request to %s: %v", fetchURL, err)
		return efr
	}
	req.Header.Set("User-Agent", "http-info-server/1.0 (+https://github.com/stefancaspersz)")

	resp, err := client.Do(req)
	efr.TLSInfo = tlsInfo

	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			efr.Error = fmt.Sprintf("Timeout fetching %s after %s", fetchURL, externalFetchTimeout)
		} else {
			efr.Error = fmt.Sprintf("Error fetching %s: %v", fetchURL, err)
		}
		return efr
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			// *** MODIFIED: Using slog
			slog.Error("failed to close response body", "url", fetchURL, "error", errClose)
		}
	}()

	efr.StatusCode = resp.StatusCode
	efr.ContentType = resp.Header.Get(headerContentType)
	efr.ResolvedIP = resolvedIP
	efr.SourcePort = sourcePort

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		efr.RedirectLocation = resp.Header.Get("Location")
	}

	limitedReader := &io.LimitedReader{R: resp.Body, N: maxExternalBodySize}
	bodyBytes, errRead := io.ReadAll(limitedReader)

	if errRead != nil {
		efr.Error = fmt.Sprintf("Error reading response body from %s: %v", fetchURL, errRead)
	} else {
		efr.Body = string(bodyBytes)
		if limitedReader.N == 0 && (resp.ContentLength > maxExternalBodySize || resp.ContentLength == -1) {
			efr.Body += fmt.Sprintf("\n... (response truncated at %d bytes)", maxExternalBodySize)
		}
	}
	return efr
}

func headersHandler(w http.ResponseWriter, r *http.Request) {
	headers := make(map[string]string)
	for name, values := range r.Header {
		headers[name] = values[0]
	}
	runCtx := getRunningContext()
	response := RequestInfo{
		Method:      r.Method,
		Path:        r.URL.Path,
		HTTPVersion: r.Proto,
		Host:        r.Host,
		RemoteAddr:  r.RemoteAddr,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Headers:     headers,
		RunContext:  runCtx,
	}

	var efr *ExternalFetchResult
	fetchURLParam := r.URL.Query().Get("fetch_url")
	if fetchURLParam != "" {
		efr = fetchExternalURL(r.Context(), fetchURLParam)
	} else if globalFetchURL != "" {
		efr = fetchExternalURL(r.Context(), globalFetchURL)
	}
	if efr != nil {
		response.ExternalFetchResult = efr
	}

	dnsQueryParam := r.URL.Query().Get("dns_query")
	if dnsQueryParam != "" {
		response.DNSQueryResult = performDNSQuery(dnsQueryParam)
	}

	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		slog.Error("failed to marshal response JSON", "error", err)
		http.Error(w, "Error converting data to JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set(headerContentType, "application/json")
	if _, err := w.Write(jsonData); err != nil {
		slog.Error("failed to write response", "error", err)
		return
	}

	// Replaced manual logging with a single slog.Info call.
	// This is much cleaner and ensures structured output without manual JSON marshalling.
	uidMapLines := 0
	if runCtx.UIDMapContent != "" {
		uidMapLines = len(strings.Split(runCtx.UIDMapContent, "\n"))
	}
	gidMapLines := 0
	if runCtx.GIDMapContent != "" {
		gidMapLines = len(strings.Split(runCtx.GIDMapContent, "\n"))
	}

	logAttrs := []slog.Attr{
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("proto", r.Proto),
		slog.String("host", r.Host),
		slog.String("remote_addr", r.RemoteAddr),
		slog.String("system_hostname", runCtx.SystemHostname),
		slog.Int("uid", runCtx.UID),
		slog.Int("gid", runCtx.GID),
		slog.Int("uid_map_lines", uidMapLines),
		slog.Int("gid_map_lines", gidMapLines),
	}

	if trueClientIP := r.Header.Get("True-Client-Ip"); trueClientIP != "" {
		logAttrs = append(logAttrs, slog.String("true_client_ip", trueClientIP))
	}

	if efr != nil {
		// Build the arguments for the group as a slice of `any`.
		// This is the most direct and correct way to do it.
		groupArgs := []any{"url", efr.URL}
		if efr.Error != "" {
			groupArgs = append(groupArgs, "error", efr.Error)
		} else {
			groupArgs = append(groupArgs, "status_code", efr.StatusCode)
			if efr.RedirectLocation != "" {
				groupArgs = append(groupArgs, "redirect_location", efr.RedirectLocation)
			}
		}
		// Now, create the group attribute and append it.
		logAttrs = append(logAttrs, slog.Group("external_fetch", groupArgs...))
	}

	if dnsQueryParam != "" {
		logAttrs = append(logAttrs, slog.String("dns_query", dnsQueryParam))
	}

	// The final call to slog.Info still needs the helper function,
	// because `logAttrs` is of type []slog.Attr.
	slog.Info("request processed", attrsToAnys(logAttrs)...)
}

func readyzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("OK")); err != nil {
		// *** MODIFIED: Using slog
		slog.Error("failed to write readyz response", "error", err)
	}
}

func main() {
	// *** NEW: Configure slog to be the default logger.
	// We use a JSONHandler to produce structured, machine-readable logs.
	// This replaces the old `log.New(...)` call.
	jsonHandler := slog.NewJSONHandler(os.Stdout, nil)
	slog.SetDefault(slog.New(jsonHandler))

	globalFetchURL = os.Getenv(envFetchURL)
	if globalFetchURL != "" {
		slog.Info("configured to fetch external URL by default", "url", globalFetchURL)
		parsedURL, errURLParse := url.ParseRequestURI(globalFetchURL)
		if errURLParse != nil {
			slog.Warn("invalid FETCH_URL environment variable",
				"url", globalFetchURL,
				"error", errURLParse.Error())
		} else if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			slog.Warn("invalid scheme in FETCH_URL environment variable",
				"url", globalFetchURL,
				"scheme", parsedURL.Scheme)
		}
	} else {
		slog.Info("no FETCH_URL environment variable set")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", readyzHandler)
	mux.HandleFunc("/", headersHandler)
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}
	addr := fmt.Sprintf(":%s", port)
	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("server starting", "port", port)
		serverErrors <- server.ListenAndServe()
	}()
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-serverErrors:
		if !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server failed to start or encountered an error", "error", err)
			os.Exit(1) // Fatal error
		}
	case sig := <-shutdown:
		slog.Info("received signal, starting graceful shutdown", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			slog.Error("graceful shutdown failed", "error", err)
			if errClose := server.Close(); errClose != nil {
				slog.Error("failed to forcefully close server", "error", errClose)
			}
		} else {
			slog.Info("server gracefully stopped")
		}
	}
	slog.Info("application exit")
}
