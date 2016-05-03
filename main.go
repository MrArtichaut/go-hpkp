package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func main() {

	client := &http.Client{Transport: NewHpkpRoundTripper()}

	resp, err := client.Get("https://report-uri.io/home/tools")
	check(err)

	fmt.Println(resp.Status)

	resp, err = client.Get("https://www.facebook.com/")
	check(err)

	fmt.Println(resp.Status)

	//	reportUri, _ := url.Parse("https://other.example.net/pkp-report")
	//
	//	config := HpkpConfig{
	//		ReportOnly:        false,
	//		IncludeSubdomains: true,
	//		MaxAge:            888888,
	//		Pins:              []string{"E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=", "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ="},
	//		ReportUri:         reportUri}
	//
	//	http.ListenAndServe(":8080", Hpkp(config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//		w.Write([]byte("Hello world!"))
	//	})))
}

type HpkpConfig struct {
	ReportOnly        bool
	ReportUri         *url.URL
	IncludeSubdomains bool
	MaxAge            uint
	Pins              []string
}

type HpkpClientConfig struct {
	HpkpConfig
	notedHostname string
	notedDate     time.Time
}

func Hpkp(config HpkpConfig, handler http.Handler) http.Handler {
	var headerValue string
	for _, pin := range config.Pins {
		headerValue += fmt.Sprintf("pin-256=\"%s\"; ", pin)
	}

	headerValue += fmt.Sprintf("max-age=%d", config.MaxAge)

	if config.IncludeSubdomains {
		headerValue += "; includeSubdomains"
	}

	if config.ReportUri != nil {
		headerValue += fmt.Sprintf("; report-uri=\"%s\"", config.ReportUri)
	}

	var headerName string
	if config.ReportOnly {
		headerName = "Public-Key-Pins-Report-Only"
	} else {
		headerName = "Public-Key-Pins"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add(headerName, headerValue)
		handler.ServeHTTP(w, r)
	})
}

type HpkpReportHandler struct {
	w *bufio.Writer
}

func NewHpkpReportHandler(w io.Writer) *HpkpReportHandler {
	return &HpkpReportHandler{w: bufio.NewWriter(w)}
}

func (hrp *HpkpReportHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	hrp.w.ReadFrom(req.Body)
	hrp.w.Flush()
}

type HpkpRoundTripper struct {
	roundTripper   http.RoundTripper
	tlsState       *tls.ConnectionState
	needCheck      bool
	hpkpConfig     *HpkpClientConfig
	hpkpConfigHash []byte
}

func NewHpkpRoundTripper() http.RoundTripper {
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	h := &HpkpRoundTripper{roundTripper: t}
	t.DialTLS = h.Dial
	return h
}

type hpkpMonitor struct {
	notedHosts map[string]HpkpClientConfig
}

func (h *HpkpRoundTripper) Dial(network, addr string) (net.Conn, error) {
	conn, err := tls.Dial(network, addr, nil)
	if err != nil {
		return conn, err
	}

	state := conn.ConnectionState()
	h.tlsState = &state

	fmt.Println("Connection state retrieved")

	return conn, err
}

func (h *HpkpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := h.roundTripper.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	fmt.Println("host: ", req.Host)

	h.updateHpkpConfig(req, resp)

	if h.hpkpConfig == nil || h.needCheck == false {
		fmt.Println("No config or no need to check")
		return resp, err
	}

	matchPin := func(cert *x509.Certificate) bool {
		pin, err := pinFromCertificate(cert)
		check(err)

		for _, knownPin := range h.hpkpConfig.Pins {
			if pin == knownPin {
				return true
			}
		}
		return false
	}

	if h.tlsState == nil {
		fmt.Println("NO TLS STATE")
		return resp, err
	}

	for _, chain := range h.tlsState.VerifiedChains {
		for _, cert := range chain {
			if matchPin(cert) {
				h.needCheck = false
				fmt.Println("GOOD PINNING")
				return resp, err
			}
		}
	}

	//No cert matching know pins
	if h.hpkpConfig.ReportUri != nil {

	}

	fmt.Println("BAD PINNING")

	return resp, nil
}

func (h *HpkpRoundTripper) updateHpkpConfig(req *http.Request, resp *http.Response) {
	reportOnly := false
	header := resp.Header.Get("Public-Key-Pins")
	if header == "" {
		header = resp.Header.Get("public-key-pins-report-only")
		if header == "" {
			return
		}
		reportOnly = true
	}

	fmt.Println("pin header", header)

	hash := sha1.Sum([]byte(header))
	if h.hpkpConfigHash != nil && bytes.Compare(hash[:], h.hpkpConfigHash) == 0 {
		fmt.Println("No change in hpkp config")
		return
	}

	fmt.Println("New or update hpkp config")

	config := parseHpkpHeader(header)
	config.ReportOnly = reportOnly

	h.hpkpConfig = &HpkpClientConfig{
		HpkpConfig:       config,
		h.hpkpConfigHash: hash[:],
		notedHostname:    req.Host,
		notedDate:        time.Now()}

	fmt.Println("noted hostname", h.hpkpConfig.notedHostname)
	h.needCheck = true
}

type violationReport struct {
	dateTime          time.Time `json:"date-time"`
	hostname          string    `json:"hostname"`
	port              int       `json:"port"`
	expirationDate    time.Time `json:"expiration-date-time"`
	includeSubdomains bool      `json:"include-subdomains"`
	notedHostname     string    `json:"noted-hostname"`
	servedChain       []string  `json:"served-certificate-chain"`
	validatedChain    []string  `json:"validated-certificate-chain"`
	knownPins         []string  `json:"known-pins"`
}

func buildViolationReport(config *HpkpClientConfig, req *http.Request) *violationReport {
	report := violationReport{}

	now := time.Now()

	report.dateTime = now

	host := req.Host
	if parts := strings.Split(host, ":"); len(parts) > 1 {
		report.hostname = parts[0]
		report.port, _ = strconv.Atoi(parts[1])
	} else {
		report.hostname = host
		report.port = 443
	}

	report.expirationDate = now.Add(time.Duration(config.MaxAge) * time.Second)
	report.includeSubdomains = config.IncludeSubdomains
	report.notedHostname = config.notedHostname

	report.knownPins = config.Pins

	/*
			{
		     "date-time": date-time,
		     "hostname": hostname,
		     "port": port,
		     "effective-expiration-date": expiration-date,
		     "include-subdomains": include-subdomains,
		     "noted-hostname": noted-hostname,
		     "served-certificate-chain": [
		       pem1, ... pemN
		     ],
		     "validated-certificate-chain": [
		       pem1, ... pemN
		     ],
		     "known-pins": [
		       known-pin1, ... known-pinN
		     ]
		   }

	*/

	return nil
}

func pinFromCertificate(cert *x509.Certificate) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}
	return pinFromPublicDERPKey(b), nil
}

func pinFromPublicDERPKey(b []byte) string {
	digest := sha256.Sum256(b)
	return base64.StdEncoding.EncodeToString(digest[:])
}

func parseHpkpHeader(h string) HpkpConfig {
	pinsRegExp, err := regexp.Compile("pin-sha256=\"([A-z0-9+=/]+)\"")
	check(err)

	pinsMatches := pinsRegExp.FindAllStringSubmatch(h, math.MaxInt32)
	if pinsMatches == nil {
		//error
	}

	pins := make([]string, len(pinsMatches))
	for idx, m := range pinsMatches {
		pins[idx] = m[1]
	}

	maxAgeRegExp, err := regexp.Compile("max-age=([0-9]+)")
	check(err)

	maxAgeMatch := maxAgeRegExp.FindStringSubmatch(h)
	if maxAgeMatch == nil {
		// error
	}
	maxAge, err := strconv.Atoi(maxAgeMatch[1])
	check(err)

	config := HpkpConfig{Pins: pins, MaxAge: uint(maxAge)}

	reportUriRegExp, err := regexp.Compile("report-uri=\"(.+)\"")
	check(err)

	reportUriMatch := reportUriRegExp.FindStringSubmatch(h)
	if len(reportUriMatch) > 0 {
		uri := reportUriMatch[1]
		config.ReportUri, err = url.Parse(uri)
		check(err)
	}

	config.IncludeSubdomains = strings.Contains(h, "includeSubdomains")

	return config
}

func check(err error, v ...interface{}) {
	if err != nil {
		if v != nil {
			log.Fatalln(v...)
		}
		log.Fatalln(err)
	}
}
