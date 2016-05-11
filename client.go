package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

type clientConfig struct {
	HpkpConfig
	notedHostname string
	notedDate     time.Time
}

type roundTripper struct {
	roundTripper   http.RoundTripper
	tlsState       *tls.ConnectionState
	checkNeeded    bool
	config         *clientConfig
	hpkpConfigHash []byte
}

func NewRoundTripper(t *http.Transport) http.RoundTripper {
	h := &roundTripper{roundTripper: t}

	dialer := t.DialTLS

	if dialer == nil {
		dialer = tls.Dial
	}

	t.DialTLS = func(network, addr string) (net.Conn, error) {
		conn, err := dialer(network, addr)
		if err != nil {
			return conn, err
		}

		tlsConn, ok := conn.(tls.Conn)
		if ok == false {
			panic("DialTLS must return a tls.Conn compatible connection")
		}

		state := tlsConn.ConnectionState()
		h.tlsState = &state

		fmt.Println("Connection state retrieved")

		return conn, err
	}

	return h
}

func NewDefaultRoundTripper() http.RoundTripper {
	t := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return NewRoundTripper(t)
}

func (h *roundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := h.roundTripper.RoundTrip(req)
	if err != nil {
		return resp, err
	}

	fmt.Println("host: ", req.Host)

	err = h.updateConfig(req, resp)
	if err != nil {
		return resp, err
	}

	if h.config == nil || h.checkNeeded == false {
		fmt.Println("No config or no need to check")
		return resp, err
	}

	matchPin := func(cert *x509.Certificate) bool {
		pin, err := pinFromCertificate(cert)
		if err != nil {
			log.Println("Error while extracting pin from certificate", cert.Subject.CommonName, cert.SerialNumber, ":", err)
			return false
		}

		for _, knownPin := range h.config.Pins {
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
				h.checkNeeded = false
				fmt.Println("GOOD PINNING")
				return resp, err
			}
		}
	}

	//No cert matching know pins
	if h.config.ReportUri != nil {

	}

	fmt.Println("BAD PINNING")

	return resp, nil
}

func (h *roundTripper) updateConfig(req *http.Request, resp *http.Response) error {
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

	config, err := parseHeader(header)
	if err != nil {
		return err
	}

	config.ReportOnly = reportOnly

	h.config = &clientConfig{
		HpkpConfig:    config,
		notedHostname: req.Host,
		notedDate:     time.Now()}

	h.hpkpConfigHash = hash[:]

	fmt.Println("noted hostname", h.config.notedHostname)
	h.checkNeeded = true
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

func buildViolationReport(config *clientConfig, req *http.Request) *violationReport {
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
func newHeaderParsingError(details string) error {
	return fmt.Errorf("Error while parsing HTTP Public Key Pinning header: %s", details)
}

func parseHeader(h string) (HpkpConfig, error) {
	pinsRegExp, err := regexp.Compile("pin-sha256=\"([A-z0-9+=/]+)\"")
	must(err)

	pinsMatches := pinsRegExp.FindAllStringSubmatch(h, math.MaxInt32)
	if pinsMatches == nil {
		return nil, newHeaderParsingError("no pins found")
	}

	pins := make([]string, len(pinsMatches))
	for idx, m := range pinsMatches {
		pins[idx] = m[1]
	}

	maxAgeRegExp, err := regexp.Compile("max-age=([0-9]+)")
	must(err)

	maxAgeMatch := maxAgeRegExp.FindStringSubmatch(h)
	if maxAgeMatch == nil {
		return nil, newHeaderParsingError("no max age found")
	}
	maxAge, err := strconv.Atoi(maxAgeMatch[1])
	if maxAgeMatch == nil {
		return nil, newHeaderParsingError("invalid max age value")
	}

	config := HpkpConfig{Pins: pins, MaxAge: uint(maxAge)}

	reportUriRegExp, err := regexp.Compile("report-uri=\"(.+)\"")
	must(err)

	reportUriMatch := reportUriRegExp.FindStringSubmatch(h)
	if len(reportUriMatch) > 0 {
		uri := reportUriMatch[1]
		config.ReportUri, err = url.Parse(uri)
		return nil, newHeaderParsingError("invalid report url")
	}

	config.IncludeSubdomains = strings.Contains(h, "includeSubdomains")

	return config
}

func must(err error) {
	if err != nil {
		panic("")
	}
}
