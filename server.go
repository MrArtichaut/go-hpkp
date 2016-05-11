package main

import (
	"fmt"
	"net/http"
)

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
		w.Header().Set(headerName, headerValue)
		handler.ServeHTTP(w, r)
	})
}
