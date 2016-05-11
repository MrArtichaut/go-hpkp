package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/url"
)

type HpkpConfig struct {
	ReportOnly        bool
	ReportUri         *url.URL
	IncludeSubdomains bool
	MaxAge            uint
	Pins              []string
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
