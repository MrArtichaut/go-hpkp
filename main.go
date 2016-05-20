package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
)

func main() {

	client := &http.Client{Transport: NewDefaultRoundTripper()}

	resp, err := client.Get("https://report-uri.io/home/tools")
	check(err)

	fmt.Println(resp.Status)

	resp, err = client.Get("https://github.com/")
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

type hpkpMonitor struct {
	notedHosts map[string]clientConfig
}
