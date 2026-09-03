// Minimal stand-in for accounts-api so the supply chain is executable end-to-end.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

type accessLog struct {
	Route     string `json:"route"`
	Status    int    `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	RequestID string `json:"request_id"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if _, err := os.Stat("/var/secrets/db/password"); err != nil && os.Getenv("ALLOW_NO_DB") == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w.WriteHeader(http.StatusNotImplemented)
		entry, _ := json.Marshal(accessLog{
			Route:     "/",
			Status:    http.StatusNotImplemented,
			LatencyMS: time.Since(start).Milliseconds(),
			RequestID: r.Header.Get("X-Request-Id"),
		})
		log.Println(string(entry))
	})

	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Println(`{"msg":"accounts-api listening","port":8080}`)
	log.Fatal(srv.ListenAndServe())
}
