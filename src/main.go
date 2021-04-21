package main

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

func HealthCheck(rw http.ResponseWriter, Request *http.Request) {
	currentTime := time.Now()
	io.WriteString(rw, currentTime.String())
}
func main() {
	// http.HandleFunc("/health", HealthCheck)
	// http.ListenAndServe(":9000", nil)
	// mux := &utils.UUID{}
	// http.ListenAndServe(":9000", mux)

	// serve multiple handlers
	newMux := http.NewServeMux()

	newMux.HandleFunc("/randomfloat", func(rw http.ResponseWriter, request *http.Request) {
		fmt.Fprintln(rw, rand.Float64())
	})

	newMux.HandleFunc("/randomint", func(rw http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(rw, rand.Intn(100))
	})

	http.ListenAndServe(":9000", newMux)
}
