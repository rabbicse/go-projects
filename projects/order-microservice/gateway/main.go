package main

import (
	"log"
	"net/http"

	"github.com/rabbicse/go-projects/order-microservice/common"
)

var (
	serviceName = "gateway"
	httpAddr    = common.EnvString("HTTP_ADDR", ":8080")
	consulAddr  = common.EnvString("CONSUL_ADDR", "localhost:8500")
	jaegerAddr  = common.EnvString("JAEGER_ADDR", "localhost:4318")
)

func main() {
	mux := http.NewServeMux()
	handler := NewHandler()
	handler.registerRouters(mux)

	log.Printf("Starting HTTP server at %s", httpAddr)

	if err := http.ListenAndServe(httpAddr, mux); err != nil {
		log.Fatal("Failed to start http server")
	}
}
