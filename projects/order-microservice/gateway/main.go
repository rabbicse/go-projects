package main

import (
	"log"
	"net/http"

	"github.com/rabbicse/go-projects/order-microservice/common"
	pb "github.com/rabbicse/go-projects/order-microservice/common/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	serviceName      = "gateway"
	httpAddr         = common.EnvString("HTTP_ADDR", ":8080")
	consulAddr       = common.EnvString("CONSUL_ADDR", "localhost:8500")
	jaegerAddr       = common.EnvString("JAEGER_ADDR", "localhost:4318")
	orderServiceAddr = "localhost:2000"
)

func main() {

	conn, err := grpc.Dial(orderServiceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to dial server: %v", err)
	}
	defer conn.Close()

	log.Println("Dialing order service at ", orderServiceAddr)

	c := pb.NewOrderServiceClient(conn)

	mux := http.NewServeMux()
	handler := NewHandler(c)
	handler.registerRouters(mux)

	log.Printf("Starting HTTP server at %s", httpAddr)

	if err := http.ListenAndServe(httpAddr, mux); err != nil {
		log.Fatal("Failed to start http server")
	}
}
