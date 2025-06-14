package main

import (
	"context"
	"log"
	"net"

	"github.com/rabbicse/go-projects/order-microservice/common"
	"google.golang.org/grpc"
)

var (
	grpcAddr = common.EnvString("GRPC_ADDR", "localhost:2000")
)

func main() {
	grpcServer := grpc.NewServer()

	l, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	store := NewStore()
	service := NewService(store)
	NewGrpcHandler(grpcServer, service)

	service.CreateOrder(context.Background())

	log.Printf("GRPC server started at %v", grpcAddr)

	if err := grpcServer.Serve(l); err != nil {
		log.Fatal(err.Error())
	}
}
