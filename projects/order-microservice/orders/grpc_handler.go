package main

import (
	"context"
	"log"

	pb "github.com/rabbicse/go-projects/order-microservice/common/api"
	"google.golang.org/grpc"
)

type grpcHandler struct {
	pb.UnimplementedOrderServiceServer

	service OrdersService
}

func NewGrpcHandler(grpcServer *grpc.Server, service OrdersService) *grpcHandler {
	handler := &grpcHandler{
		service: service,
	}
	pb.RegisterOrderServiceServer(grpcServer, handler)
	return &grpcHandler{}
}

func (h *grpcHandler) CreateOrder(ctx context.Context, payload *pb.CreateOrderRequest) (*pb.Order, error) {
	log.Printf("New order received! Order: %v", payload)
	o := &pb.Order{
		ID: "42",
	}
	return o, nil
}
