package main

import (
	"context"
	"log"
	"net"

	pb "github.com/rabbicse/go-microservice/data/protos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	port = ":50051"
)

type server struct{}

func (s *server) MakeTransaction(ctx context.Context, in *pb.Transactionrequest) (*pb.Transactionresponse, error) {
	return &pb.Transactionresponse{Confirmation: true}, nil
}

func main() {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		panic(err)
	}

	s := grpc.NewServer()
	pb.RegisterMoneyTransactionServer(s, &server{})
	reflection.Register(s)
	if err := s.Serve(lis); err != nil {
		log.Fatal("Failed to serve: %v", err)
	}
}
