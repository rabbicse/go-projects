package main

import (
	"context"
	"log"

	pb "github.com/rabbicse/go-microservice/data/protos"
	"google.golang.org/grpc"
)

const (
	address = "localhost:50051"
)

func main() {
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		panic(err)
	}

	defer conn.Close()
	c := pb.NewMoneyTransactionClient(conn)

	from := "1234"
	to := "5678"
	amount := float32(1240.75)

	r, err := c.MakeTransaction(context.Background(), &pb.Transactionrequest{From: from, To: to, Amount: amount})
	if err != nil {
		panic(err)
	}
	log.Printf("Transaction confirmed: %t", r.Confirmation)

}
