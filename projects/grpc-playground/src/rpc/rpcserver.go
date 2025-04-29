package main

import (
	"log"
	"net"
	"net/http"
	"net/rpc"

	"github.com/rabbicse/go-microservice/utils"
)

func main() {
	timeServer := new(utils.TimeServer)
	rpc.Register(timeServer)
	rpc.HandleHTTP()
	l, e := net.Listen("tcp", ":1234")
	if e != nil {
		log.Fatal(e)
	}
	http.Serve(l, nil)
}
