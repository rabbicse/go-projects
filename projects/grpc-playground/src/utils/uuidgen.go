package utils

import (
	"crypto/rand"
	"fmt"
	"net/http"
)

type UUID struct {
}

func (uuid *UUID) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path == "/" {
		giveRandomUUID(rw, req)
		return
	}
	http.NotFound(rw, req)
	return
}

func giveRandomUUID(rw http.ResponseWriter, request *http.Request) {
	c := 10
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	fmt.Fprintf(rw, fmt.Sprintf("%x", b))
}
