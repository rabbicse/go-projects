package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func HealthCheck(rw http.ResponseWriter, Request *http.Request) {
	currentTime := time.Now()
	io.WriteString(rw, currentTime.String())
}
func ArticleHandler(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "Category is: %v", vars["category"])
	fmt.Fprintf(rw, "ID is: %v", vars["id"])
}
func NumGenerator() func() int {
	var i = 0
	return func() int {
		i++
		return i
	}
}

func middleware(originalHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		fmt.Println("Executing middleware.. before request phase")
		originalHandler.ServeHTTP(rw, r)
		fmt.Println("Executing middlware after request phase")
	})
}

func handle(rw http.ResponseWriter, req *http.Request) {
	fmt.Println("Executing main handler...")
	rw.Write([]byte("OK"))
}

type city struct {
	Name string
	Area uint64
}

func main() {
	// http.HandleFunc("/health", HealthCheck)
	// http.ListenAndServe(":9000", nil)
	// mux := &utils.UUID{}
	// http.ListenAndServe(":9000", mux)

	// serve multiple handlers
	// newMux := http.NewServeMux()

	// newMux.HandleFunc("/randomfloat", func(rw http.ResponseWriter, request *http.Request) {
	// 	fmt.Fprintln(rw, rand.Float64())
	// })

	// newMux.HandleFunc("/randomint", func(rw http.ResponseWriter, req *http.Request) {
	// 	fmt.Fprintln(rw, rand.Intn(100))
	// })

	// http.ListenAndServe(":9000", newMux)

	// gorilla
	// router := mux.NewRouter()
	// router.HandleFunc("/articles/{category}/{id:[0-9]+}", ArticleHandler)
	// server := &http.Server{
	// 	Addr:    "127.0.0.1:9000",
	// 	Handler: router,
	// }
	// log.Fatal(server.ListenAndServe())

	// gen := NumGenerator()
	// for i := 0; i < 5; i++ {
	// 	fmt.Print(gen(), "\t")
	// }

	originalHandler := http.HandlerFunc(handle)
	http.Handle("/", middleware(originalHandler))
	http.ListenAndServe(":9000", nil)
}
