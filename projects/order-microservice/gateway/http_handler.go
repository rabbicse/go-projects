package main

import "net/http"

type handler struct {
}

func NewHandler() *handler {
	return &handler{}
}

func (h *handler) registerRouters(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/customers/{customerID}/orders", h.HandleCreateOrder)
}

func (h *handler) HandleCreateOrder(w http.ResponseWriter, r *http.Request) {

}
