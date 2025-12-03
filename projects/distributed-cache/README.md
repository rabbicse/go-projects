# Distributed Cache Server (Golang)

## Run Server
Write the following command
```
# node 1
go run server.go -port=8001 -peers=http://localhost:8001,http://localhost:8002 -rep=2

# node 2
go run server.go -port=8002 -peers=http://localhost:8001,http://localhost:8002 -rep=2
```