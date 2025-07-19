package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"realtime-server-monitoring/internal/hardware"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
)

// Constants
const (
	Port                    = ":8080"
	StaticFilesDir          = "./htmx"
	UpdateInterval          = 3 * time.Second
	WriteTimeout            = 5 * time.Second
	SubscriberBufferSize    = 10
	GracefulShutdownTimeout = 10 * time.Second
	TimestampFormat         = "2006-01-02 15:04:05"
)

// Message represents a broadcast message to subscribers
type Message struct {
	Timestamp string
	System    string
	CPU       string
	Disk      string
}

// Subscriber represents a connected WebSocket client
type Subscriber struct {
	conn *websocket.Conn
	msgs chan []byte
}

// Server manages the application state
type Server struct {
	subscribers   map[*Subscriber]struct{}
	subscribersMu sync.RWMutex
	mux           http.ServeMux
}

// NewServer creates a new Server instance
func NewServer() *Server {
	s := &Server{
		subscribers: make(map[*Subscriber]struct{}),
	}

	s.mux.Handle("/", http.FileServer(http.Dir(StaticFilesDir)))
	s.mux.HandleFunc("/ws", s.handleWebSocket)

	return s
}

// Start begins the server and monitoring loop
func (s *Server) Start() error {
	// Setup graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	httpServer := &http.Server{
		Addr:    Port,
		Handler: &s.mux,
	}

	// Start monitoring loop
	go s.monitorSystem()

	// Start HTTP server
	go func() {
		fmt.Printf("Starting server on %s\n", Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Error starting server: %v\n", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	<-stop
	fmt.Println("\nShutting down server...")

	// Create shutdown context
	ctx, cancel := context.WithTimeout(context.Background(), GracefulShutdownTimeout)
	defer cancel()

	// Close all WebSocket connections
	s.closeAllConnections()

	// Shutdown HTTP server
	if err := httpServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("error shutting down server: %w", err)
	}

	fmt.Println("Server stopped gracefully")
	return nil
}

// monitorSystem collects and broadcasts system metrics
func (s *Server) monitorSystem() {
	ticker := time.NewTicker(UpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		msg, err := s.collectSystemData()
		if err != nil {
			fmt.Printf("Error collecting system data: %v\n", err)
			continue
		}

		s.broadcast(msg)
	}
}

// collectSystemData gathers all system metrics
func (s *Server) collectSystemData() ([]byte, error) {
	var msg Message
	var err error

	msg.Timestamp = time.Now().Format(TimestampFormat)

	if msg.System, err = hardware.GetSystemSection(); err != nil {
		return nil, fmt.Errorf("error getting system data: %w", err)
	}

	if msg.CPU, err = hardware.GetCpuSection(); err != nil {
		return nil, fmt.Errorf("error getting CPU data: %w", err)
	}

	if msg.Disk, err = hardware.GetDiskSection(); err != nil {
		return nil, fmt.Errorf("error getting disk data: %w", err)
	}

	html := fmt.Sprintf(`
		<div hx-swap-oob="innerHTML:#update-timestamp">
			<p><i style="color: green" class="fa fa-circle"></i> %s</p>
		</div>
		<div hx-swap-oob="innerHTML:#system-data">%s</div>
		<div hx-swap-oob="innerHTML:#cpu-data">%s</div>
		<div hx-swap-oob="innerHTML:#disk-data">%s</div>`,
		msg.Timestamp, msg.System, msg.CPU, msg.Disk)

	return []byte(html), nil
}

// handleWebSocket manages WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		fmt.Printf("Error accepting WebSocket connection: %v\n", err)
		return
	}

	sub := &Subscriber{
		conn: conn,
		msgs: make(chan []byte, SubscriberBufferSize),
	}

	s.addSubscriber(sub)
	defer s.removeSubscriber(sub)

	ctx := conn.CloseRead(r.Context())

	for {
		select {
		case msg := <-sub.msgs:
			ctx, cancel := context.WithTimeout(ctx, WriteTimeout)
			err := conn.Write(ctx, websocket.MessageText, msg)
			cancel()
			if err != nil {
				fmt.Printf("Error writing to WebSocket: %v\n", err)
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// addSubscriber adds a new subscriber
func (s *Server) addSubscriber(sub *Subscriber) {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()
	s.subscribers[sub] = struct{}{}
	fmt.Printf("New subscriber connected. Total: %d\n", len(s.subscribers))
}

// removeSubscriber removes a subscriber
func (s *Server) removeSubscriber(sub *Subscriber) {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()
	delete(s.subscribers, sub)
	close(sub.msgs)
	fmt.Printf("Subscriber disconnected. Total: %d\n", len(s.subscribers))
}

// broadcast sends a message to all subscribers
func (s *Server) broadcast(msg []byte) {
	s.subscribersMu.RLock()
	defer s.subscribersMu.RUnlock()

	for sub := range s.subscribers {
		select {
		case sub.msgs <- msg:
		default:
			fmt.Println("Subscriber channel full, skipping")
		}
	}
}

// closeAllConnections gracefully closes all WebSocket connections
func (s *Server) closeAllConnections() {
	s.subscribersMu.Lock()
	defer s.subscribersMu.Unlock()

	for sub := range s.subscribers {
		sub.conn.Close(websocket.StatusNormalClosure, "Server shutting down")
		close(sub.msgs)
		delete(s.subscribers, sub)
	}
}

func main() {
	server := NewServer()
	if err := server.Start(); err != nil {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}
