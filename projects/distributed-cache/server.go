package main

import (
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Item stores a value and its expiry.
type Item struct {
	Value     []byte
	Expiry    time.Time
	HasExpiry bool
	CreatedAt time.Time
}

// Cache is a concurrency-safe in-memory store.
type Cache struct {
	mu    sync.RWMutex
	items map[string]Item
}

func NewCache() *Cache {
	c := &Cache{
		items: make(map[string]Item),
	}
	// background janitor
	go func() {
		t := time.NewTicker(1 * time.Second)
		for range t.C {
			now := time.Now()
			c.mu.Lock()
			for k, it := range c.items {
				if it.HasExpiry && now.After(it.Expiry) {
					delete(c.items, k)
				}
			}
			c.mu.Unlock()
		}
	}()
	return c
}

func (c *Cache) Set(key string, value []byte, ttlSecs int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it := Item{Value: value, CreatedAt: time.Now()}
	if ttlSecs > 0 {
		it.HasExpiry = true
		it.Expiry = time.Now().Add(time.Duration(ttlSecs) * time.Second)
	}
	c.items[key] = it
}

func (c *Cache) Get(key string) (value []byte, ok bool, ttlLeft int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	it, ok := c.items[key]
	if !ok {
		return nil, false, 0
	}
	if it.HasExpiry {
		now := time.Now()
		if now.After(it.Expiry) {
			return nil, false, 0
		}
		return it.Value, true, int(it.Expiry.Sub(now).Seconds())
	}
	return it.Value, true, 0
}

func (c *Cache) Delete(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.items[key]; ok {
		delete(c.items, key)
		return true
	}
	return false
}

func (c *Cache) Stats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	n := len(c.items)
	return map[string]interface{}{
		"items": n,
	}
}

// --- Consistent Hashing Ring (simple) ---
type HashRing struct {
	sortedHashes []uint32
	hashMap      map[uint32]string // hash -> node
	replicas     int
	mu           sync.RWMutex
}

func NewHashRing(replicas int) *HashRing {
	return &HashRing{
		hashMap:  make(map[uint32]string),
		replicas: replicas,
	}
}

func (hr *HashRing) AddNode(node string) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	for i := 0; i < hr.replicas; i++ {
		h := hr.hashKey(fmt.Sprintf("%s#%d", node, i))
		hr.hashMap[h] = node
		hr.sortedHashes = append(hr.sortedHashes, h)
	}
	sort.Slice(hr.sortedHashes, func(i, j int) bool { return hr.sortedHashes[i] < hr.sortedHashes[j] })
}

func (hr *HashRing) RemoveNode(node string) {
	hr.mu.Lock()
	defer hr.mu.Unlock()
	newHashes := make([]uint32, 0, len(hr.sortedHashes))
	for _, h := range hr.sortedHashes {
		if hr.hashMap[h] == node {
			delete(hr.hashMap, h)
			continue
		}
		newHashes = append(newHashes, h)
	}
	hr.sortedHashes = newHashes
}

func (hr *HashRing) GetNode(key string) string {
	hr.mu.RLock()
	defer hr.mu.RUnlock()
	if len(hr.sortedHashes) == 0 {
		return ""
	}
	h := hr.hashKey(key)
	// binary search for first hash >= h
	idx := sort.Search(len(hr.sortedHashes), func(i int) bool {
		return hr.sortedHashes[i] >= h
	})
	if idx == len(hr.sortedHashes) {
		idx = 0
	}
	return hr.hashMap[hr.sortedHashes[idx]]
}

func (hr *HashRing) GetNNodes(key string, n int) []string {
	hr.mu.RLock()
	defer hr.mu.RUnlock()
	out := []string{}
	if len(hr.sortedHashes) == 0 || n <= 0 {
		return out
	}
	h := hr.hashKey(key)
	idx := sort.Search(len(hr.sortedHashes), func(i int) bool {
		return hr.sortedHashes[i] >= h
	})
	used := make(map[string]bool)
	for i := 0; len(out) < n && i < len(hr.sortedHashes); i++ {
		j := (idx + i) % len(hr.sortedHashes)
		node := hr.hashMap[hr.sortedHashes[j]]
		if !used[node] {
			out = append(out, node)
			used[node] = true
		}
	}
	return out
}

func (hr *HashRing) hashKey(key string) uint32 {
	h := sha1.Sum([]byte(key))
	// use first 4 bytes as uint32
	return (uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]))
}

// --- HTTP server and peer forwarding ---
type Server struct {
	self      string
	peers     []string
	repFactor int
	cache     *Cache
	ring      *HashRing
	client    *http.Client
}

func NewServer(self string, peers []string, rep int) *Server {
	r := NewHashRing(100) // virtual nodes
	for _, p := range peers {
		r.AddNode(p)
	}
	return &Server{
		self:      self,
		peers:     peers,
		repFactor: rep,
		cache:     NewCache(),
		ring:      r,
		client:    &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *Server) isOwner(key string) bool {
	nodes := s.ring.GetNNodes(key, s.repFactor)
	for _, n := range nodes {
		if n == s.self {
			return true
		}
	}
	return false
}

func (s *Server) ownerNodes(key string) []string {
	return s.ring.GetNNodes(key, s.repFactor)
}

func (s *Server) forwardTo(node, method, path string, body io.Reader) (*http.Response, error) {
	u := node + path
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	// copy headers if needed
	req.Header.Set("X-Forwarded-By", s.self)
	return s.client.Do(req)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	if !s.isOwner(key) {
		// forward to first owner
		owners := s.ownerNodes(key)
		if len(owners) == 0 {
			http.Error(w, "no peers", http.StatusServiceUnavailable)
			return
		}
		if owners[0] == s.self {
			// fallthrough
		} else {
			resp, err := s.forwardTo(owners[0], "GET", "/internal/get?key="+url.QueryEscape(key), nil)
			if err != nil {
				http.Error(w, "forward error: "+err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			w.WriteHeader(resp.StatusCode)
			io.Copy(w, resp.Body)
			return
		}
	}

	// local get
	v, ok, ttl := s.cache.Get(key)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("X-TTL", strconv.Itoa(ttl))
	w.Write(v)
}

func (s *Server) handleSet(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	ttlS := r.URL.Query().Get("ttl")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	ttl := 0
	if ttlS != "" {
		if t, err := strconv.Atoi(ttlS); err == nil {
			ttl = t
		}
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	owners := s.ownerNodes(key)
	if len(owners) == 0 {
		http.Error(w, "no peers", http.StatusServiceUnavailable)
		return
	}

	// If I'm an owner, set locally and optionally replicate to others.
	isOwner := false
	for _, o := range owners {
		if o == s.self {
			isOwner = true
			break
		}
	}
	if isOwner {
		s.cache.Set(key, body, ttl)
		// replicate to other owners in background (best-effort)
		for _, o := range owners {
			if o == s.self {
				continue
			}
			go func(peer string) {
				peerURL := peer + "/internal/set?key=" + url.QueryEscape(key) + "&ttl=" + strconv.Itoa(ttl)
				req, _ := http.NewRequest("POST", peerURL, strings.NewReader(string(body)))
				req.Header.Set("X-Forwarded-By", s.self)
				_, _ = s.client.Do(req)
			}(o)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
		return
	}

	// otherwise forward to first owner
	resp, err := s.forwardTo(owners[0], "POST", "/internal/set?key="+url.QueryEscape(key)+"&ttl="+strconv.Itoa(ttl), strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "forward error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleDel(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	owners := s.ownerNodes(key)
	if len(owners) == 0 {
		http.Error(w, "no peers", http.StatusServiceUnavailable)
		return
	}
	isOwner := false
	for _, o := range owners {
		if o == s.self {
			isOwner = true
			break
		}
	}
	if isOwner {
		s.cache.Delete(key)
		for _, o := range owners {
			if o == s.self {
				continue
			}
			go func(peer string) {
				peerURL := peer + "/internal/del?key=" + url.QueryEscape(key)
				req, _ := http.NewRequest("POST", peerURL, nil)
				req.Header.Set("X-Forwarded-By", s.self)
				_, _ = s.client.Do(req)
			}(o)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "deleted")
		return
	}
	resp, err := s.forwardTo(owners[0], "POST", "/internal/del?key="+url.QueryEscape(key), nil)
	if err != nil {
		http.Error(w, "forward error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) handleInternalGet(w http.ResponseWriter, r *http.Request) {
	// internal endpoints bypass routing assumptions and only operate locally (used for forwarding)
	key := r.URL.Query().Get("key")
	v, ok, ttl := s.cache.Get(key)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("X-TTL", strconv.Itoa(ttl))
	w.Write(v)
}

func (s *Server) handleInternalSet(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	ttlS := r.URL.Query().Get("ttl")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	ttl := 0
	if ttlS != "" {
		if t, err := strconv.Atoi(ttlS); err == nil {
			ttl = t
		}
	}
	body, _ := io.ReadAll(r.Body)
	s.cache.Set(key, body, ttl)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func (s *Server) handleInternalDel(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	s.cache.Delete(key)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	js, _ := json.Marshal(s.cache.Stats())
	w.Header().Set("Content-Type", "application/json")
	w.Write(js)
}

func main() {
	port := flag.Int("port", 8001, "http port")
	peersFlag := flag.String("peers", "http://localhost:8001", "comma-separated peer urls (include self)")
	rep := flag.Int("rep", 2, "replication factor (1..n)")
	flag.Parse()

	// normalize peers
	peers := []string{}
	for _, p := range strings.Split(*peersFlag, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// ensure scheme
		if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
			p = "http://" + p
		}
		// remove trailing slash
		p = strings.TrimRight(p, "/")
		peers = append(peers, p)
	}

	self := fmt.Sprintf("http://localhost:%d", *port)
	// ensure self present
	found := false
	for _, p := range peers {
		if p == self {
			found = true
			break
		}
	}
	if !found {
		peers = append(peers, self)
	}

	s := NewServer(self, peers, *rep)

	mux := http.NewServeMux()
	mux.HandleFunc("/get", s.handleGet)
	mux.HandleFunc("/set", s.handleSet) // POST body used as value
	mux.HandleFunc("/del", s.handleDel) // POST to delete
	mux.HandleFunc("/stats", s.handleStats)

	// internal endpoints used for forwarding between peers
	mux.HandleFunc("/internal/get", s.handleInternalGet)
	mux.HandleFunc("/internal/set", s.handleInternalSet)
	mux.HandleFunc("/internal/del", s.handleInternalDel)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("starting node %s peers=%v rep=%d", self, peers, *rep)
	log.Fatal(http.ListenAndServe(addr, mux))
}
