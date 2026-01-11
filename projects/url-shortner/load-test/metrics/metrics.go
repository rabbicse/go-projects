package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type RequestResult struct {
	URL         string
	Method      string
	StatusCode  int
	Duration    time.Duration
	Success     bool
	Error       error
	Timestamp   time.Time
	PayloadSize int
}

type Collector struct {
	mu             sync.RWMutex
	results        []RequestResult
	statusCodes    map[int]int
	totalRequests  int
	failedRequests int
	totalDuration  time.Duration
}

func NewCollector() *Collector {
	return &Collector{
		results:     make([]RequestResult, 0),
		statusCodes: make(map[int]int),
	}
}

func (c *Collector) Start(ctx context.Context, results <-chan RequestResult) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-results:
			if !ok {
				return
			}
			c.AddResult(result)
		}
	}
}

func (c *Collector) AddResult(result RequestResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.results = append(c.results, result)
	c.totalRequests++
	c.totalDuration += result.Duration

	if result.StatusCode > 0 {
		c.statusCodes[result.StatusCode]++
	}

	if !result.Success || result.StatusCode >= 400 {
		c.failedRequests++
	}
}

func (c *Collector) GetSummary() Summary {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.totalRequests == 0 {
		return Summary{}
	}

	avgDuration := c.totalDuration / time.Duration(c.totalRequests)
	successRate := 1.0 - float64(c.failedRequests)/float64(c.totalRequests)

	return Summary{
		TotalRequests:  c.totalRequests,
		FailedRequests: c.failedRequests,
		SuccessRate:    successRate,
		AvgDuration:    avgDuration,
		StatusCodes:    c.statusCodes,
	}
}

type Summary struct {
	TotalRequests  int
	FailedRequests int
	SuccessRate    float64
	AvgDuration    time.Duration
	StatusCodes    map[int]int
}

func (s Summary) String() string {
	return fmt.Sprintf(
		"Requests: %d, Failed: %d, Success: %.2f%%, Avg Duration: %v",
		s.TotalRequests,
		s.FailedRequests,
		s.SuccessRate*100,
		s.AvgDuration,
	)
}
