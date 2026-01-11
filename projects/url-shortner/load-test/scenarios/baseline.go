package scenarios

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortener/load-test/config"
	"github.com/rabbicse/go-projects/projects/url-shortener/load-test/metrics"
)

func RunBaselineTest(ctx context.Context, cfg *config.Config, numUsers int, results chan<- metrics.RequestResult) {
	var wg sync.WaitGroup
	client := &http.Client{
		Timeout: cfg.DefaultTimeout,
	}

	for i := 0; i < numUsers; i++ {
		wg.Add(1)
		go func(userID int) {
			defer wg.Done()
			userWorker(ctx, client, cfg, userID, results)
		}(i)
	}

	wg.Wait()
}

func userWorker(ctx context.Context, client *http.Client, cfg *config.Config, userID int, results chan<- metrics.RequestResult) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C: // Fixed: Use ticker.C instead of ticker.Timeout
			// 70% chance to shorten URL, 30% to redirect
			if rand.Float32() < 0.7 {
				shortenURL(ctx, client, cfg, userID, results)
			} else {
				redirectURL(ctx, client, cfg, userID, results)
			}
		}
	}
}

func shortenURL(ctx context.Context, client *http.Client, cfg *config.Config, userID int, results chan<- metrics.RequestResult) {
	start := time.Now()

	payload := map[string]string{
		"url": fmt.Sprintf("https://example.com/user/%d/timestamp/%d", userID, time.Now().UnixNano()),
	}

	jsonData, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, "POST", cfg.APIBaseURL+"/api/v1/shorten", bytes.NewReader(jsonData))
	if err != nil {
		results <- metrics.RequestResult{Error: err, Success: false, Timestamp: time.Now()}
		return
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	duration := time.Since(start)

	result := metrics.RequestResult{
		URL:       req.URL.String(),
		Method:    req.Method,
		Duration:  duration,
		Timestamp: time.Now(),
		Success:   err == nil && resp.StatusCode == 200,
		Error:     err,
	}

	if resp != nil {
		result.StatusCode = resp.StatusCode
		resp.Body.Close()
	}

	results <- result
}

func redirectURL(ctx context.Context, client *http.Client, cfg *config.Config, userID int, results chan<- metrics.RequestResult) {
	// This would require some stored short URLs
	// For now, we'll skip or implement URL storage
}
