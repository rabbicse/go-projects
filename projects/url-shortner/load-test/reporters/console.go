package reporters

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortener/load-test/metrics"
)

type ConsoleReporter struct {
	updateInterval time.Duration
	startTime      time.Time
}

func NewConsoleReporter() *ConsoleReporter {
	return &ConsoleReporter{
		updateInterval: 5 * time.Second,
		startTime:      time.Now(),
	}
}

func (r *ConsoleReporter) Start(ctx context.Context, collector *metrics.Collector) {
	ticker := time.NewTicker(r.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			summary := collector.GetSummary()
			testDuration := time.Since(r.startTime)

			var rps float64
			if testDuration.Seconds() > 0 {
				rps = float64(summary.TotalRequests) / testDuration.Seconds()
			}

			fmt.Printf("📊 %s | RPS: %.1f | Total: %d | Success: %.1f%% | Avg: %v\n",
				time.Now().Format("15:04:05"),
				rps,
				summary.TotalRequests,
				summary.SuccessRate*100,
				summary.AvgDuration,
			)
		}
	}
}

func (r *ConsoleReporter) ReportSummary(summary metrics.Summary, testDuration time.Duration) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🚀 LOAD TEST SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Duration:        %v\n", testDuration)
	fmt.Printf("Total Requests:  %d\n", summary.TotalRequests)
	fmt.Printf("Failed Requests: %d\n", summary.FailedRequests)
	fmt.Printf("Success Rate:    %.2f%%\n", summary.SuccessRate*100)
	fmt.Printf("Avg Duration:    %v\n", summary.AvgDuration)

	var rps float64
	if testDuration.Seconds() > 0 {
		rps = float64(summary.TotalRequests) / testDuration.Seconds()
	}
	fmt.Printf("Requests/sec:    %.1f\n", rps)

	fmt.Println("\nStatus Codes:")
	for code, count := range summary.StatusCodes {
		percentage := float64(count) / float64(summary.TotalRequests) * 100
		fmt.Printf("  %d: %d (%.1f%%)\n", code, count, percentage)
	}
	fmt.Println(strings.Repeat("=", 60))
}
