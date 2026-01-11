package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/rabbicse/go-projects/projects/url-shortener/load-test/config"
	"github.com/rabbicse/go-projects/projects/url-shortener/load-test/metrics"
	"github.com/rabbicse/go-projects/projects/url-shortener/load-test/reporters"
	"github.com/rabbicse/go-projects/projects/url-shortener/load-test/scenarios"
)

func main() {
	// Parse command line flags
	configFile := flag.String("config", "config.yaml", "Configuration file")
	scenario := flag.String("scenario", "baseline", "Test scenario: baseline, spike, endurance")
	output := flag.String("output", "console", "Output format: console, json, prometheus")
	duration := flag.Duration("duration", 5*time.Minute, "Test duration")
	users := flag.Int("users", 100, "Number of concurrent users")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize metrics collector
	metricsCollector := metrics.NewCollector()

	// Initialize reporter
	var reporter reporters.Reporter
	switch *output {
	case "console":
		reporter = reporters.NewConsoleReporter()
	// case "json":
	// 	reporter = reporters.NewJSONReporter()
	// case "prometheus":
	// 	reporter = reporters.NewPrometheusReporter()
	default:
		log.Fatalf("Unknown output format: %s", *output)
	}

	// Create context with cancellation
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		fmt.Println("\n🛑 Received interrupt signal, shutting down...")
		cancel()
	}()

	fmt.Printf("🚀 Starting %s load test with %d users for %v\n", *scenario, *users, *duration)
	fmt.Printf("📊 Target: %s\n", cfg.APIBaseURL)

	// Run the selected scenario
	startTime := time.Now()

	var wg sync.WaitGroup
	results := make(chan metrics.RequestResult, 1000)

	// Start metrics collector
	wg.Add(1)
	go func() {
		defer wg.Done()
		metricsCollector.Start(ctx, results)
	}()

	// Start reporter
	wg.Add(1)
	go func() {
		defer wg.Done()
		reporter.Start(ctx, metricsCollector)
	}()

	// Run load test scenario
	switch *scenario {
	case "baseline":
		scenarios.RunBaselineTest(ctx, cfg, *users, results)
	case "spike":
		scenarios.RunSpikeTest(ctx, cfg, *users, results)
	case "endurance":
		scenarios.RunEnduranceTest(ctx, cfg, *users, results)
	default:
		log.Fatalf("Unknown scenario: %s", *scenario)
	}

	// Wait for completion
	close(results)
	wg.Wait()

	// Generate final report
	duration := time.Since(startTime)
	summary := metricsCollector.GetSummary()
	reporter.ReportSummary(summary, duration)

	fmt.Printf("✅ Load test completed in %v\n", duration)
}
