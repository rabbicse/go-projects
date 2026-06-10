package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total HTTP requests, labelled by method, route template, and status code.",
	}, []string{"method", "path", "status"})

	httpRequestDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency in seconds, labelled by method and route template.",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	}, []string{"method", "path"})

	httpRequestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "http_requests_in_flight",
		Help: "Current number of HTTP requests being processed.",
	})
)

// Metrics records per-route Prometheus counters, histograms, and an in-flight gauge.
// Must be registered after gin.Recovery() so panics are caught before we record metrics.
func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		httpRequestsInFlight.Inc()

		c.Next()

		httpRequestsInFlight.Dec()

		// c.FullPath() returns the Gin route template (e.g. /api/v1/movies/:id),
		// preventing high-cardinality label explosions from raw URL params.
		path := c.FullPath()
		if path == "" {
			path = "unmatched"
		}

		httpRequestsTotal.WithLabelValues(
			c.Request.Method,
			path,
			strconv.Itoa(c.Writer.Status()),
		).Inc()

		httpRequestDurationSeconds.WithLabelValues(
			c.Request.Method,
			path,
		).Observe(time.Since(start).Seconds())
	}
}
