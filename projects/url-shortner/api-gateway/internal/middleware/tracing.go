package middleware

import (
	"context"

	"github.com/gofiber/contrib/otelfiber"
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// SetupTracing initializes OpenTelemetry tracing with OTLP HTTP exporter
func SetupTracing(serviceName, endpoint string) (*sdktrace.TracerProvider, error) {
	if endpoint == "" {
		return nil, nil
	}

	// Create OTLP HTTP exporter
	ctx := context.Background()
	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // Use WithTLSCredentials for production
	)
	if err != nil {
		return nil, err
	}

	// Create resource with service name
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.DeploymentEnvironment("production"),
		),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
	)
	if err != nil {
		return nil, err
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set global tracer provider and propagator
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp, nil
}

// TracingMiddleware returns Fiber middleware for OpenTelemetry tracing
func TracingMiddleware() fiber.Handler {
	return otelfiber.Middleware(
		otelfiber.WithServerName("api-gateway"),
		otelfiber.WithTracerProvider(otel.GetTracerProvider()),
	)
}

// SetupConsoleTracing sets up tracing with console exporter (for development)
func SetupConsoleTracing(serviceName string) (*sdktrace.TracerProvider, error) {
	// For development/testing, you might want console exporter
	// Note: You'll need to import the stdout exporter
	// "go.opentelemetry.io/otel/exporters/stdout/stdouttrace"

	// This is a placeholder - in production, use OTLP exporter above
	// For now, we'll return nil which will use the no-op tracer
	return nil, nil
}

// ShutdownTracing gracefully shuts down the tracer provider
func ShutdownTracing(ctx context.Context, tp *sdktrace.TracerProvider) error {
	if tp != nil {
		return tp.Shutdown(ctx)
	}
	return nil
}
