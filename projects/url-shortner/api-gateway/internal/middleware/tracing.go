package middleware

import (
	"github.com/gofiber/fiber/v2"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.15.0"
)

// import (
// 	"github.com/gofiber/contrib/otelfiber/v2"
// 	"github.com/gofiber/fiber/v2"
// 	"go.opentelemetry.io/otel"
// 	"go.opentelemetry.io/otel/exporters/jaeger"
// 	"go.opentelemetry.io/otel/sdk/resource"
// 	"go.opentelemetry.io/otel/sdk/trace"
// 	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
// )

func SetupTracing(serviceName, endpoint string) (*trace.TracerProvider, error) {
	if endpoint == "" {
		return nil, nil
	}

	// Create Jaeger exporter
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint)))
	if err != nil {
		return nil, err
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp),
		trace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(serviceName),
			semconv.DeploymentEnvironmentKey.String("production"),
		)),
	)

	otel.SetTracerProvider(tp)
	return tp, nil
}

func TracingMiddleware() fiber.Handler {
	return otelfiber.Middleware("api-gateway")
}
