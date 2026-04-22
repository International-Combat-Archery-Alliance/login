package telemetry

import (
	"context"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/semconv/v1.26.0"
)

const serviceName = "login"

func Init(ctx context.Context) (shutdown func(context.Context) error, err error) {
	endpoint := os.Getenv("OTEL_COLLECTOR_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:4317"
	}

	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}

	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
	}
	attrs = append(attrs, lambdaAttributes()...)

	res, err := resource.New(ctx, resource.WithAttributes(attrs...))
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	batchTimeout := 5 * time.Second
	exportTimeout := 30 * time.Second
	if isLambda() {
		batchTimeout = 1 * time.Second
		exportTimeout = 5 * time.Second
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter,
			sdktrace.WithBatchTimeout(batchTimeout),
			sdktrace.WithExportTimeout(exportTimeout),
		),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return func(ctx context.Context) error {
		return tp.Shutdown(ctx)
	}, nil
}

func isLambda() bool {
	return os.Getenv("AWS_LAMBDA_FUNCTION_NAME") != ""
}

func lambdaAttributes() []attribute.KeyValue {
	var attrs []attribute.KeyValue

	if fn := os.Getenv("AWS_LAMBDA_FUNCTION_NAME"); fn != "" {
		attrs = append(attrs, semconv.FaaSName(fn))
	}
	if region := os.Getenv("AWS_REGION"); region != "" {
		attrs = append(attrs, semconv.CloudRegion(region))
	}
	if version := os.Getenv("AWS_LAMBDA_FUNCTION_VERSION"); version != "" {
		attrs = append(attrs, semconv.FaaSVersion(version))
	}

	return attrs
}
