// Package telemetry is the OpenTelemetry metrics and traces r2broker
// publishes.
//
// It follows the fleet's shape (truvity/audit's internal/telemetry,
// truvity/policy 0006): push over OTLP/HTTP, only when a collector is named,
// configured by OpenTelemetry's own environment and nothing else. Without
// OTEL_EXPORTER_OTLP_ENDPOINT (or the per-signal variables) nothing is
// installed, every instrument records into the SDK's no-op, and no listener
// is opened.
//
// Spans carry no personal data and no credential. The only instrumentation is
// otelhttp on the server, which records the method, the route, the status and
// the peer's address; the handler adds no attribute, and no request or
// response body or header reaches a span.
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// ServiceName is the service.name r2broker reports unless OTEL_SERVICE_NAME
// says otherwise.
const ServiceName = "r2-broker"

// MetricsEnabled reports whether a collector is named for metrics.
func MetricsEnabled() bool {
	return named("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT")
}

// TracesEnabled reports whether a collector is named for traces.
func TracesEnabled() bool {
	return named("OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
}

func named(vars ...string) bool {
	for _, name := range vars {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return true
		}
	}

	return false
}

// Start installs the global meter provider when a collector is named for
// metrics, and the global tracer provider and the W3C trace-context
// propagator when one is named for traces. It returns what flushes and stops
// them; without a collector it installs nothing and the function does
// nothing.
func Start(ctx context.Context, version string, logger *slog.Logger) (func(context.Context) error, error) {
	if !MetricsEnabled() && !TracesEnabled() {
		return func(context.Context) error { return nil }, nil
	}

	attrs := []attribute.KeyValue{attribute.String("service.version", version)}
	if strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME")) == "" {
		attrs = append(attrs, attribute.String("service.name", ServiceName))
	}

	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
	if err != nil {
		return nil, fmt.Errorf("telemetry: the resource: %w", err)
	}

	var stops []func(context.Context) error

	if MetricsEnabled() {
		exporter, err := otlpmetrichttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: an OTLP metric exporter: %w", err)
		}

		provider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter)),
		)
		otel.SetMeterProvider(provider)

		stops = append(stops, provider.Shutdown)

		logger.InfoContext(ctx, "publishing metrics over OTLP")
	}

	if TracesEnabled() {
		exporter, err := otlptracehttp.New(ctx)
		if err != nil {
			return nil, fmt.Errorf("telemetry: an OTLP trace exporter: %w", err)
		}

		// The sampler: OTEL_TRACES_SAMPLER and OTEL_TRACES_SAMPLER_ARG are read
		// by the SDK; unset it is the SDK's default, a parent-based always_on.
		provider := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithBatcher(exporter))
		otel.SetTracerProvider(provider)
		otel.SetTextMapPropagator(propagation.TraceContext{})

		stops = append(stops, provider.Shutdown)

		logger.InfoContext(ctx, "publishing traces over OTLP")
	}

	return func(ctx context.Context) error {
		var errs []error
		for _, stop := range stops {
			errs = append(errs, stop(ctx))
		}

		return errors.Join(errs...)
	}, nil
}

// Broker is what the broker counts. Every dimension is a metric attribute
// with a handful of values; none is the caller, a group, a bucket or a prefix,
// which grow with the estate and would be a series per customer.
type Broker struct {
	minted    metric.Int64Counter
	refused   metric.Int64Counter
	fallbacks metric.Int64Counter
	duration  metric.Float64Histogram
}

// Outcome values of the `outcome` attribute, in step with broker.Outcome.
const (
	OutcomeMinted          = "minted"
	OutcomeUnauthenticated = "unauthenticated"
	OutcomeRefused         = "refused"
	OutcomeMintFailed      = "mint_failed"
)

// NewBroker makes the broker's instruments on provider, normally the global
// one Start installed, and registers the steady gauge `r2broker.grants`
// (grants configured), which is exported every interval whether or not
// anybody asks for a credential: the series a TelemetryAbsent rule watches,
// since a counter has no series until its first increment.
func NewBroker(provider metric.MeterProvider, grants int) (*Broker, error) {
	m := provider.Meter("github.com/truvity/cloudflare/r2broker")

	var (
		b   Broker
		err error
	)

	if b.minted, err = m.Int64Counter("r2broker.credentials.minted",
		metric.WithUnit("{credential}"),
		metric.WithDescription("Credentials minted, by the path that produced them (local or api).")); err != nil {
		return nil, fmt.Errorf("telemetry: r2broker.credentials.minted: %w", err)
	}

	if b.refused, err = m.Int64Counter("r2broker.credentials.failed",
		metric.WithUnit("{request}"),
		metric.WithDescription("Credential requests that ended without a credential, by outcome: "+
			"unauthenticated, refused or mint_failed.")); err != nil {
		return nil, fmt.Errorf("telemetry: r2broker.credentials.failed: %w", err)
	}

	if b.fallbacks, err = m.Int64Counter("r2broker.mint.api_fallbacks",
		metric.WithUnit("{mint}"),
		metric.WithDescription("Mints that fell back from local signing to the Cloudflare API: "+
			"the signal that Cloudflare changed something under the local-signing contract.")); err != nil {
		return nil, fmt.Errorf("telemetry: r2broker.mint.api_fallbacks: %w", err)
	}

	if b.duration, err = m.Float64Histogram("r2broker.credentials.duration",
		metric.WithUnit("s"),
		metric.WithDescription("Time to answer one credential request, by outcome."),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15)); err != nil {
		return nil, fmt.Errorf("telemetry: r2broker.credentials.duration: %w", err)
	}

	if _, err = m.Int64ObservableGauge("r2broker.grants",
		metric.WithUnit("{grant}"),
		metric.WithDescription("Grant rows in the loaded configuration. Exported every interval, so its absence means the broker is not publishing."),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(int64(grants))

			return nil
		})); err != nil {
		return nil, fmt.Errorf("telemetry: r2broker.grants: %w", err)
	}

	return &b, nil
}

// Request records one answered credential request: its outcome, the path that
// minted it when it was minted, and how long it took.
func (b *Broker) Request(ctx context.Context, outcome, path string, seconds float64) {
	if b == nil {
		return
	}

	b.duration.Record(ctx, seconds, metric.WithAttributes(attribute.String("outcome", outcome)))

	if outcome == OutcomeMinted {
		b.minted.Add(ctx, 1, metric.WithAttributes(attribute.String("path", path)))

		return
	}

	b.refused.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", outcome)))
}

// APIFallback records one mint that fell back from local signing to the API.
func (b *Broker) APIFallback(ctx context.Context) {
	if b == nil {
		return
	}

	b.fallbacks.Add(ctx, 1)
}
