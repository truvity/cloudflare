package telemetry_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/truvity/cloudflare/v2/internal/telemetry"
)

func collect(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))

	out := map[string]metricdata.Metrics{}

	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m
		}
	}

	return out
}

func TestBrokerMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	b, err := telemetry.NewBroker(sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)), 3)
	require.NoError(t, err)

	// Before any request: only the steady gauge has a series, which is what
	// a TelemetryAbsent rule can rely on.
	got := collect(t, reader)
	require.Contains(t, got, "r2broker.grants")
	require.NotContains(t, got, "r2broker.credentials.minted")

	gauge, ok := got["r2broker.grants"].Data.(metricdata.Gauge[int64])
	require.True(t, ok)
	require.Equal(t, int64(3), gauge.DataPoints[0].Value)

	ctx := context.Background()
	b.Request(ctx, telemetry.OutcomeMinted, "local", 0.01)
	b.Request(ctx, telemetry.OutcomeMinted, "local", 0.02)
	b.Request(ctx, telemetry.OutcomeMinted, "api", 0.2)
	b.Request(ctx, telemetry.OutcomeRefused, "", 0.001)
	b.Request(ctx, telemetry.OutcomeUnauthenticated, "", 0.001)
	b.APIFallback(ctx)

	got = collect(t, reader)

	minted := got["r2broker.credentials.minted"].Data.(metricdata.Sum[int64])
	byPath := map[string]int64{}

	for _, dp := range minted.DataPoints {
		v, _ := dp.Attributes.Value("path")
		byPath[v.AsString()] = dp.Value
	}

	require.Equal(t, map[string]int64{"local": 2, "api": 1}, byPath)

	failed := got["r2broker.credentials.failed"].Data.(metricdata.Sum[int64])
	byOutcome := map[string]int64{}

	for _, dp := range failed.DataPoints {
		v, _ := dp.Attributes.Value("outcome")
		byOutcome[v.AsString()] = dp.Value
	}

	require.Equal(t, map[string]int64{"refused": 1, "unauthenticated": 1}, byOutcome)

	hist := got["r2broker.credentials.duration"].Data.(metricdata.Histogram[float64])

	var total uint64
	for _, dp := range hist.DataPoints {
		total += dp.Count
	}

	require.Equal(t, uint64(5), total)
	require.Contains(t, got, "r2broker.mint.api_fallbacks")
}

func TestNilBrokerIsANoOp(*testing.T) {
	var b *telemetry.Broker

	b.Request(context.Background(), telemetry.OutcomeMinted, "local", 1)
	b.APIFallback(context.Background())
}

func TestStartWithoutACollectorInstallsNothing(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	require.False(t, telemetry.MetricsEnabled())
	require.False(t, telemetry.TracesEnabled())

	stop, err := telemetry.Start(context.Background(), "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)
	require.NoError(t, stop(context.Background()))
}

func TestStartWithACollectorShutsDown(t *testing.T) {
	// Nothing listens here; Start must not dial at construction, and Shutdown
	// of an empty queue must return.
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "3600000")

	require.True(t, telemetry.MetricsEnabled())
	require.True(t, telemetry.TracesEnabled())

	stop, err := telemetry.Start(context.Background(), "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	// Shutdown flushes the final metric collection to the dead endpoint; it
	// reports that error rather than hanging, which is all this asserts.
	_ = stop(context.Background())
}
