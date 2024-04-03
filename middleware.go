package gocloak

import (
	"context"

	"github.com/go-resty/resty/v2"
	"github.com/opentracing/opentracing-go"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// Middleware function that is called before all requests to keycloak.
type Middleware func(ctx context.Context, req *resty.Request) context.Context

// RegisterMiddlewares registers middlewares for the GoCloak client.
// Middlewares are called in-order.
func (g *GoCloak) RegisterMiddlewares(middlewares ...Middleware) {
	g.middlewares = append(g.middlewares, middlewares...)
}

// OpenTracingMiddleware passes OpenTracing tracing data to the request
func OpenTracingMiddleware(ctx context.Context, req *resty.Request) context.Context {
	// look for span in context, do nothing if span is not found
	span := opentracing.SpanFromContext(ctx)
	if span == nil {
		return ctx
	}

	// look for tracer in context, use global tracer if not found
	tracer, ok := ctx.Value(tracerContextKey).(opentracing.Tracer)
	if !ok || tracer == nil {
		tracer = opentracing.GlobalTracer()
	}

	// inject tracing header into request
	tracer.Inject(span.Context(), opentracing.HTTPHeaders, opentracing.HTTPHeadersCarrier(req.Header))
	return ctx
}

// OpenTelemetryMiddleware passes OpenTelemetry tracing data to the request
func OpenTelemetryMiddleware(ctx context.Context, req *resty.Request) context.Context {
	prop := otel.GetTextMapPropagator()
	prop.Inject(ctx, propagation.HeaderCarrier(req.Header))
	return ctx
}
