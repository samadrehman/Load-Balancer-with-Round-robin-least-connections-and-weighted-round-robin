import { Registry, Counter, Histogram, Gauge } from 'prom-client';
import { Request, Response } from 'express';

// Create a Registry to register the metrics
export const register = new Registry();

// Add default metrics (CPU, memory, etc.)
register.setDefaultLabels({
  app: 'load-balancer'
});

// Request metrics
export const httpRequestDuration = new Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
});

export const httpRequestTotal = new Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status_code']
});

export const httpRequestErrors = new Counter({
  name: 'http_request_errors_total',
  help: 'Total number of HTTP request errors',
  labelNames: ['method', 'route', 'error_type']
});

// Server metrics
export const serverRequestsTotal = new Counter({
  name: 'server_requests_total',
  help: 'Total number of requests to backend servers',
  labelNames: ['server_id', 'status']
});

export const serverResponseTime = new Histogram({
  name: 'server_response_time_seconds',
  help: 'Response time from backend servers in seconds',
  labelNames: ['server_id'],
  buckets: [0.1, 0.3, 0.5, 0.7, 1, 3, 5, 7, 10]
});

export const serverHealthStatus = new Gauge({
  name: 'server_health_status',
  help: 'Health status of backend servers (1 = healthy, 0 = unhealthy)',
  labelNames: ['server_id']
});

export const activeConnections = new Gauge({
  name: 'active_connections',
  help: 'Number of active connections',
  labelNames: ['server_id']
});

// Rate limiting metrics
export const rateLimitHits = new Counter({
  name: 'rate_limit_hits_total',
  help: 'Total number of rate limit hits',
  labelNames: ['type', 'identifier']
});

// Circuit breaker metrics
export const circuitBreakerState = new Gauge({
  name: 'circuit_breaker_state',
  help: 'Circuit breaker state (0 = closed, 1 = open, 2 = half-open)',
  labelNames: ['server_id']
});

// Register all metrics
register.registerMetric(httpRequestDuration);
register.registerMetric(httpRequestTotal);
register.registerMetric(httpRequestErrors);
register.registerMetric(serverRequestsTotal);
register.registerMetric(serverResponseTime);
register.registerMetric(serverHealthStatus);
register.registerMetric(activeConnections);
register.registerMetric(rateLimitHits);
register.registerMetric(circuitBreakerState);

/**
 * Prometheus metrics middleware
 */
export function prometheusMiddleware(req: Request, res: Response, next: () => void): void {
  const start = Date.now();
  const route = req.route?.path || req.path;

  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    const statusCode = res.statusCode.toString();

    httpRequestDuration.observe(
      { method: req.method, route, status_code: statusCode },
      duration
    );

    httpRequestTotal.inc({
      method: req.method,
      route,
      status_code: statusCode
    });

    if (res.statusCode >= 400) {
      httpRequestErrors.inc({
        method: req.method,
        route,
        error_type: res.statusCode >= 500 ? 'server_error' : 'client_error'
      });
    }
  });

  next();
}

