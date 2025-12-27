export interface Server {
  id: string;
  url: string;
  weight?: number;
  enabled: boolean;
}

export interface HealthCheckResult {
  serverId: string;
  isHealthy: boolean;
  responseTime?: number;
  lastChecked: Date;
  consecutiveFailures: number;
}

export interface ServerMetrics {
  serverId: string;
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  averageResponseTime: number;
  currentConnections: number;
  lastResponseTime?: number;
  uptime: number;
}

export interface RateLimitConfig {
  enabled: boolean;
  windowMs: number;
  maxRequests: number;
  perIP: boolean;
  perUser: boolean;
  userHeader?: string; // Header to identify users (e.g., 'X-User-ID')
}

export interface LoadBalancerConfig {
  port: number;
  algorithm: 'round-robin' | 'least-connections' | 'weighted-round-robin' | 'sticky-session';
  healthCheck: {
    enabled: boolean;
    interval: number; // milliseconds
    timeout: number; // milliseconds
    path: string;
    failureThreshold: number; // consecutive failures before marking unhealthy
    successThreshold: number; // consecutive successes before marking healthy
  };
  rateLimit: RateLimitConfig;
  servers: Server[];
  monitoring: {
    enabled: boolean;
    metricsEndpoint: string;
  };
  security?: {
    adminApiKey?: string;
    requireAuth?: boolean;
    https?: {
      enabled: boolean;
      keyPath?: string;
      certPath?: string;
    };
  };
}

export interface RateLimitInfo {
  count: number;
  resetTime: Date;
  limit: number;
}

