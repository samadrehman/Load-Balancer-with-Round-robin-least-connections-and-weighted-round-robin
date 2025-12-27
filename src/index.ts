import express, { Request, Response, NextFunction } from 'express';
import http from 'http';
import https from 'https';
import helmet from 'helmet';
import cors from 'cors';
import bcrypt from 'bcrypt';
import { loadConfig, saveConfig } from './utils/config-loader';
import { logger } from './utils/logger';
import { RateLimiter } from './middleware/rate-limiter';
import { HealthChecker } from './health/health-checker';
import { MetricsCollector } from './metrics/metrics-collector';
import { LoadBalancer } from './load-balancer/load-balancer';
import { Server, LoadBalancerConfig } from './types';
import { requestIdMiddleware } from './middleware/request-id';
import { createAuthMiddleware } from './middleware/auth';
import { createJWTAuthMiddleware, generateToken } from './middleware/jwt-auth';
import { validateServerInput, validateRateLimitConfig, validateAlgorithm } from './middleware/input-validation';
import { prometheusMiddleware, register } from './utils/prometheus';
import { serverSchema, rateLimitConfigSchema, algorithmSchema, loginSchema } from './utils/validation-schemas';
import { ZodError } from 'zod';
import { createHttpsServer } from './utils/https-server';
import { WebSocketProxy } from './utils/websocket-proxy';
import { validateJWTSecret, sanitizeError, validateServerUrl } from './utils/security';
import { EndpointRateLimiter } from './middleware/endpoint-rate-limit';

const app = express();

// Load configuration first
const config: LoadBalancerConfig = loadConfig();
logger.info('Configuration loaded', { config });

// Security: Require API key from environment variable (no hardcoded defaults)
const adminApiKey = process.env.ADMIN_API_KEY;
if (!adminApiKey || adminApiKey.length < 16) {
  const error = 'ADMIN_API_KEY environment variable is required and must be at least 16 characters long';
  logger.error(error);
  throw new Error(error);
}

// Security: Require separate JWT secret with minimum strength
const jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret) {
  const error = 'JWT_SECRET environment variable is required';
  logger.error(error);
  throw new Error(error);
}

const jwtValidation = validateJWTSecret(jwtSecret);
if (!jwtValidation.valid) {
  const error = `JWT_SECRET validation failed: ${jwtValidation.error}`;
  logger.error(error);
  throw new Error(error);
}

const requireAuth = config.security?.requireAuth !== false; // Default to true
const isProduction = process.env.NODE_ENV === 'production';

// Simple in-memory user store (replace with database in production)
// In production, use a proper user database with hashed passwords
interface User {
  username: string;
  passwordHash: string; // bcrypt hash
  role: string;
}

// Default admin user (should be changed in production)
// Password: 'admin' (change this!)
const defaultUsers: User[] = [
  {
    username: 'admin',
    passwordHash: '$2b$10$rOzJqZqZqZqZqZqZqZqZqOqZqZqZqZqZqZqZqZqZqZqZqZqZqZqZqZq', // 'admin'
    role: 'admin'
  }
];

// Load users from environment or use defaults (for development only)
const users: Map<string, User> = new Map();
if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD_HASH) {
  users.set(process.env.ADMIN_USERNAME, {
    username: process.env.ADMIN_USERNAME,
    passwordHash: process.env.ADMIN_PASSWORD_HASH,
    role: 'admin'
  });
} else if (!isProduction) {
  // Only use default users in development
  defaultUsers.forEach(user => users.set(user.username, user));
  logger.warn('Using default admin credentials. Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH in production!');
}

// Initialize components
const rateLimiter: RateLimiter = new RateLimiter(config.rateLimit);
const healthChecker: HealthChecker = new HealthChecker(config.healthCheck);
const metricsCollector: MetricsCollector = new MetricsCollector();
const loadBalancer: LoadBalancer = new LoadBalancer(
  config.servers,
  config.algorithm,
  healthChecker,
  metricsCollector,
  {
    enableStickySessions: config.algorithm === 'sticky-session',
    sessionTimeout: 3600000
  }
);

// Start health checks
if (config.healthCheck.enabled) {
  healthChecker.startHealthChecks(config.servers);
  logger.info('Health checks started');
}

// Start cleanup interval for metrics collector (every 5 minutes)
const metricsCleanupInterval = setInterval(() => {
  metricsCollector.cleanupStaleRequests();
}, 300000); // 5 minutes

logger.info('Load balancer initialized', {
  servers: config.servers.length,
  algorithm: config.algorithm,
  authRequired: requireAuth
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'"], // Removed 'unsafe-inline' for better security
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  },
  crossOriginEmbedderPolicy: false,
  hsts: isProduction ? {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  } : false
}));

// CORS configuration - never use * in production
const corsOrigins = process.env.CORS_ORIGIN 
  ? process.env.CORS_ORIGIN.split(',').map(o => o.trim())
  : (isProduction ? [] : ['*']); // Only allow * in development

if (isProduction && corsOrigins.length === 0) {
  logger.warn('CORS_ORIGIN not set in production - CORS will be disabled');
}

const corsOptions = {
  origin: corsOrigins.length > 0 ? corsOrigins : false,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Request-ID', 'X-Session-ID']
};
app.use(cors(corsOptions));

// Middleware
app.use(express.json({ limit: '10mb' })); // Add body size limit
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Trust proxy for accurate IP addresses
app.set('trust proxy', true);

// Request ID middleware (must be early in the chain)
app.use(requestIdMiddleware);

// Prometheus metrics middleware
app.use(prometheusMiddleware);

// Rate limiting middleware
app.use(rateLimiter.middleware());

// Authentication middleware for admin endpoints
const authMiddleware = createAuthMiddleware(adminApiKey);
const jwtAuthMiddleware = createJWTAuthMiddleware(jwtSecret);

// Endpoint-specific rate limiter for login (aggressive rate limiting)
const endpointRateLimiter = new EndpointRateLimiter();
const loginRateLimiter = endpointRateLimiter.middleware('/admin/login', {
  enabled: true,
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5, // Only 5 attempts per 15 minutes
  perIP: true,
  perUser: false
});

// JWT Login endpoint with proper credential validation and rate limiting
app.post('/admin/login', loginRateLimiter, async (req: Request, res: Response) => {
  try {
    const validated = loginSchema.parse(req.body);
    
    // Find user
    const user = users.get(validated.username);
    if (!user) {
      // Log failed login attempt
      logger.warn('Failed login attempt - user not found', {
        username: validated.username,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        requestId: (req as any).requestId,
        timestamp: new Date().toISOString()
      });
      
      // Use generic error message to prevent user enumeration
      await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200)); // Add random delay
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid username or password'
      });
    }

    // Verify password using bcrypt
    const passwordValid = await bcrypt.compare(validated.password, user.passwordHash);
    if (!passwordValid) {
      // Log failed login attempt
      logger.warn('Failed login attempt - invalid password', {
        username: validated.username,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
        requestId: (req as any).requestId,
        timestamp: new Date().toISOString()
      });
      
      // Use generic error message and add random delay
      await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 200));
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid username or password'
      });
    }

    // Generate JWT token
    const token = generateToken(
      { userId: user.username, role: user.role },
      jwtSecret,
      '24h'
    );

    // Log successful login
    logger.info('Successful login', {
      username: user.username,
      role: user.role,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      requestId: (req as any).requestId,
      timestamp: new Date().toISOString()
    });

    res.json({
      token,
      expiresIn: '24h',
      user: {
        id: user.username,
        role: user.role
      }
    });
  } catch (error: any) {
    if (error instanceof ZodError) {
      const sanitized = sanitizeError(error, isProduction);
      res.status(400).json({
        error: 'Validation Error',
        message: sanitized.message,
        ...(sanitized.details && { details: sanitized.details })
      });
    } else {
      logger.error('Login error', { 
        error: error.message,
        stack: error.stack,
        requestId: (req as any).requestId,
        ip: req.ip
      });
      const sanitized = sanitizeError(error, isProduction);
      res.status(500).json({
        error: 'Internal Server Error',
        message: sanitized.message
      });
    }
  }
});

// Health endpoints for load balancer itself
app.get('/lb/health', (req: Request, res: Response) => {
  const healthyServers = healthChecker.getAllHealthyServers(config.servers);
  const isHealthy = healthyServers.length > 0;
  
  res.status(isHealthy ? 200 : 503).json({
    status: isHealthy ? 'healthy' : 'unhealthy',
    healthyServers: healthyServers.length,
    totalServers: config.servers.length,
    timestamp: new Date().toISOString()
  });
});

// Liveness probe (Kubernetes)
app.get('/lb/liveness', (req: Request, res: Response) => {
  res.status(200).json({ status: 'alive' });
});

// Readiness probe (Kubernetes)
app.get('/lb/readiness', (req: Request, res: Response) => {
  const healthyServers = healthChecker.getAllHealthyServers(config.servers);
  const isReady = healthyServers.length > 0;
  
  res.status(isReady ? 200 : 503).json({
    status: isReady ? 'ready' : 'not ready',
    healthyServers: healthyServers.length,
    totalServers: config.servers.length
  });
});

// Prometheus metrics endpoint
app.get('/metrics', async (req: Request, res: Response) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});

// Metrics endpoint
app.get(config.monitoring.metricsEndpoint, (req: Request, res: Response) => {
  const allMetrics = metricsCollector.getAllMetrics();
  const overallStats = metricsCollector.getOverallStats();
  const healthStatus = healthChecker.getHealthStatus() as Map<string, any>;
  const rateLimitStats = rateLimiter.getStats();

  // Calculate server load percentages
  const totalConnections = allMetrics.reduce((sum, m) => sum + m.currentConnections, 0);
  const maxConnections = allMetrics.length * 100; // Assuming max 100 connections per server

  const metrics = {
    timestamp: new Date().toISOString(),
    overall: {
      ...overallStats,
      successRate: overallStats.totalRequests > 0 
        ? ((overallStats.totalSuccessful / overallStats.totalRequests) * 100).toFixed(2) + '%'
        : '0%',
      failureRate: overallStats.totalRequests > 0
        ? ((overallStats.totalFailed / overallStats.totalRequests) * 100).toFixed(2) + '%'
        : '0%',
      averageResponseTimeMs: overallStats.averageResponseTime.toFixed(2),
      totalConnections,
      loadPercentage: maxConnections > 0 
        ? ((totalConnections / maxConnections) * 100).toFixed(2) + '%'
        : '0%'
    },
    servers: allMetrics.map(metric => {
      const health = healthStatus.get(metric.serverId);
      const server = config.servers.find(s => s.id === metric.serverId);
      const uptimeSeconds = Math.floor((Date.now() - metric.uptime) / 1000);
      
      return {
        ...metric,
        serverUrl: server?.url,
        weight: server?.weight || 1,
        enabled: server?.enabled ?? true,
        isHealthy: health?.isHealthy ?? false,
        lastHealthCheck: health?.lastChecked,
        healthCheckResponseTime: health?.responseTime,
        consecutiveFailures: health?.consecutiveFailures ?? 0,
        successRate: metric.totalRequests > 0
          ? ((metric.successfulRequests / metric.totalRequests) * 100).toFixed(2) + '%'
          : '0%',
        failureRate: metric.totalRequests > 0
          ? ((metric.failedRequests / metric.totalRequests) * 100).toFixed(2) + '%'
          : '0%',
        averageResponseTimeMs: metric.averageResponseTime.toFixed(2),
        lastResponseTimeMs: metric.lastResponseTime?.toFixed(2),
        uptimeSeconds,
        uptimeFormatted: formatUptime(uptimeSeconds)
      };
    }),
    rateLimiting: {
      ...rateLimitStats,
      config: {
        enabled: config.rateLimit.enabled,
        maxRequests: config.rateLimit.maxRequests,
        windowMs: config.rateLimit.windowMs,
        windowSeconds: Math.floor(config.rateLimit.windowMs / 1000),
        perIP: config.rateLimit.perIP,
        perUser: config.rateLimit.perUser,
        userHeader: config.rateLimit.userHeader
      },
      activeTrackers: {
        ip: rateLimitStats.ipLimits,
        user: rateLimitStats.userLimits,
        total: rateLimitStats.ipLimits + rateLimitStats.userLimits
      }
    },
    loadBalancer: {
      algorithm: config.algorithm,
      totalServers: config.servers.length,
      healthyServers: healthChecker.getAllHealthyServers(config.servers).length,
      unhealthyServers: config.servers.length - healthChecker.getAllHealthyServers(config.servers).length,
      healthCheckEnabled: config.healthCheck.enabled,
      healthCheckInterval: config.healthCheck.interval,
      healthCheckPath: config.healthCheck.path
    },
    failover: {
      enabled: config.healthCheck.enabled,
      automatic: true,
      unhealthyServers: allMetrics
        .map(m => {
          const health = healthStatus.get(m.serverId);
          return health && !health.isHealthy ? m.serverId : null;
        })
        .filter(id => id !== null),
      lastFailover: allMetrics
        .map(m => {
          const health = healthStatus.get(m.serverId);
          if (health && !health.isHealthy && health.lastChecked) {
            return {
              serverId: m.serverId,
              timestamp: health.lastChecked,
              consecutiveFailures: health.consecutiveFailures
            };
          }
          return null;
        })
        .filter(f => f !== null)
    }
  };

  res.json(metrics);
});

// Helper function to format uptime
function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

// Admin API - Get all servers
app.get('/admin/servers', requireAuth ? authMiddleware : (req, res, next) => next(), (req: Request, res: Response) => {
  const servers = loadBalancer.getServers();
  const healthStatus = healthChecker.getHealthStatus() as Map<string, any>;
  
  const serversWithHealth = servers.map(server => {
    const health = healthStatus.get(server.id);
    return {
      ...server,
      health: {
        isHealthy: health?.isHealthy ?? false,
        lastChecked: health?.lastChecked,
        responseTime: health?.responseTime,
        consecutiveFailures: health?.consecutiveFailures ?? 0
      }
    };
  });

  res.json(serversWithHealth);
});

// Admin API - Add server
app.post('/admin/servers', 
  requireAuth ? jwtAuthMiddleware : (req, res, next) => next(),
  (req: Request, res: Response) => {
  try {
    const validated = serverSchema.parse(req.body);
    
    // SSRF protection: validate server URL
    const urlValidation = validateServerUrl(validated.url);
    if (!urlValidation.valid) {
      logger.warn('SSRF attempt blocked in server addition', {
        url: validated.url,
        requestId: (req as any).requestId,
        ip: req.ip,
        reason: urlValidation.error
      });
      return res.status(400).json({
        error: 'Bad Request',
        message: urlValidation.error || 'Invalid server URL: blocked for security reasons'
      });
    }
    
    const server: Server = validated as Server;

    loadBalancer.addServer(server);
    
    // Start health check for the new server if enabled
    if (config.healthCheck.enabled && server.enabled) {
      healthChecker.startHealthCheck(server);
      logger.info('Health check started for newly added server', {
        serverId: server.id,
        url: server.url
      });
    }
    
    // Update config
    config.servers = loadBalancer.getServers();
    saveConfig(config);

    logger.info('Server added dynamically', {
      serverId: server.id,
      url: server.url,
      weight: server.weight,
      enabled: server.enabled,
      totalServers: config.servers.length
    });

    res.status(201).json({
      message: 'Server added successfully',
      server,
      healthCheckStarted: config.healthCheck.enabled && server.enabled,
      totalServers: config.servers.length
    });
  } catch (error: any) {
    logger.error('Failed to add server', { 
      error: error.message, 
      stack: error.stack,
      requestId: (req as any).requestId,
      ip: req.ip
    });
    const sanitized = sanitizeError(error, isProduction);
    res.status(400).json({
      error: 'Bad Request',
      message: sanitized.message
    });
  }
});

// Admin API - Remove server
app.delete('/admin/servers/:serverId', 
  requireAuth ? authMiddleware : (req, res, next) => next(),
  (req: Request, res: Response) => {
  const { serverId } = req.params;
  const server = config.servers.find(s => s.id === serverId);
  
  if (!server) {
    return res.status(404).json({
      error: 'Not Found',
      message: `Server with id ${serverId} not found`
    });
  }

  const removed = loadBalancer.removeServer(serverId);

  if (removed) {
    // Health check is stopped automatically by loadBalancer.removeServer
    // Update config
    config.servers = loadBalancer.getServers();
    saveConfig(config);

    logger.info('Server removed dynamically', {
      serverId,
      url: server.url,
      totalServers: config.servers.length
    });

    res.json({
      message: 'Server removed successfully',
      serverId,
      removedServer: server,
      totalServers: config.servers.length,
      healthyServers: healthChecker.getAllHealthyServers(config.servers).length
    });
  } else {
    res.status(500).json({
      error: 'Internal Server Error',
      message: 'Failed to remove server'
    });
  }
});

// Admin API - Update server
app.put('/admin/servers/:serverId', 
  requireAuth ? authMiddleware : (req, res, next) => next(),
  validateServerInput,
  (req: Request, res: Response) => {
  const { serverId } = req.params;
  const updates = req.body;
  
  // Validate URL if provided (with SSRF protection)
  if (updates.url) {
    const urlValidation = validateServerUrl(updates.url);
    if (!urlValidation.valid) {
      logger.warn('SSRF attempt blocked in server update', {
        url: updates.url,
        serverId,
        requestId: (req as any).requestId,
        ip: req.ip,
        reason: urlValidation.error
      });
      return res.status(400).json({
        error: 'Bad Request',
        message: urlValidation.error || 'Invalid server URL: blocked for security reasons'
      });
    }
  }

  const server = config.servers.find(s => s.id === serverId);
  if (!server) {
    return res.status(404).json({
      error: 'Not Found',
      message: `Server with id ${serverId} not found`
    });
  }

  const updated = loadBalancer.updateServer(serverId, updates);

  if (updated) {
    // Restart health check if server was enabled/disabled or URL changed
    const updatedServer = loadBalancer.getServers().find(s => s.id === serverId);
    if (updatedServer && config.healthCheck.enabled) {
      if (updatedServer.enabled) {
        healthChecker.startHealthCheck(updatedServer);
      } else {
        healthChecker.stopHealthCheck(serverId);
      }
    }

    // Update config
    config.servers = loadBalancer.getServers();
    saveConfig(config);

    logger.info('Server updated dynamically', {
      serverId,
      updates,
      enabled: updatedServer?.enabled
    });

    res.json({
      message: 'Server updated successfully',
      serverId,
      updates,
      server: updatedServer
    });
  } else {
    res.status(404).json({
      error: 'Not Found',
      message: `Server with id ${serverId} not found`
    });
  }
});

// Admin API - Update rate limit config
app.put('/admin/config/rate-limit', 
  requireAuth ? jwtAuthMiddleware : (req, res, next) => next(),
  (req: Request, res: Response) => {
  try {
    const validated = rateLimitConfigSchema.parse(req.body);
    const newConfig = { ...config.rateLimit, ...validated };
    config.rateLimit = newConfig;
    rateLimiter.updateConfig(newConfig);
    saveConfig(config);

    logger.info('Rate limit config updated', { config: newConfig });

    res.json({
      message: 'Rate limit configuration updated',
      config: newConfig
    });
  } catch (error: any) {
    logger.error('Failed to update rate limit config', { 
      error: error.message,
      stack: error.stack,
      requestId: (req as any).requestId,
      ip: req.ip
    });
    const sanitized = sanitizeError(error, isProduction);
    res.status(400).json({
      error: 'Bad Request',
      message: sanitized.message
    });
  }
});

// Admin API - Update load balancing algorithm
app.put('/admin/config/algorithm', 
  requireAuth ? jwtAuthMiddleware : (req, res, next) => next(),
  (req: Request, res: Response) => {
  try {
    const validated = algorithmSchema.parse(req.body);
    const { algorithm } = validated;

    config.algorithm = algorithm;
    loadBalancer.updateAlgorithm(algorithm);
    
    // Update sticky session support if algorithm changed
    if (algorithm === 'sticky-session' && !loadBalancer.getServers().some(() => true)) {
      // Enable sticky sessions if not already enabled
      // This would require updating LoadBalancer constructor
    }
    
    saveConfig(config);

    logger.info('Load balancing algorithm updated', { algorithm });

    res.json({
      message: 'Algorithm updated successfully',
      algorithm
    });
  } catch (error: any) {
    if (error instanceof ZodError) {
      res.status(400).json({
        error: 'Validation Error',
        message: 'Invalid algorithm',
        details: error.errors
      });
    } else {
      logger.error('Failed to update algorithm', { 
        error: error.message,
        stack: error.stack,
        requestId: (req as any).requestId,
        ip: req.ip
      });
      const sanitized = sanitizeError(error, isProduction);
      res.status(500).json({
        error: 'Internal Server Error',
        message: sanitized.message
      });
    }
  }
  });

// Admin API - Get current configuration
app.get('/admin/config', 
  requireAuth ? authMiddleware : (req, res, next) => next(),
  (req: Request, res: Response) => {
    // Don't expose API key in response
    const safeConfig = { ...config };
    if (safeConfig.security) {
      safeConfig.security = {
        ...safeConfig.security,
        adminApiKey: '***hidden***'
      };
    }
    res.json(safeConfig);
  });

// Admin API - Get rate limit hits
app.get('/admin/rate-limit/hits', 
  requireAuth ? authMiddleware : (req, res, next) => next(),
  (req: Request, res: Response) => {
  const limit = req.query.limit ? parseInt(req.query.limit as string) : undefined;
  const hits = rateLimiter.getRateLimitHits(limit);
  
  res.json({
    total: hits.length,
    hits,
    stats: rateLimiter.getStats()
  });
});

// Admin API - Get rate limit statistics
app.get('/admin/rate-limit/stats', 
  requireAuth ? authMiddleware : (req, res, next) => next(),
  (req: Request, res: Response) => {
  const stats = rateLimiter.getStats();
  res.json({
    ...stats,
    config: {
      enabled: config.rateLimit.enabled,
      maxRequests: config.rateLimit.maxRequests,
      windowMs: config.rateLimit.windowMs,
      windowSeconds: Math.floor(config.rateLimit.windowMs / 1000),
      perIP: config.rateLimit.perIP,
      perUser: config.rateLimit.perUser,
      userHeader: config.rateLimit.userHeader
    }
  });
});

// Load balancing - forward all other requests
app.all('*', async (req: Request, res: Response, next: NextFunction) => {
  try {
    await loadBalancer.forwardRequest(req, res);
  } catch (error: any) {
    next(error);
  }
});

// Zod validation error handler
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  if (err instanceof ZodError) {
    const requestId = (req as any).requestId || 'unknown';
    const sanitized = sanitizeError(err, isProduction);
    
    logger.warn('Validation error', {
      errors: err.errors,
      requestId,
      path: req.path,
      method: req.method,
      ip: req.ip
    });
    
    res.status(400).json({
      error: 'Validation Error',
      message: sanitized.message,
      ...(sanitized.details && { details: sanitized.details }),
      requestId
    });
    return;
  }
  next(err);
});

// Global error handling middleware (must be last)
app.use((err: any, req: Request, res: Response, next: NextFunction) => {
  const requestId = (req as any).requestId || 'unknown';
  
  // Log full error details server-side
  logger.error('Unhandled error', { 
    error: err.message, 
    stack: err.stack,
    requestId,
    path: req.path,
    method: req.method,
    ip: req.ip,
    userAgent: req.headers['user-agent'],
    body: req.body,
    query: req.query,
    timestamp: new Date().toISOString()
  });

  // Don't send error response if headers already sent
  if (res.headersSent) {
    return next(err);
  }

  // Sanitize error for client
  const sanitized = sanitizeError(err, isProduction);
  
  res.status(err.status || 500).json({
    error: err.status ? sanitized.message : 'Internal Server Error',
    message: err.status ? sanitized.message : 'An unexpected error occurred',
    requestId
  });
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  logger.error('Unhandled Promise Rejection', {
    reason: reason?.message || reason,
    stack: reason?.stack,
    promise: promise.toString()
  });
  // Don't exit in production, but log the error
  if (process.env.NODE_ENV === 'production') {
    // Could send to error tracking service here
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', {
    error: error.message,
    stack: error.stack
  });
  // Exit process on uncaught exception as it's a critical error
  gracefulShutdown('uncaughtException');
});

// Start server
const PORT = config.port || parseInt(process.env.PORT || '3000', 10);

let server: http.Server | https.Server | null = null;
let wsProxy: WebSocketProxy | null = null;

// Create HTTPS server if configured
const httpsServer = config.security?.https?.enabled
  ? createHttpsServer(app, config.security.https)
  : null;

// Graceful shutdown function
function gracefulShutdown(signal: string): void {
  logger.info(`${signal} received, shutting down gracefully`, { signal });

  // Stop accepting new connections
  if (server) {
    server.close(() => {
      logger.info('HTTP/HTTPS server closed');

      // Cleanup WebSocket proxy
      if (wsProxy) {
        wsProxy.cleanup();
      }

      // Cleanup resources
      healthChecker.stopAllHealthChecks();
      rateLimiter.cleanup();
      endpointRateLimiter.cleanup();
      metricsCollector.cleanup();
      loadBalancer.cleanup();
      clearInterval(metricsCleanupInterval);

      logger.info('Cleanup completed, exiting');
      process.exit(0);
    });

    // Force close after 10 seconds
    setTimeout(() => {
      logger.error('Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  } else {
    // If server not started yet, just cleanup and exit
    healthChecker.stopAllHealthChecks();
    rateLimiter.cleanup();
    metricsCollector.cleanup();
    clearInterval(metricsCleanupInterval);
    process.exit(0);
  }
}

// Start the server (HTTPS if configured, otherwise HTTP)
if (httpsServer) {
  server = httpsServer.listen(PORT, () => {
    logger.info(`Load balancer started on HTTPS port ${PORT}`, {
      port: PORT,
      servers: config.servers.length,
      algorithm: config.algorithm,
      rateLimitEnabled: config.rateLimit.enabled,
      authRequired: requireAuth,
      https: true,
      nodeEnv: process.env.NODE_ENV || 'development'
    });
  });
} else {
  server = app.listen(PORT, () => {
    logger.info(`Load balancer started on HTTP port ${PORT}`, {
      port: PORT,
      servers: config.servers.length,
      algorithm: config.algorithm,
      rateLimitEnabled: config.rateLimit.enabled,
      authRequired: requireAuth,
      https: false,
      nodeEnv: process.env.NODE_ENV || 'development'
    });
  });
}

// Initialize WebSocket proxy with authentication
if (server) {
  wsProxy = new WebSocketProxy(server, loadBalancer, healthChecker, {
    jwtSecret: requireAuth ? jwtSecret : undefined,
    requireAuth: requireAuth
  });
}

// Graceful shutdown handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Export app for testing
export { app };

