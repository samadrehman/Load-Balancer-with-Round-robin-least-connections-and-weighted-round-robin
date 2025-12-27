import { Server } from '../types';
import { HealthChecker } from '../health/health-checker';
import { MetricsCollector } from '../metrics/metrics-collector';
import { logger } from '../utils/logger';
import { randomUUID } from 'crypto';
import { CircuitBreaker, CircuitBreakerConfig } from '../middleware/circuit-breaker';
import { retryWithBackoff, RetryConfig } from '../utils/retry';
import { ConnectionPool } from '../utils/connection-pool';
import { SessionManager } from '../utils/session-manager';
import { serverRequestsTotal, serverResponseTime, circuitBreakerState } from '../utils/prometheus';

export type LoadBalancingAlgorithm = 'round-robin' | 'least-connections' | 'weighted-round-robin' | 'sticky-session';

export interface LoadBalancerOptions {
  circuitBreakerConfig?: CircuitBreakerConfig;
  retryConfig?: RetryConfig;
  enableStickySessions?: boolean;
  sessionTimeout?: number;
}

export class LoadBalancer {
  private servers: Server[] = [];
  private algorithm: LoadBalancingAlgorithm;
  private currentIndex: Map<string, number> = new Map();
  private healthChecker: HealthChecker;
  private metricsCollector: MetricsCollector;
  private connectionPool: ConnectionPool;
  private circuitBreakers: Map<string, CircuitBreaker> = new Map();
  private sessionManager?: SessionManager;
  private options: LoadBalancerOptions;

  constructor(
    servers: Server[],
    algorithm: LoadBalancingAlgorithm,
    healthChecker: HealthChecker,
    metricsCollector: MetricsCollector,
    options: LoadBalancerOptions = {}
  ) {
    this.servers = servers;
    this.algorithm = algorithm;
    this.healthChecker = healthChecker;
    this.metricsCollector = metricsCollector;
    this.connectionPool = new ConnectionPool();
    this.options = {
      circuitBreakerConfig: {
        failureThreshold: 5,
        successThreshold: 2,
        timeout: 60000,
        resetTimeout: 300000
      },
      retryConfig: {
        maxRetries: 3,
        initialDelay: 100,
        maxDelay: 5000,
        backoffMultiplier: 2,
        retryableErrors: ['ECONNREFUSED', 'ETIMEDOUT', 'ECONNABORTED']
      },
      enableStickySessions: false,
      sessionTimeout: 3600000,
      ...options
    };

    if (this.options.enableStickySessions) {
      this.sessionManager = new SessionManager(this.options.sessionTimeout);
    }

    // Initialize circuit breakers for each server
    servers.forEach(server => {
      this.circuitBreakers.set(server.id, new CircuitBreaker(this.options.circuitBreakerConfig!));
    });
  }

  updateServers(servers: Server[]): void {
    this.servers = servers;
    this.healthChecker.startHealthChecks(servers);
  }

  updateAlgorithm(algorithm: LoadBalancingAlgorithm): void {
    this.algorithm = algorithm;
  }

  selectServer(sessionId?: string): Server | null {
    // Check for sticky session first
    if (this.sessionManager && sessionId) {
      const sessionServer = this.sessionManager.getServerForSession(sessionId, this.servers);
      if (sessionServer) {
        return sessionServer;
      }
    }

    const healthyServers = this.healthChecker.getAllHealthyServers(this.servers)
      .filter(server => {
        // Filter out servers with open circuit breakers
        const breaker = this.circuitBreakers.get(server.id);
        return !breaker || breaker.getState() !== 'OPEN';
      });
    
    if (healthyServers.length === 0) {
      logger.error('No healthy servers available');
      return null;
    }

    let selected: Server;
    switch (this.algorithm) {
      case 'round-robin':
        selected = this.roundRobin(healthyServers);
        break;
      case 'least-connections':
        selected = this.leastConnections(healthyServers);
        break;
      case 'weighted-round-robin':
        selected = this.weightedRoundRobin(healthyServers);
        break;
      case 'sticky-session':
        selected = this.stickySession(healthyServers, sessionId);
        break;
      default:
        selected = this.roundRobin(healthyServers);
    }

    // Create session if sticky sessions enabled
    if (this.sessionManager && sessionId && !this.sessionManager.getServerForSession(sessionId, this.servers)) {
      this.sessionManager.createSession(selected.id);
    }

    return selected;
  }

  private stickySession(servers: Server[], sessionId?: string): Server {
    // If no session, fall back to round-robin
    if (!sessionId || !this.sessionManager) {
      return this.roundRobin(servers);
    }
    
    const sessionServer = this.sessionManager.getServerForSession(sessionId, servers);
    return sessionServer || this.roundRobin(servers);
  }

  private roundRobin(servers: Server[]): Server {
    const key = 'round-robin';
    const current = this.currentIndex.get(key) || 0;
    const selected = servers[current % servers.length];
    this.currentIndex.set(key, (current + 1) % servers.length);
    return selected;
  }

  private leastConnections(servers: Server[]): Server {
    let minConnections = Infinity;
    let selectedServer = servers[0];

    for (const server of servers) {
      const metrics = this.metricsCollector.getMetrics(server.id) as any;
      const connections = metrics.currentConnections || 0;
      
      if (connections < minConnections) {
        minConnections = connections;
        selectedServer = server;
      }
    }

    return selectedServer;
  }

  private weightedRoundRobin(servers: Server[]): Server {
    const totalWeight = servers.reduce((sum, s) => sum + (s.weight || 1), 0);
    let random = Math.random() * totalWeight;

    for (const server of servers) {
      random -= (server.weight || 1);
      if (random <= 0) {
        return server;
      }
    }

    return servers[servers.length - 1];
  }

  async forwardRequest(req: any, res: any): Promise<void> {
    const sessionId = req.headers['x-session-id'] as string | undefined;
    const server = this.selectServer(sessionId);
    
    if (!server) {
      const healthyCount = this.healthChecker.getAllHealthyServers(this.servers).length;
      logger.error('No healthy servers available for request', {
        method: req.method,
        path: req.path,
        totalServers: this.servers.length,
        healthyServers: healthyCount,
        ip: req.ip
      });

      return res.status(503).json({
        error: 'Service Unavailable',
        message: 'No healthy servers available',
        totalServers: this.servers.length,
        healthyServers: healthyCount
      });
    }

    const requestId = (req as any).requestId || randomUUID();
    const circuitBreaker = this.circuitBreakers.get(server.id)!;
    
    this.metricsCollector.incrementConnections(server.id);
    this.metricsCollector.recordRequestStart(server.id, requestId);

    const startTime = Date.now();
    const targetUrl = `${server.url}${req.path}`;

    try {
      // Execute request through circuit breaker with retry logic
      const response = await circuitBreaker.execute(async () => {
        return await retryWithBackoff(
          async () => {
            const client = this.connectionPool.getClient(server.url);
            const path = new URL(targetUrl).pathname + new URL(targetUrl).search;
            
            const response = await client.request({
              method: req.method,
              url: path,
              data: req.body,
              headers: {
                ...req.headers,
                'X-Forwarded-For': req.ip,
                'X-Request-ID': requestId,
                'X-Load-Balancer': 'true',
                'X-Selected-Server': server.id
              },
              params: req.query,
              responseType: 'arraybuffer',
              timeout: 30000
            });
            
            return response;
          },
          this.options.retryConfig!,
          `server ${server.id}`
        );
      }, server.id);

      const responseTime = Date.now() - startTime;
      const success = response.status >= 200 && response.status < 300;

      // Update Prometheus metrics
      serverRequestsTotal.inc({ server_id: server.id, status: response.status.toString() });
      serverResponseTime.observe({ server_id: server.id }, responseTime / 1000);
      
      // Update circuit breaker state metric
      const breakerState = circuitBreaker.getState();
      const stateValue = breakerState === 'CLOSED' ? 0 : breakerState === 'OPEN' ? 1 : 2;
      circuitBreakerState.set({ server_id: server.id }, stateValue);

      this.metricsCollector.recordRequestEnd(server.id, requestId, success, responseTime);
      this.metricsCollector.decrementConnections(server.id);

      // Forward response
      res.status(response.status);
      res.setHeader('X-Served-By', server.id);
      res.setHeader('X-Response-Time', `${responseTime}ms`);
      
      // Add session ID to response if sticky sessions enabled
      if (this.sessionManager && sessionId) {
        res.setHeader('X-Session-ID', sessionId);
      }
      
      Object.keys(response.headers).forEach(key => {
        if (!['content-encoding', 'content-length', 'transfer-encoding', 'x-served-by', 'x-session-id'].includes(key.toLowerCase())) {
          res.setHeader(key, response.headers[key]);
        }
      });
      res.send(Buffer.from(response.data));

      logger.debug('Request forwarded successfully', {
        serverId: server.id,
        serverUrl: server.url,
        method: req.method,
        path: req.path,
        status: response.status,
        responseTime,
        requestId
      });
    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      this.metricsCollector.recordRequestEnd(server.id, requestId, false, responseTime);
      this.metricsCollector.decrementConnections(server.id);

      // Update Prometheus metrics
      serverRequestsTotal.inc({ server_id: server.id, status: 'error' });
      
      // Update circuit breaker state
      const breakerState = circuitBreaker.getState();
      const stateValue = breakerState === 'CLOSED' ? 0 : breakerState === 'OPEN' ? 1 : 2;
      circuitBreakerState.set({ server_id: server.id }, stateValue);

      // Check if server should be marked as unhealthy (failover trigger)
      const isTimeout = error.code === 'ECONNABORTED' || error.message.includes('timeout');
      const isConnectionError = error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND';

      logger.error('Request forwarding failed', {
        serverId: server.id,
        serverUrl: server.url,
        method: req.method,
        path: req.path,
        error: error.message,
        errorCode: error.code,
        responseTime,
        requestId,
        isTimeout,
        isConnectionError,
        circuitBreakerState: breakerState
      });

      if (!res.headersSent) {
        res.status(502).json({
          error: 'Bad Gateway',
          message: 'Failed to forward request to server',
          serverId: server.id,
          serverUrl: server.url,
          errorType: isTimeout ? 'timeout' : isConnectionError ? 'connection_error' : 'unknown',
          circuitBreakerState: breakerState
        });
      }
    }
  }

  getServers(): Server[] {
    return [...this.servers];
  }

  addServer(server: Server): void {
    if (this.servers.find(s => s.id === server.id)) {
      throw new Error(`Server with id ${server.id} already exists`);
    }
    this.servers.push(server);
    // Initialize circuit breaker for new server
    this.circuitBreakers.set(server.id, new CircuitBreaker(this.options.circuitBreakerConfig!));
    if (server.enabled) {
      this.healthChecker.startHealthCheck(server);
    }
    logger.info('Server added', { serverId: server.id, url: server.url });
  }

  removeServer(serverId: string): boolean {
    const index = this.servers.findIndex(s => s.id === serverId);
    if (index === -1) {
      return false;
    }
    this.servers.splice(index, 1);
    this.circuitBreakers.delete(serverId);
    this.healthChecker.stopHealthCheck(serverId);
    logger.info('Server removed', { serverId });
    return true;
  }

  /**
   * Cleanup resources
   */
  cleanup(): void {
    this.connectionPool.destroy();
    if (this.sessionManager) {
      this.sessionManager.cleanupAll();
    }
  }

  updateServer(serverId: string, updates: Partial<Server>): boolean {
    const server = this.servers.find(s => s.id === serverId);
    if (!server) {
      return false;
    }
    Object.assign(server, updates);
    if (server.enabled) {
      this.healthChecker.startHealthCheck(server);
    } else {
      this.healthChecker.stopHealthCheck(serverId);
    }
    logger.info('Server updated', { serverId, updates });
    return true;
  }
}

