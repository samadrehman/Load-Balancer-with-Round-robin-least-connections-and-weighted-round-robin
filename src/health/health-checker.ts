import axios, { AxiosInstance } from 'axios';
import { Server, HealthCheckResult } from '../types';
import { logger } from '../utils/logger';

export class HealthChecker {
  private healthStatus: Map<string, HealthCheckResult> = new Map();
  private intervals: Map<string, NodeJS.Timeout> = new Map();
  private httpClient: AxiosInstance;
  private config: {
    interval: number;
    timeout: number;
    path: string;
    failureThreshold: number;
    successThreshold: number;
  };

  constructor(config: {
    interval: number;
    timeout: number;
    path: string;
    failureThreshold: number;
    successThreshold: number;
  }) {
    this.config = config;
    this.httpClient = axios.create({
      timeout: config.timeout,
      validateStatus: () => true // Accept any status code
    });
  }

  startHealthChecks(servers: Server[]): void {
    // Stop existing checks
    this.stopAllHealthChecks();

    // Start checks for all servers
    servers.forEach(server => {
      if (server.enabled) {
        this.startHealthCheck(server);
      }
    });
  }

  startHealthCheck(server: Server): void {
    // Stop existing check for this server if any
    this.stopHealthCheck(server.id);

    // Perform initial check
    this.performHealthCheck(server);

    // Schedule periodic checks
    const interval = setInterval(() => {
      this.performHealthCheck(server);
    }, this.config.interval);

    this.intervals.set(server.id, interval);
  }

  stopHealthCheck(serverId: string): void {
    const interval = this.intervals.get(serverId);
    if (interval) {
      clearInterval(interval);
      this.intervals.delete(serverId);
    }
  }

  stopAllHealthChecks(): void {
    this.intervals.forEach(interval => clearInterval(interval));
    this.intervals.clear();
  }

  private async performHealthCheck(server: Server): Promise<void> {
    const startTime = Date.now();
    const healthUrl = `${server.url}${this.config.path}`;

    try {
      const response = await this.httpClient.get(healthUrl);
      const responseTime = Date.now() - startTime;
      const isHealthy = response.status >= 200 && response.status < 300;

      const previousResult = this.healthStatus.get(server.id);
      let consecutiveFailures = 0;

      if (isHealthy) {
        if (previousResult && !previousResult.isHealthy) {
          // Server was unhealthy, check if we've reached success threshold
          consecutiveFailures = Math.max(0, previousResult.consecutiveFailures - 1);
          if (consecutiveFailures === 0) {
            logger.info(`Server recovered - marked as healthy (FAILOVER RECOVERY)`, {
              serverId: server.id,
              url: server.url,
              responseTime,
              status: response.status,
              event: 'server_recovered',
              timestamp: new Date().toISOString()
            });
          } else {
            logger.debug(`Server ${server.id} recovering (${this.config.failureThreshold - consecutiveFailures}/${this.config.successThreshold} successes)`, {
              serverId: server.id,
              consecutiveFailures,
              remainingFailures: this.config.failureThreshold - consecutiveFailures
            });
          }
        }
      } else {
        consecutiveFailures = (previousResult?.consecutiveFailures || 0) + 1;
        
        if (consecutiveFailures >= this.config.failureThreshold && (!previousResult || previousResult.isHealthy)) {
          // Server just became unhealthy - this is a failover event
          logger.warn(`Server marked as unhealthy - FAILOVER TRIGGERED`, {
            serverId: server.id,
            url: server.url,
            status: response.status,
            consecutiveFailures,
            failureThreshold: this.config.failureThreshold,
            event: 'failover_triggered',
            timestamp: new Date().toISOString(),
            note: 'Requests will now be routed to other healthy servers'
          });
        } else if (consecutiveFailures >= this.config.failureThreshold) {
          logger.debug(`Server ${server.id} remains unhealthy`, {
            serverId: server.id,
            consecutiveFailures,
            status: response.status
          });
        } else {
          logger.warn(`Server ${server.id} health check failed (${consecutiveFailures}/${this.config.failureThreshold})`, {
            serverId: server.id,
            url: server.url,
            status: response.status,
            consecutiveFailures,
            remainingFailures: this.config.failureThreshold - consecutiveFailures
          });
        }
      }

      this.healthStatus.set(server.id, {
        serverId: server.id,
        isHealthy: consecutiveFailures < this.config.failureThreshold,
        responseTime,
        lastChecked: new Date(),
        consecutiveFailures: isHealthy ? 0 : consecutiveFailures
      });
    } catch (error: any) {
      const responseTime = Date.now() - startTime;
      const previousResult = this.healthStatus.get(server.id);
      const consecutiveFailures = (previousResult?.consecutiveFailures || 0) + 1;

      logger.error(`Health check failed for server ${server.id}`, {
        serverId: server.id,
        url: server.url,
        error: error.message,
        consecutiveFailures
      });

      this.healthStatus.set(server.id, {
        serverId: server.id,
        isHealthy: consecutiveFailures < this.config.failureThreshold,
        responseTime,
        lastChecked: new Date(),
        consecutiveFailures
      });

      if (consecutiveFailures >= this.config.failureThreshold && (!previousResult || previousResult.isHealthy)) {
        // Server just became unhealthy - this is a failover event
        logger.warn(`Server marked as unhealthy after ${consecutiveFailures} failures - FAILOVER TRIGGERED`, {
          serverId: server.id,
          url: server.url,
          consecutiveFailures,
          failureThreshold: this.config.failureThreshold,
          error: error.message,
          errorCode: error.code,
          event: 'failover_triggered',
          timestamp: new Date().toISOString(),
          note: 'Requests will now be routed to other healthy servers'
        });
      } else if (consecutiveFailures >= this.config.failureThreshold) {
        logger.debug(`Server ${server.id} remains unhealthy`, {
          serverId: server.id,
          consecutiveFailures,
          error: error.message
        });
      } else {
        logger.warn(`Server ${server.id} health check failed (${consecutiveFailures}/${this.config.failureThreshold})`, {
          serverId: server.id,
          url: server.url,
          error: error.message,
          consecutiveFailures,
          remainingFailures: this.config.failureThreshold - consecutiveFailures
        });
      }
    }
  }

  isHealthy(serverId: string): boolean {
    const result = this.healthStatus.get(serverId);
    return result?.isHealthy ?? false;
  }

  getHealthStatus(serverId?: string): HealthCheckResult | Map<string, HealthCheckResult> {
    if (serverId) {
      return this.healthStatus.get(serverId) || {
        serverId,
        isHealthy: false,
        lastChecked: new Date(),
        consecutiveFailures: 0
      };
    }
    return new Map(this.healthStatus);
  }

  getAllHealthyServers(servers: Server[]): Server[] {
    return servers.filter(server => 
      server.enabled && this.isHealthy(server.id)
    );
  }
}

