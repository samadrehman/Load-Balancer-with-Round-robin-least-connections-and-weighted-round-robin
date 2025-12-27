import { ServerMetrics } from '../types';
import { logger } from '../utils/logger';

export class MetricsCollector {
  private metrics: Map<string, ServerMetrics> = new Map();
  private requestStartTimes: Map<string, number> = new Map();

  recordRequestStart(serverId: string, requestId: string): void {
    this.requestStartTimes.set(requestId, Date.now());
  }

  recordRequestEnd(serverId: string, requestId: string, success: boolean, responseTime?: number): void {
    const startTime = this.requestStartTimes.get(requestId);
    const actualResponseTime = responseTime || (startTime ? Date.now() - startTime : undefined);
    
    let metric = this.metrics.get(serverId);
    if (!metric) {
      metric = {
        serverId,
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        averageResponseTime: 0,
        currentConnections: 0,
        uptime: Date.now()
      };
      this.metrics.set(serverId, metric);
    }

    metric.totalRequests++;
    if (success) {
      metric.successfulRequests++;
    } else {
      metric.failedRequests++;
    }

    if (actualResponseTime !== undefined) {
      // Calculate moving average
      const totalResponses = metric.successfulRequests + metric.failedRequests;
      metric.averageResponseTime = 
        (metric.averageResponseTime * (totalResponses - 1) + actualResponseTime) / totalResponses;
      metric.lastResponseTime = actualResponseTime;
    }

    // Always cleanup requestStartTimes to prevent memory leaks
    this.requestStartTimes.delete(requestId);
  }

  /**
   * Cleanup stale request start times (older than 5 minutes)
   * Should be called periodically to prevent memory leaks
   */
  cleanupStaleRequests(): void {
    const fiveMinutesAgo = Date.now() - 300000; // 5 minutes in ms
    let cleaned = 0;
    
    for (const [requestId, startTime] of this.requestStartTimes.entries()) {
      if (startTime < fiveMinutesAgo) {
        this.requestStartTimes.delete(requestId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug(`Cleaned up ${cleaned} stale request start times`);
    }
  }

  /**
   * Cleanup method to be called on shutdown
   */
  cleanup(): void {
    this.requestStartTimes.clear();
    // Optionally clear metrics on shutdown
    // this.metrics.clear();
  }

  incrementConnections(serverId: string): void {
    let metric = this.metrics.get(serverId);
    if (!metric) {
      metric = this.createDefaultMetric(serverId);
    }
    metric.currentConnections++;
  }

  decrementConnections(serverId: string): void {
    const metric = this.metrics.get(serverId);
    if (metric) {
      metric.currentConnections = Math.max(0, metric.currentConnections - 1);
    }
  }

  getMetrics(serverId?: string): ServerMetrics | Map<string, ServerMetrics> {
    if (serverId) {
      return this.metrics.get(serverId) || this.createDefaultMetric(serverId);
    }
    return new Map(this.metrics);
  }

  getAllMetrics(): ServerMetrics[] {
    return Array.from(this.metrics.values());
  }

  resetMetrics(serverId?: string): void {
    if (serverId) {
      this.metrics.delete(serverId);
    } else {
      this.metrics.clear();
    }
  }

  private createDefaultMetric(serverId: string): ServerMetrics {
    return {
      serverId,
      totalRequests: 0,
      successfulRequests: 0,
      failedRequests: 0,
      averageResponseTime: 0,
      currentConnections: 0,
      uptime: Date.now()
    };
  }

  getOverallStats(): {
    totalRequests: number;
    totalSuccessful: number;
    totalFailed: number;
    averageResponseTime: number;
    activeServers: number;
  } {
    const allMetrics = this.getAllMetrics();
    const totalRequests = allMetrics.reduce((sum, m) => sum + m.totalRequests, 0);
    const totalSuccessful = allMetrics.reduce((sum, m) => sum + m.successfulRequests, 0);
    const totalFailed = allMetrics.reduce((sum, m) => sum + m.failedRequests, 0);
    const totalResponseTime = allMetrics.reduce((sum, m) => sum + m.averageResponseTime * m.totalRequests, 0);
    const averageResponseTime = totalRequests > 0 ? totalResponseTime / totalRequests : 0;
    const activeServers = allMetrics.filter(m => m.currentConnections > 0).length;

    return {
      totalRequests,
      totalSuccessful,
      totalFailed,
      averageResponseTime,
      activeServers
    };
  }
}

