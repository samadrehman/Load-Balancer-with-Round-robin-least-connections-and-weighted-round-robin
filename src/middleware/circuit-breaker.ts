import { logger } from '../utils/logger';

export enum CircuitState {
  CLOSED = 'CLOSED',
  OPEN = 'OPEN',
  HALF_OPEN = 'HALF_OPEN'
}

export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures before opening
  successThreshold: number; // Number of successes in half-open to close
  timeout: number; // Time in ms before attempting half-open
  resetTimeout: number; // Time in ms before resetting failure count
}

export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastFailureTime: number = 0;
  private config: CircuitBreakerConfig;

  constructor(config: CircuitBreakerConfig) {
    this.config = config;
  }

  async execute<T>(fn: () => Promise<T>, serverId: string): Promise<T> {
    if (this.state === CircuitState.OPEN) {
      const now = Date.now();
      if (now - this.lastFailureTime >= this.config.timeout) {
        this.state = CircuitState.HALF_OPEN;
        this.successCount = 0;
        logger.info(`Circuit breaker entering HALF_OPEN state for server ${serverId}`);
      } else {
        throw new Error(`Circuit breaker is OPEN for server ${serverId}`);
      }
    }

    try {
      const result = await fn();
      this.onSuccess(serverId);
      return result;
    } catch (error) {
      this.onFailure(serverId);
      throw error;
    }
  }

  private onSuccess(serverId: string): void {
    if (this.state === CircuitState.HALF_OPEN) {
      this.successCount++;
      if (this.successCount >= this.config.successThreshold) {
        this.state = CircuitState.CLOSED;
        this.failureCount = 0;
        logger.info(`Circuit breaker CLOSED for server ${serverId} after successful recovery`);
      }
    } else if (this.state === CircuitState.CLOSED) {
      // Reset failure count on success
      const now = Date.now();
      if (now - this.lastFailureTime >= this.config.resetTimeout) {
        this.failureCount = 0;
      }
    }
  }

  private onFailure(serverId: string): void {
    this.lastFailureTime = Date.now();
    this.failureCount++;

    if (this.state === CircuitState.HALF_OPEN) {
      this.state = CircuitState.OPEN;
      logger.warn(`Circuit breaker OPENED for server ${serverId} - recovery failed`);
    } else if (this.state === CircuitState.CLOSED && this.failureCount >= this.config.failureThreshold) {
      this.state = CircuitState.OPEN;
      logger.warn(`Circuit breaker OPENED for server ${serverId} after ${this.failureCount} failures`);
    }
  }

  getState(): CircuitState {
    return this.state;
  }

  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
  }
}

