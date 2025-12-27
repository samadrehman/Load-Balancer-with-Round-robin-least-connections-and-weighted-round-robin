import { Request, Response, NextFunction } from 'express';
import { RateLimiter } from './rate-limiter';
import { RateLimitConfig } from '../types';

/**
 * Endpoint-specific rate limiting
 */
export class EndpointRateLimiter {
  private limiters: Map<string, RateLimiter> = new Map();

  /**
   * Create or get rate limiter for a specific endpoint
   */
  getLimiter(endpoint: string, config: RateLimitConfig): RateLimiter {
    if (!this.limiters.has(endpoint)) {
      this.limiters.set(endpoint, new RateLimiter(config));
    }
    return this.limiters.get(endpoint)!;
  }

  /**
   * Middleware factory for endpoint-specific rate limiting
   */
  middleware(endpoint: string, config: RateLimitConfig) {
    return (req: Request, res: Response, next: NextFunction) => {
      const limiter = this.getLimiter(endpoint, config);
      limiter.middleware()(req, res, next);
    };
  }

  /**
   * Cleanup all limiters
   */
  cleanup(): void {
    this.limiters.forEach(limiter => limiter.cleanup());
    this.limiters.clear();
  }
}

