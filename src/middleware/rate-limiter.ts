import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';
import { RateLimitConfig, RateLimitInfo } from '../types';
import { logger } from '../utils/logger';

interface RateLimitHit {
  timestamp: Date;
  id: string;
  identifier: string;
  type: 'IP' | 'User' | 'Both';
  path: string;
  method: string;
  ip?: string;
  user?: string;
  limit: number;
  retryAfter: number;
}

export class RateLimiter {
  private ipLimits: Map<string, RateLimitInfo> = new Map();
  private userLimits: Map<string, RateLimitInfo> = new Map();
  private config: RateLimitConfig;
  private rateLimitHits: RateLimitHit[] = [];
  private totalHits: number = 0;
  private readonly MAX_HITS_HISTORY = 1000; // Keep last 1000 hits for monitoring

  constructor(config: RateLimitConfig) {
    this.config = config;
    // Clean up expired entries every minute
    setInterval(() => this.cleanupExpired(), 60000);
  }

  updateConfig(config: RateLimitConfig): void {
    this.config = config;
    // Clear existing limits when config changes
    this.ipLimits.clear();
    this.userLimits.clear();
    logger.info('Rate limit configuration updated', { config });
  }

  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!this.config.enabled) {
        return next();
      }

      // Check both IP and User limits if both are enabled
      if (this.config.perIP && this.config.perUser && this.config.userHeader) {
        return this.checkBothLimits(req, res, next);
      }

      // Check single limit (IP or User)
      const identifier = this.getIdentifier(req);
      const limitType = this.config.perIP ? 'IP' : 'User';
      const limitInfo = this.getLimitInfo(identifier, limitType);

      if (limitInfo.count >= limitInfo.limit) {
        return this.handleRateLimitExceeded(req, res, identifier, limitType, limitInfo);
      }

      limitInfo.count++;
      const remaining = Math.max(0, limitInfo.limit - limitInfo.count);

      res.setHeader('X-RateLimit-Limit', limitInfo.limit.toString());
      res.setHeader('X-RateLimit-Remaining', remaining.toString());
      res.setHeader('X-RateLimit-Reset', limitInfo.resetTime.toISOString());

      next();
    };
  }

  private checkBothLimits(req: Request, res: Response, next: NextFunction): void {
    const ipIdentifier = req.ip || req.socket.remoteAddress || 'unknown';
    const userIdentifier = req.headers[this.config.userHeader!.toLowerCase()] as string || 'anonymous';
    
    const ipLimitInfo = this.getLimitInfo(ipIdentifier, 'IP');
    const userLimitInfo = this.getLimitInfo(userIdentifier, 'User');

    // Check if either limit is exceeded
    const ipExceeded = ipLimitInfo.count >= ipLimitInfo.limit;
    const userExceeded = userLimitInfo.count >= userLimitInfo.limit;

    if (ipExceeded) {
      return this.handleRateLimitExceeded(req, res, ipIdentifier, 'IP', ipLimitInfo, userIdentifier);
    }

    if (userExceeded) {
      return this.handleRateLimitExceeded(req, res, userIdentifier, 'User', userLimitInfo, ipIdentifier);
    }

    // Both limits are OK, increment both
    ipLimitInfo.count++;
    userLimitInfo.count++;

    const ipRemaining = Math.max(0, ipLimitInfo.limit - ipLimitInfo.count);
    const userRemaining = Math.max(0, userLimitInfo.limit - userLimitInfo.count);

    res.setHeader('X-RateLimit-Limit-IP', ipLimitInfo.limit.toString());
    res.setHeader('X-RateLimit-Remaining-IP', ipRemaining.toString());
    res.setHeader('X-RateLimit-Reset-IP', ipLimitInfo.resetTime.toISOString());
    res.setHeader('X-RateLimit-Limit-User', userLimitInfo.limit.toString());
    res.setHeader('X-RateLimit-Remaining-User', userRemaining.toString());
    res.setHeader('X-RateLimit-Reset-User', userLimitInfo.resetTime.toISOString());

    next();
  }

  private handleRateLimitExceeded(
    req: Request,
    res: Response,
    identifier: string,
    type: 'IP' | 'User' | 'Both',
    limitInfo: RateLimitInfo,
    secondaryIdentifier?: string
  ): void {
    const retryAfter = Math.ceil((limitInfo.resetTime.getTime() - Date.now()) / 1000);
    
    res.setHeader('Retry-After', retryAfter.toString());
    res.setHeader('X-RateLimit-Limit', limitInfo.limit.toString());
    res.setHeader('X-RateLimit-Remaining', '0');
    res.setHeader('X-RateLimit-Reset', limitInfo.resetTime.toISOString());

    // Record the rate limit hit
    const hit: RateLimitHit = {
      timestamp: new Date(),
      id: randomUUID(),
      identifier,
      type: type === 'Both' ? 'Both' : type,
      path: req.path,
      method: req.method,
      ip: type === 'IP' || type === 'Both' ? identifier : req.ip || req.socket.remoteAddress || 'unknown',
      user: type === 'User' || type === 'Both' ? identifier : secondaryIdentifier || req.headers[this.config.userHeader?.toLowerCase() || ''] as string || undefined,
      limit: limitInfo.limit,
      retryAfter
    };

    this.recordRateLimitHit(hit);

    // Log with full context
    logger.warn('Rate limit exceeded', {
      hitId: hit.id,
      identifier,
      secondaryIdentifier,
      limit: limitInfo.limit,
      count: limitInfo.count,
      type: hit.type,
      path: req.path,
      method: req.method,
      ip: hit.ip,
      user: hit.user,
      retryAfter,
      timestamp: hit.timestamp.toISOString()
    });

    res.status(429).json({
      error: 'Too Many Requests',
      message: 'Rate limit exceeded. Please try again later.',
      retryAfter,
      limit: limitInfo.limit,
      resetTime: limitInfo.resetTime.toISOString()
    });
  }

  private recordRateLimitHit(hit: RateLimitHit): void {
    this.totalHits++;
    this.rateLimitHits.push(hit);
    
    // Keep only the last MAX_HITS_HISTORY hits to prevent memory leaks
    if (this.rateLimitHits.length > this.MAX_HITS_HISTORY) {
      this.rateLimitHits.shift();
    }
  }

  /**
   * Cleanup method to be called on shutdown
   */
  cleanup(): void {
    this.ipLimits.clear();
    this.userLimits.clear();
    this.rateLimitHits = [];
    this.totalHits = 0;
  }

  private getIdentifier(req: Request): string {
    if (this.config.perIP) {
      return req.ip || req.socket.remoteAddress || 'unknown';
    }
    if (this.config.perUser && this.config.userHeader) {
      return req.headers[this.config.userHeader.toLowerCase()] as string || 'anonymous';
    }
    return 'global';
  }

  private getLimitInfo(identifier: string, type: 'IP' | 'User'): RateLimitInfo {
    const map = type === 'IP' ? this.ipLimits : this.userLimits;
    let limitInfo = map.get(identifier);

    if (!limitInfo || limitInfo.resetTime < new Date()) {
      limitInfo = {
        count: 0,
        resetTime: new Date(Date.now() + this.config.windowMs),
        limit: this.config.maxRequests
      };
      map.set(identifier, limitInfo);
    }

    return limitInfo;
  }

  private cleanupExpired(): void {
    const now = new Date();
    let cleaned = 0;
    
    for (const [key, info] of this.ipLimits.entries()) {
      if (info.resetTime < now) {
        this.ipLimits.delete(key);
        cleaned++;
      }
    }

    for (const [key, info] of this.userLimits.entries()) {
      if (info.resetTime < now) {
        this.userLimits.delete(key);
        cleaned++;
      }
    }

    // Clean up old rate limit hits (older than 1 hour)
    const oneHourAgo = new Date(Date.now() - 3600000);
    this.rateLimitHits = this.rateLimitHits.filter(hit => hit.timestamp > oneHourAgo);

    if (cleaned > 0) {
      logger.debug(`Cleaned up ${cleaned} expired rate limit entries`);
    }
  }

  getStats(): {
    ipLimits: number;
    userLimits: number;
    totalHits: number;
    recentHits: number;
    hitsByType: { IP: number; User: number; Both: number };
    recentHitsList: RateLimitHit[];
  } {
    const recentHits = this.rateLimitHits.filter(
      hit => hit.timestamp > new Date(Date.now() - 3600000) // Last hour
    );

    const hitsByType = {
      IP: 0,
      User: 0,
      Both: 0
    };

    recentHits.forEach(hit => {
      hitsByType[hit.type]++;
    });

    return {
      ipLimits: this.ipLimits.size,
      userLimits: this.userLimits.size,
      totalHits: this.totalHits,
      recentHits: recentHits.length,
      hitsByType,
      recentHitsList: recentHits.slice(-100) // Last 100 hits
    };
  }

  getRateLimitHits(limit?: number): RateLimitHit[] {
    const hits = [...this.rateLimitHits].reverse(); // Most recent first
    return limit ? hits.slice(0, limit) : hits;
  }
}

