import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { constantTimeCompare } from '../utils/security';

/**
 * Basic authentication middleware for admin endpoints
 * Uses simple API key authentication via Authorization header or X-API-Key header
 * Uses constant-time comparison to prevent timing attacks
 */
export function createAuthMiddleware(apiKey: string) {
  if (!apiKey || apiKey.length < 16) {
    throw new Error('API key must be at least 16 characters long for security');
  }

  return (req: Request, res: Response, next: NextFunction) => {
    // Get API key from Authorization header (Bearer token) or X-API-Key header
    const authHeader = req.headers.authorization;
    const apiKeyHeader = req.headers['x-api-key'] as string;
    
    let providedKey: string | undefined;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      providedKey = authHeader.substring(7);
    } else if (apiKeyHeader) {
      providedKey = apiKeyHeader;
    }

    // Use constant-time comparison to prevent timing attacks
    if (!providedKey || !constantTimeCompare(providedKey, apiKey)) {
      // Enhanced security logging
      logger.warn('Unauthorized admin API access attempt', {
        ip: req.ip,
        path: req.path,
        method: req.method,
        userAgent: req.headers['user-agent'],
        hasAuthHeader: !!authHeader,
        hasApiKeyHeader: !!apiKeyHeader,
        timestamp: new Date().toISOString(),
        requestId: (req as any).requestId
      });

      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or missing API key. Use Authorization: Bearer <key> or X-API-Key header.'
      });
    }

    next();
  };
}

